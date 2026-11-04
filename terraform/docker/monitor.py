import logging
import requests
import re
import os
import sys
from datetime import datetime
import threading
import time
import subprocess
import signal
import json
import queue
import ipaddress

MAX_QUEUE_SIZE = int(os.getenv("NETWATCH_MAX_QUEUE_SIZE", "10000"))
attack_queue = queue.Queue(maxsize=MAX_QUEUE_SIZE)
shutdown_event = threading.Event()
_child_reap_requested = False

logging.basicConfig(
    encoding="utf-8",
    level=logging.INFO,
    format="%(asctime)s %(message)s"
)


def get_env(key, fallback):
    env = os.getenv(key, default=fallback)
    return env


def _check_if_in_test_mode():
    test = get_env("NETWATCH_TEST_MODE", "false")
    logging.info("Test:" + test)
    if get_env("NETWATCH_TEST_MODE", "false") != "false":
        return True

    return False


_RFC1918_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
)


def is_private_ip(ip: str) -> bool:
    """
    Check if an IP address is private/non-routable per RFC 1918 and related standards.
    
    This includes:
    - RFC 1918 private addresses (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
    - Loopback addresses (127.0.0.0/8)
    - Link-local addresses (169.254.0.0/16)
    
    Args:
        ip: IP address string to check
        
    Returns:
        True if IP is private/non-routable, False otherwise
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        return (
            ip_obj.is_loopback
            or ip_obj.is_link_local
            or any(ip_obj in net for net in _RFC1918_NETWORKS)
        )
    except ValueError:
        logging.warning(f"Invalid IP address format: {ip}")
        return False


def mask_payload_for_log(payload: dict) -> dict:
    """Returns a shallow copy of an attack payload with metadata.password masked for safe stdout logging."""
    masked = dict(payload)
    meta = payload.get("metadata")
    if isinstance(meta, dict):
        masked_meta = dict(meta)
        if "password" in masked_meta:
            masked_meta["password"] = "***"
        masked["metadata"] = masked_meta
    return masked


def redact_sshd_line(line: str) -> str:
    """Redacts cleartext passwords from patched sshd debug lines before logging."""
    return re.sub(r"(password ')[^']*(')", r"\1***\2", line)


def enqueue_attack(payload: dict, target_queue: queue.Queue = None):
    """Enqueues an attack payload with drop-oldest eviction when the bounded queue is full."""
    q = target_queue if target_queue is not None else attack_queue
    try:
        q.put_nowait(payload)
    except queue.Full:
        try:
            q.get_nowait()
        except queue.Empty:
            pass
        try:
            q.put_nowait(payload)
        except queue.Full:
            pass


def get_local_ip():
    url = f"{get_env('NETWATCH_COLLECTOR_URL', 'https://api.netwatch.team')}/check_ip"
    for attempt in range(50):
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                local_ip = response.json().get("ip")
                logging.info(f"Got the following local IP: {local_ip}")
                return local_ip

            logging.error(f"[!] Got a non 200 status code from the netwatch backend: {response.status_code}, message: {response.text}")

        except requests.RequestException as e:
            logging.error(f"[!] Got a request exception while trying to get the local IP: {e}")

        except Exception as e:
            logging.error(f"[!] Got an exception while trying to get the local IP: {e}")

        time.sleep(10)

    logging.error("[!] The system was unable to get the local IP. Sensor can not work without local IP => Exit with code 1")
    sys.exit(1)


def submit_attack(ip, user, password, evidence, ATTACKPOD_LOCAL_IP):
    # Check if source or destination is a private/local IP (RFC 1918 filtering)
    allow_private = _check_if_in_test_mode() or get_env("NETWATCH_ALLOW_PRIVATE_IPS", "false").lower() == "true"
    if not allow_private and (is_private_ip(ip) or is_private_ip(ATTACKPOD_LOCAL_IP)):
        logging.info(f"Skipping attack from/to private IP - Source: {ip}, Destination: {ATTACKPOD_LOCAL_IP}, User: {user}")
        return

    json_dict = {
        "timestamp": datetime.now().isoformat(),
        "uuid": get_env("SENSOR_UUID", ""),
        "tlp": get_env("SENSOR_TLP", "CLEAR"),
        "source": ip,
        "destination": ATTACKPOD_LOCAL_IP,
        "attack_type": "SSH_BRUTE_FORCE",
        "source_type": "IP",
        "test_mode": _check_if_in_test_mode(),
        "evidence": evidence,
        "metadata": {
            "username": user,
            "password": password,
        }
    }

    enqueue_attack(json_dict)


def attack_forward_worker(attack_queue):
    session = requests.Session()
    while not shutdown_event.is_set():
        try:
            json_dict = attack_queue.get(timeout=1.0)
        except queue.Empty:
            continue

        url = f"{get_env('NETWATCH_COLLECTOR_URL', '')}/v2/add_attack/ssh_bruteforce"
        headers = {"Authorization": get_env("NETWATCH_COLLECTOR_AUTHORIZATION", "")}

        try:
            response = session.post(url, json=json_dict, headers=headers, timeout=5)
            if response.status_code == 200:
                safe_log_json = json.dumps(mask_payload_for_log(json_dict))
                if _check_if_in_test_mode():
                    logging.info(f"Reported the following JSON to the NetWatch collector IN TEST MODE ATTACK WILL NOT BE SAVED: {safe_log_json}")
                else:
                    logging.info(f"Reported the following JSON to the NetWatch collector: {safe_log_json}")
            else:
                logging.error(f"[!] Got a non 200 status code from the collector: {response.status_code} with message: {response.text}")

        except requests.RequestException as e:
            logging.error(f"[!] Got a request exception while submitting the attack: {e}")
            enqueue_attack(json_dict, attack_queue)
            shutdown_event.wait(10)

        except Exception as e:
            logging.error(f"[!] Got an exception while submitting the attack: {e}")
            enqueue_attack(json_dict, attack_queue)
            shutdown_event.wait(10)


def reap_children(signum, frame):
    """Async-signal-safe flag setter; actual child reaping is performed outside the signal frame or via Popen.wait."""
    global _child_reap_requested
    _child_reap_requested = True


def reap_zombie_processes():
    """Safely reaps any orphaned child processes outside the signal handler context."""
    global _child_reap_requested
    if not _child_reap_requested:
        return
    _child_reap_requested = False
    try:
        while True:
            pid, _ = os.waitpid(-1, os.WNOHANG)
            if pid == 0:
                break
    except (ChildProcessError, OSError):
        pass


def handle_shutdown_signal(signum, frame):
    """Re-entrant termination handler setting the shutdown event."""
    shutdown_event.set()


def register_signal_handlers():
    signal.signal(signal.SIGCHLD, reap_children)
    signal.signal(signal.SIGTERM, handle_shutdown_signal)
    signal.signal(signal.SIGINT, handle_shutdown_signal)


def run_sshd():
    while not shutdown_event.is_set():
        try:
            process = subprocess.Popen(["/usr/sbin/sshd", "-D", "-E", "/var/log/ssh.log"])
            while process.poll() is None and not shutdown_event.is_set():
                time.sleep(0.5)
            if shutdown_event.is_set() and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
        except Exception as e:
            logging.error(f"Error while running sshd: {e}")
            shutdown_event.wait(1)


def rotate_sshd_keys():
    for key_file in ("/etc/ssh/ssh_host_rsa_key", "/etc/ssh/ssh_host_rsa_key.pub",
                     "/etc/ssh/ssh_host_ecdsa_key", "/etc/ssh/ssh_host_ecdsa_key.pub",
                     "/etc/ssh/ssh_host_ed25519_key", "/etc/ssh/ssh_host_ed25519_key.pub"):
        try:
            if os.path.exists(key_file):
                os.remove(key_file)
        except OSError:
            pass
    subprocess.run(
        ["ssh-keygen", "-t", "rsa", "-b", "3072", "-f", "/etc/ssh/ssh_host_rsa_key", "-N", ""],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    subprocess.run(
        ["ssh-keygen", "-t", "ecdsa", "-b", "521", "-f", "/etc/ssh/ssh_host_ecdsa_key", "-N", ""],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


if __name__ == '__main__':
    mode = os.getenv("NETWATCH_MODE", "lowint").lower()
    if mode == "gateway":
        logging.info("[+] Starting NetWatch Attackpod in GATEWAY mode")
        import gateway
        gateway.main()
        sys.exit(0)

    register_signal_handlers()
    logging.info("[+] Starting NetWatch Attackpod in LOW-INTERACTION mode")

    if _check_if_in_test_mode():
        logging.info("################################")
        logging.info("################################")
        logging.info("###   !Sensor in test mode!   ##")
        logging.info("### Attacks will be submitted ##")
        logging.info("###       but NOT SAVED       ##")
        logging.info("################################")
        logging.info("################################")

    logging.info("[+] Getting local ip")

    if os.getenv("ATTACK_POD_IP") is not None:
        ATTACKPOD_LOCAL_IP = get_env("ATTACK_POD_IP", "")
    else:
        ATTACKPOD_LOCAL_IP = get_local_ip()

    logging.info("[+] Got the local ip of {} for the AttackPod".format(ATTACKPOD_LOCAL_IP))

    logging.info("[+] Rotating SSHD Keys")
    rotate_sshd_keys()

    logging.info("[+] Starting SSHD")
    sshd_thread = threading.Thread(target=run_sshd, args=(), daemon=True)
    sshd_thread.start()

    logging.info("[+] Starting the attack forward worker")
    attack_submit_worker_thread = threading.Thread(target=attack_forward_worker, args=(attack_queue,), daemon=True)
    attack_submit_worker_thread.start()

    with open("/var/log/ssh.log", 'r') as logfile:
        logfile.seek(0, os.SEEK_END)

        ip = ""
        user = ""
        password = ""
        evidence = ""

        while not shutdown_event.is_set():
            reap_zombie_processes()
            # read last line of file
            line = logfile.readline()
            # sleep if file hasn't been updated
            if not line:
                time.sleep(0.1)
                continue

            logging.debug("Captured a new line from sshd: {}".format(redact_sshd_line(line.rstrip("\r\n"))))
            output = re.findall(r"Login attempt by username '(.*)', password '(.*)', from ip '(\d.*)'", line)

            if len(output) == 1:
                # if the regex has a match it's the patched debug message

                if ip != "":
                    # If we have two matches after each other we submit the first one to not miss one, even if we don't have the evidence of the first one
                    submit_attack(ip, user, password, evidence, ATTACKPOD_LOCAL_IP)
                    ip = ""
                    user = ""
                    password = ""
                    evidence = ""

                user = output[0][0]
                password = output[0][1]
                ip = output[0][2]
            else:
                # If we don't have a regex match and we have a match of the "ip" in the line it is likely the "official" logline
                if ip in line and "Failed" in line:
                    evidence = line.rstrip("\r\n")
                    submit_attack(ip, user, password, evidence, ATTACKPOD_LOCAL_IP)

                    ip = ""
                    user = ""
                    password = ""
                    evidence = ""