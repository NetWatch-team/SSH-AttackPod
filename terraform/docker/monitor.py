import ipaddress
import json
import logging
import os
import queue
import re
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime
from typing import Any

import requests

MAX_QUEUE_SIZE = int(os.getenv("NETWATCH_MAX_QUEUE_SIZE", "10000"))
attack_queue: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=MAX_QUEUE_SIZE)
shutdown_event = threading.Event()
_child_reap_requested = False

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")


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
        return ip_obj.is_loopback or ip_obj.is_link_local or any(ip_obj in net for net in _RFC1918_NETWORKS)
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


def enqueue_attack(payload: dict, target_queue: queue.Queue | None = None):
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

            logging.error(
                f"[!] Got a non 200 status code from the netwatch backend: {response.status_code}, message: {response.text}"
            )

        except requests.RequestException as e:
            logging.error(f"[!] Got a request exception while trying to get the local IP: {e}")

        except Exception as e:
            logging.error(f"[!] Got an exception while trying to get the local IP: {e}")

        time.sleep(10)

    logging.error(
        "[!] The system was unable to get the local IP. Sensor can not work without local IP => Exit with code 1"
    )
    sys.exit(1)


def submit_attack(
    ip: str,
    user: str,
    password: str,
    evidence: str,
    ATTACKPOD_LOCAL_IP: str,
    source_port: int | None = None,
    ssh_client_version: str | None = None,
    auth_method: str = "password",
    pubkey_fingerprint: str | None = None,
    pubkey_algorithm: str | None = None,
):
    # Check if source or destination is a private/local IP (RFC 1918 filtering)
    allow_private = _check_if_in_test_mode() or get_env("NETWATCH_ALLOW_PRIVATE_IPS", "false").lower() == "true"
    if not allow_private and (is_private_ip(ip) or is_private_ip(ATTACKPOD_LOCAL_IP)):
        logging.info(
            f"Skipping attack from/to private IP - Source: {ip}, Destination: {ATTACKPOD_LOCAL_IP}, User: {user}"
        )
        return

    metadata: dict[str, Any] = {
        "username": user,
        "password": password,
        "auth_method": auth_method,
    }
    if source_port is not None and source_port > 0:
        metadata["source_port"] = source_port
    if ssh_client_version:
        metadata["ssh_client_version"] = ssh_client_version
    if pubkey_fingerprint:
        metadata["pubkey_fingerprint"] = pubkey_fingerprint
    if pubkey_algorithm:
        metadata["pubkey_algorithm"] = pubkey_algorithm

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
        "metadata": metadata,
    }

    enqueue_attack(json_dict)


class SshdLogParser:
    """Stateful parser tracking connection context across OpenSSH sshd[PID] sessions."""

    def __init__(self, max_sessions: int = 2000, session_ttl: float = 300.0):
        self.sessions: dict[str, dict[str, Any]] = {}
        self.max_sessions = max_sessions
        self.session_ttl = session_ttl

    def _prune_stale(self, now: float) -> None:
        if len(self.sessions) > self.max_sessions:
            stale_pids = [pid for pid, s in self.sessions.items() if (now - s.get("last_seen", 0.0)) > self.session_ttl]
            for pid in stale_pids:
                self.sessions.pop(pid, None)
            if len(self.sessions) > self.max_sessions:
                sorted_pids = sorted(self.sessions.keys(), key=lambda p: self.sessions[p].get("last_seen", 0.0))
                for pid in sorted_pids[: max(1, len(sorted_pids) // 5)]:
                    self.sessions.pop(pid, None)

    def parse_line(self, line: str) -> list[dict[str, Any]]:
        now = time.time()
        self._prune_stale(now)
        attacks_to_submit: list[dict[str, Any]] = []

        pid_match = re.search(r"sshd\[(\d+)\]:", line)
        pid = pid_match.group(1) if pid_match else "default"

        if pid not in self.sessions:
            self.sessions[pid] = {"last_seen": now}
        session = self.sessions[pid]
        session["last_seen"] = now

        # Software version banner
        version_match = re.search(r"client software version (.*)", line)
        if version_match:
            session["ssh_client_version"] = version_match.group(1).strip()

        # Source port / IP
        port_match = re.search(r"from (?:\[?([0-9a-fA-F:.]+)\]? )?port (\d+)", line)
        if port_match:
            if port_match.group(1):
                session["ip"] = port_match.group(1)
            try:
                session["source_port"] = int(port_match.group(2))
            except ValueError:
                pass

        # Patched debug line: Login attempt by username '...', password '...', from ip '...'
        login_match = re.findall(r"Login attempt by username '(.*)', password '(.*)', from ip '(\S+)'", line)
        if login_match:
            if session.get("pending_attempt"):
                prev = session["pending_attempt"]
                attacks_to_submit.append(
                    {
                        "ip": prev["ip"],
                        "user": prev["user"],
                        "password": prev["password"],
                        "evidence": prev.get(
                            "evidence", f"Failed password attempt for {prev['user']} from {prev['ip']}"
                        ),
                        "source_port": session.get("source_port"),
                        "ssh_client_version": session.get("ssh_client_version"),
                        "auth_method": "password",
                    }
                )
            user, password, ip = login_match[0]
            session["ip"] = ip
            session["pending_attempt"] = {"user": user, "password": password, "ip": ip}
            return attacks_to_submit

        # Official Failed line
        if "Failed" in line and "publickey" not in line:
            pending = session.get("pending_attempt")
            if pending:
                attacks_to_submit.append(
                    {
                        "ip": pending["ip"],
                        "user": pending["user"],
                        "password": pending["password"],
                        "evidence": line.rstrip("\r\n"),
                        "source_port": session.get("source_port"),
                        "ssh_client_version": session.get("ssh_client_version"),
                        "auth_method": "password",
                    }
                )
                session.pop("pending_attempt", None)
            return attacks_to_submit

        # Failed publickey attempt
        pk_match = re.search(
            r"Failed publickey for (?:invalid user )?(\S+) from (\S+) port (\d+) ssh2: (\S+) (SHA256:\S+)",
            line,
        )
        if pk_match:
            user = pk_match.group(1)
            ip = pk_match.group(2)
            port: int | None = None
            try:
                port = int(pk_match.group(3))
            except (ValueError, TypeError):
                port = session.get("source_port")
            algo = pk_match.group(4)
            fp = pk_match.group(5)
            attacks_to_submit.append(
                {
                    "ip": ip,
                    "user": user,
                    "password": "",
                    "evidence": line.rstrip("\r\n"),
                    "source_port": port,
                    "ssh_client_version": session.get("ssh_client_version"),
                    "auth_method": "publickey",
                    "pubkey_algorithm": algo,
                    "pubkey_fingerprint": fp,
                }
            )
            return attacks_to_submit

        # Connection teardown
        if "Connection closed" in line or "Disconnected from" in line or "session closed" in line:
            if session.get("pending_attempt"):
                prev = session["pending_attempt"]
                attacks_to_submit.append(
                    {
                        "ip": prev["ip"],
                        "user": prev["user"],
                        "password": prev["password"],
                        "evidence": f"Failed password attempt for {prev['user']} from {prev['ip']}",
                        "source_port": session.get("source_port"),
                        "ssh_client_version": session.get("ssh_client_version"),
                        "auth_method": "password",
                    }
                )
            self.sessions.pop(pid, None)

        return attacks_to_submit


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
                    logging.info(
                        f"Reported the following JSON to the NetWatch collector IN TEST MODE ATTACK WILL NOT BE SAVED: {safe_log_json}"
                    )
                else:
                    logging.info(f"Reported the following JSON to the NetWatch collector: {safe_log_json}")
            else:
                logging.error(
                    f"[!] Got a non 200 status code from the collector: {response.status_code} with message: {response.text}"
                )

        except requests.RequestException as e:
            logging.error(f"[!] Got a request exception while submitting the attack: {e}")
            enqueue_attack(json_dict, attack_queue)
            shutdown_event.wait(10)

        except Exception as e:
            logging.error(f"[!] Got an exception while submitting the attack: {e}")
            enqueue_attack(json_dict, attack_queue)
            shutdown_event.wait(10)


def reap_children(_signum, _frame):
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


def handle_shutdown_signal(_signum, _frame):
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
    for key_file in (
        "/etc/ssh/ssh_host_rsa_key",
        "/etc/ssh/ssh_host_rsa_key.pub",
        "/etc/ssh/ssh_host_ecdsa_key",
        "/etc/ssh/ssh_host_ecdsa_key.pub",
        "/etc/ssh/ssh_host_ed25519_key",
        "/etc/ssh/ssh_host_ed25519_key.pub",
    ):
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


if __name__ == "__main__":
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

    logging.info(f"[+] Got the local ip of {ATTACKPOD_LOCAL_IP} for the AttackPod")

    logging.info("[+] Rotating SSHD Keys")
    rotate_sshd_keys()

    logging.info("[+] Starting SSHD")
    sshd_thread = threading.Thread(target=run_sshd, args=(), daemon=True)
    sshd_thread.start()

    logging.info("[+] Starting the attack forward worker")
    attack_submit_worker_thread = threading.Thread(target=attack_forward_worker, args=(attack_queue,), daemon=True)
    attack_submit_worker_thread.start()

    log_parser = SshdLogParser()
    with open("/var/log/ssh.log") as logfile:
        logfile.seek(0, os.SEEK_END)

        while not shutdown_event.is_set():
            reap_zombie_processes()
            # read last line of file
            line = logfile.readline()
            # sleep if file hasn't been updated
            if not line:
                time.sleep(0.1)
                continue

            logging.debug("Captured a new line from sshd: {}".format(redact_sshd_line(line.rstrip("\r\n"))))
            attacks = log_parser.parse_line(line)
            for att in attacks:
                submit_attack(
                    ip=att["ip"],
                    user=att["user"],
                    password=att["password"],
                    evidence=att.get("evidence", ""),
                    ATTACKPOD_LOCAL_IP=ATTACKPOD_LOCAL_IP,
                    source_port=att.get("source_port"),
                    ssh_client_version=att.get("ssh_client_version"),
                    auth_method=att.get("auth_method", "password"),
                    pubkey_fingerprint=att.get("pubkey_fingerprint"),
                    pubkey_algorithm=att.get("pubkey_algorithm"),
                )
