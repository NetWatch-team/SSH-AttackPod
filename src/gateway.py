"""
NetWatch SSH-Gateway (Sensor Mode)
Terminates incoming SSH connections with genuine OpenSSH banners and persistent host keys.
Evaluates password authentication attempts via the Sequence Admission Engine.
Rejected attempts are reported as standard brute-force attacks to Collector 2.0.
Admitted attempts are relayed over WireGuard to the central Honeypot Farm.
"""

import os
import sys
import time
import uuid
import signal
import asyncio
import logging
import requests
from typing import Optional, Dict

import asyncssh
from admission_engine import AdmissionEngine, AdmissionDecision, AdmissionReason

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("ssh_gateway")

# Environment configurations
COLLECTOR_URL = os.getenv("NETWATCH_COLLECTOR_URL", "https://api.netwatch.team")
COLLECTOR_AUTH = os.getenv("NETWATCH_COLLECTOR_AUTHORIZATION", "")
SENSOR_UUID = os.getenv("SENSOR_UUID", "")
SENSOR_TLP = os.getenv("SENSOR_TLP", "CLEAR")
FARM_BROKER_URL = os.getenv("FARM_BROKER_URL", "http://10.20.255.1:8080")
FARM_BROKER_TOKEN = os.getenv("FARM_BROKER_TOKEN", "")

LISTEN_HOST = os.getenv("SSH_LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.getenv("SSH_LISTEN_PORT", "22"))
SERVER_VERSION = os.getenv("SSH_SERVER_VERSION", "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5")
HOST_KEYS_DIR = os.getenv("HOST_KEYS_DIR", "/etc/ssh/host_keys")
CACHE_DIR = os.getenv("CACHE_DIR", "/var/lib/netwatch_gateway")

MAX_SESSION_SECONDS = int(os.getenv("MAX_SESSION_SECONDS", "900"))
IDLE_TIMEOUT_SECONDS = int(os.getenv("IDLE_TIMEOUT_SECONDS", "300"))


def ensure_host_keys():
    """Generates and persists persistent host keys if not present."""
    os.makedirs(HOST_KEYS_DIR, exist_ok=True)
    rsa_path = os.path.join(HOST_KEYS_DIR, "ssh_host_rsa_key")
    ed25519_path = os.path.join(HOST_KEYS_DIR, "ssh_host_ed25519_key")

    keys = []
    if os.path.exists(rsa_path):
        keys.append(asyncssh.read_private_key(rsa_path))
    else:
        logger.info(f"Generating persistent RSA host key at {rsa_path}...")
        key = asyncssh.generate_private_key("ssh-rsa", key_size=3072)
        key.write_private_key(rsa_path)
        keys.append(key)

    if os.path.exists(ed25519_path):
        keys.append(asyncssh.read_private_key(ed25519_path))
    else:
        logger.info(f"Generating persistent Ed25519 host key at {ed25519_path}...")
        key = asyncssh.generate_private_key("ssh-ed25519")
        key.write_private_key(ed25519_path)
        keys.append(key)

    return keys


def report_bruteforce_attack(src_ip: str, user: str, password: str, dst_ip: str):
    """Submits standard low-interaction brute-force payload to Collector 2.0."""
    url = f"{COLLECTOR_URL}/v2/add_attack/ssh_bruteforce"
    headers = {"Authorization": COLLECTOR_AUTH, "Content-Type": "application/json"}
    payload = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "uuid": SENSOR_UUID,
        "tlp": SENSOR_TLP,
        "source": src_ip,
        "destination": dst_ip,
        "attack_type": "SSH_BRUTE_FORCE",
        "source_type": "IP",
        "test_mode": False,
        "evidence": f"Failed password attempt for {user} from {src_ip}",
        "metadata": {"username": user, "password": password}
    }
    try:
        requests.post(url, json=payload, headers=headers, timeout=3)
    except Exception as e:
        logger.debug(f"Failed to submit bruteforce attack to collector: {e}")


class CowrieRelaySession(asyncssh.SSHServerSession):
    def __init__(self, server: "GatewaySSHServer"):
        self.server = server
        self.channel = None
        self.client_conn = None
        self.cowrie_process = None
        self.term_type = "xterm-256color"
        self.term_size = (80, 24, 0, 0)
        self.env: Dict[str, str] = {}

    def connection_made(self, chan):
        self.channel = chan

    def pty_requested(self, term_type, term_size, term_modes):
        self.term_type = term_type
        self.term_size = term_size
        return True

    def env_received(self, name, value):
        self.env[name] = value
        return True

    def terminal_size_changed(self, width, height, pixwidth, pixheight):
        self.term_size = (width, height, pixwidth, pixheight)
        if self.cowrie_process:
            self.cowrie_process.change_terminal_size(width, height, pixwidth, pixheight)

    def shell_requested(self):
        asyncio.create_task(self._start_relay(command=None))
        return True

    def exec_requested(self, command):
        asyncio.create_task(self._start_relay(command=command))
        return True

    async def _start_relay(self, command: Optional[str] = None):
        try:
            self.client_conn = await asyncssh.connect(
                self.server.cowrie_host,
                port=self.server.cowrie_port,
                username=self.server.admitted_username or "root",
                password=self.server.relay_token,
                known_hosts=None
            )
            term_size_pair = (self.term_size[0], self.term_size[1])
            self.cowrie_process = await self.client_conn.create_process(
                command=command,
                term_type=self.term_type,
                term_size=term_size_pair,
                env=self.env
            )
            asyncio.create_task(self._pipe_cowrie_to_client())
            await self.cowrie_process.wait()
            exit_status = self.cowrie_process.exit_status or 0
            if self.channel:
                self.channel.exit(exit_status)
                self.channel.close()
        except Exception as e:
            logger.error(f"Relay error to Cowrie: {e}")
            if self.channel:
                self.channel.close()
        finally:
            if self.client_conn:
                self.client_conn.close()

    async def _pipe_cowrie_to_client(self):
        try:
            while not self.cowrie_process.stdout.at_eof():
                data = await self.cowrie_process.stdout.read(4096)
                if not data:
                    break
                self.server.bytes_out += len(data)
                if self.channel:
                    self.channel.write(data)
        except Exception:
            pass

    def data_received(self, data, datatype):
        self.server.bytes_in += len(data)
        if self.cowrie_process and not self.cowrie_process.stdin.is_closing():
            self.cowrie_process.stdin.write(data)

    def eof_received(self):
        if self.cowrie_process and not self.cowrie_process.stdin.is_closing():
            self.cowrie_process.stdin.write_eof()
        return True

    def connection_lost(self, exc):
        if self.cowrie_process:
            self.cowrie_process.terminate()
        if self.client_conn:
            self.client_conn.close()


class GatewaySSHServer(asyncssh.SSHServer):
    def __init__(self, admission_engine: AdmissionEngine, local_ip: str):
        self.engine = admission_engine
        self.local_ip = local_ip
        self.peer_ip = ""
        self.peer_port = 0
        self.admitted_engagement_uuid = None
        self.admitted_metadata = None
        self.admitted_username = None
        self.cowrie_host = None
        self.cowrie_port = None
        self.relay_token = None
        self.cowrie_client_conn = None
        self.session_start_time = None
        self.bytes_in = 0
        self.bytes_out = 0

    def connection_made(self, conn):
        peername = conn.get_extra_info("peername")
        self.peer_ip = peername[0] if peername else "0.0.0.0"
        self.peer_port = peername[1] if peername else 0
        logger.debug(f"Incoming connection from {self.peer_ip}:{self.peer_port}")

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        decision, reason, meta = self.engine.evaluate_attempt(self.peer_ip, username, password)

        if decision == AdmissionDecision.REJECT:
            # Report standard bruteforce attempt
            report_bruteforce_attack(self.peer_ip, username, password, self.local_ip)
            return False

        # --- ADMITTED! ---
        eng_uuid = str(uuid.uuid4())
        self.admitted_engagement_uuid = eng_uuid
        self.admitted_metadata = meta
        self.admitted_username = username
        self.session_start_time = time.time()

        logger.info(f"Admitting session for {self.peer_ip} (user '{username}'). Engagement UUID: {eng_uuid}")

        # 1. Report admission to Collector
        try:
            adm_url = f"{COLLECTOR_URL}/v2/sandbox/admission"
            requests.post(
                adm_url,
                json={
                    "sensor_uuid": SENSOR_UUID,
                    "source_ip": self.peer_ip,
                    "username": username,
                    "password": password,
                    "matched_cluster_uuid": meta.get("matched_cluster_uuid"),
                    "score": meta.get("score", 0.0),
                    "matched_pairs_count": meta.get("matched_pairs_count", 0)
                },
                headers={"Authorization": COLLECTOR_AUTH},
                timeout=4
            )
        except Exception as e:
            logger.error(f"Failed to notify Collector of admission: {e}")

        # 2. Register initial Engagement in Collector
        try:
            eng_url = f"{COLLECTOR_URL}/v2/engagement"
            requests.post(
                eng_url,
                json={
                    "engagement_uuid": eng_uuid,
                    "sensor_uuid": SENSOR_UUID,
                    "source_ip": self.peer_ip,
                    "destination_ip": self.local_ip,
                    "service": "SSH",
                    "username": username,
                    "admission_reason": reason,
                    "session_start": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "engagement_status": "ACTIVE"
                },
                headers={"Authorization": COLLECTOR_AUTH},
                timeout=4
            )
        except Exception as e:
            logger.error(f"Failed to create engagement in Collector: {e}")

        # 3. Request relay token from Honeypot Farm Broker
        try:
            broker_resp = requests.post(
                f"{FARM_BROKER_URL}/broker/v1/sessions",
                json={
                    "engagement_uuid": eng_uuid,
                    "sensor_uuid": SENSOR_UUID,
                    "attacker_ip": self.peer_ip,
                    "username": username
                },
                headers={"Authorization": f"Bearer {FARM_BROKER_TOKEN}"} if FARM_BROKER_TOKEN else {},
                timeout=5
            )
            if broker_resp.status_code == 200:
                broker_data = broker_resp.json()
                self.cowrie_host = broker_data["cowrie_host"]
                self.cowrie_port = broker_data["cowrie_port"]
                self.relay_token = broker_data["relay_token"]
                return True
            else:
                logger.error(f"Broker returned status {broker_resp.status_code}: {broker_resp.text}")
        except Exception as e:
            logger.error(f"Failed to connect to Honeypot Farm Broker: {e}")

        # Farm unavailable fallback
        return False

    def session_requested(self):
        """Allows opening an interactive shell session channel."""
        return CowrieRelaySession(self)

    def connection_lost(self, exc):
        """Finalizes engagement metrics on disconnect."""
        if self.admitted_engagement_uuid and self.session_start_time:
            duration = int(time.time() - self.session_start_time)
            logger.info(f"Engagement {self.admitted_engagement_uuid} disconnected. Duration: {duration}s")
            try:
                eng_url = f"{COLLECTOR_URL}/v2/engagement"
                requests.post(
                    eng_url,
                    json={
                        "engagement_uuid": self.admitted_engagement_uuid,
                        "session_end": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "duration_seconds": duration,
                        "engagement_status": "COMPLETED",
                        "bytes_in": self.bytes_in,
                        "bytes_out": self.bytes_out
                    },
                    headers={"Authorization": COLLECTOR_AUTH},
                    timeout=5
                )
            except Exception as e:
                logger.error(f"Failed to finalize engagement in Collector: {e}")


async def sync_fingerprints_bundle(admission_engine: AdmissionEngine):
    """Background task syncing the cluster fingerprint bundle from Collector every 5 minutes."""
    while True:
        try:
            url = f"{COLLECTOR_URL}/v2/sandbox/fingerprints"
            headers = {"Authorization": COLLECTOR_AUTH}
            resp = requests.get(url, headers=headers, timeout=5)
            if resp.status_code == 200:
                bundle = resp.json()
                admission_engine.load_bundle(bundle)
        except Exception as e:
            logger.debug(f"Failed to sync fingerprint bundle from Collector: {e}")
        await asyncio.sleep(300)


async def sync_accepted_credentials(admission_engine: AdmissionEngine):
    """Background task syncing accepted credentials from Collector."""
    while True:
        try:
            url = f"{COLLECTOR_URL}/v2/sandbox/accepted_credentials"
            headers = {"Authorization": COLLECTOR_AUTH}
            resp = requests.get(url, headers=headers, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                creds = data.get("accepted_credentials", [])
                admission_engine.sync_accepted_credentials_list(creds)
        except Exception as e:
            logger.debug(f"Failed to sync accepted credentials from Collector: {e}")
        await asyncio.sleep(60)


async def start_gateway_server():
    os.makedirs(CACHE_DIR, exist_ok=True)
    sqlite_path = os.path.join(CACHE_DIR, "gateway_credentials.db")
    admission_engine = AdmissionEngine(sqlite_db_path=sqlite_path)

    # Local IP lookup
    local_ip = os.getenv("ATTACK_POD_IP", "127.0.0.1")

    # Load host keys
    host_keys = ensure_host_keys()

    # Start sync loops
    asyncio.create_task(sync_fingerprints_bundle(admission_engine))
    asyncio.create_task(sync_accepted_credentials(admission_engine))

    logger.info(f"Starting NetWatch SSH-Gateway on {LISTEN_HOST}:{LISTEN_PORT}...")
    server = await asyncssh.create_server(
        lambda: GatewaySSHServer(admission_engine, local_ip),
        LISTEN_HOST,
        LISTEN_PORT,
        server_host_keys=host_keys,
        server_version=SERVER_VERSION
    )
    await server.wait_closed()


def main():
    asyncio.run(start_gateway_server())


if __name__ == "__main__":
    main()
