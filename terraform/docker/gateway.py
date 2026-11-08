"""
NetWatch SSH-Gateway (Sensor Mode)
Terminates incoming SSH connections with genuine OpenSSH banners and persistent host keys.
Evaluates password authentication attempts via the Sequence Admission Engine.
Rejected attempts are reported as standard brute-force attacks to Collector 2.0.
Admitted attempts are relayed over WireGuard to the central Honeypot Farm.
"""

import asyncio
import hashlib
import ipaddress
import logging
import os
import signal
import time
import uuid
from typing import Any

import requests

try:
    import asyncssh
except ImportError:  # pragma: no cover - fallback for lightweight unit test runners

    class _AsyncSSHStub:
        class SSHServer:
            pass

        class SSHServerSession:
            pass

        @staticmethod
        async def connect(*_args, **_kwargs):
            raise RuntimeError("asyncssh is not installed")

        @staticmethod
        async def create_server(*_args, **_kwargs):
            raise RuntimeError("asyncssh is not installed")

        @staticmethod
        def read_private_key(*_args, **_kwargs):
            raise RuntimeError("asyncssh is not installed")

        @staticmethod
        def generate_private_key(*_args, **_kwargs):
            raise RuntimeError("asyncssh is not installed")

    asyncssh = _AsyncSSHStub()  # type: ignore[assignment]

from admission_engine import AdmissionDecision, AdmissionEngine

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger("ssh_gateway")

# Environment configurations
COLLECTOR_URL = os.getenv("NETWATCH_COLLECTOR_URL", "https://api.netwatch.team")
COLLECTOR_AUTH = os.getenv("NETWATCH_COLLECTOR_AUTHORIZATION", "")
SENSOR_UUID = os.getenv("SENSOR_UUID", "")
SENSOR_TLP = os.getenv("SENSOR_TLP", "CLEAR")
FARM_BROKER_URL = os.getenv("FARM_BROKER_URL", "http://10.20.255.1:8080")
FARM_BROKER_TOKEN = os.getenv("FARM_BROKER_TOKEN", "")

LISTEN_HOST = os.getenv("SSH_LISTEN_HOST", "0.0.0.0")  # nosec B104
LISTEN_PORT = int(os.getenv("SSH_LISTEN_PORT", "22"))
SERVER_VERSION = os.getenv("SSH_SERVER_VERSION", "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5")
HOST_KEYS_DIR = os.getenv("HOST_KEYS_DIR", "/etc/ssh/host_keys")
CACHE_DIR = os.getenv("CACHE_DIR", "/var/lib/netwatch_gateway")

MAX_SESSION_SECONDS = int(os.getenv("MAX_SESSION_SECONDS", "900"))
IDLE_TIMEOUT_SECONDS = int(os.getenv("IDLE_TIMEOUT_SECONDS", "300"))


_RFC1918_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
)


def is_private_ip(ip: str) -> bool:
    """Checks if an IP address is RFC 1918 private, loopback, or link-local (excluding RFC 5737 documentation IPs)."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_loopback or ip_obj.is_link_local or any(ip_obj in net for net in _RFC1918_NETWORKS)
    except ValueError:
        return False


def ensure_host_keys():
    """Generates and persists persistent host keys with strict 0600 permissions if not present."""
    os.makedirs(HOST_KEYS_DIR, mode=0o700, exist_ok=True)
    rsa_path = os.path.join(HOST_KEYS_DIR, "ssh_host_rsa_key")
    ed25519_path = os.path.join(HOST_KEYS_DIR, "ssh_host_ed25519_key")

    keys = []
    if os.path.exists(rsa_path):
        os.chmod(rsa_path, 0o600)
        keys.append(asyncssh.read_private_key(rsa_path))
    else:
        logger.info(f"Generating persistent RSA host key at {rsa_path}...")
        key = asyncssh.generate_private_key("ssh-rsa", key_size=3072)
        key.write_private_key(rsa_path)
        os.chmod(rsa_path, 0o600)
        keys.append(key)

    if os.path.exists(ed25519_path):
        os.chmod(ed25519_path, 0o600)
        keys.append(asyncssh.read_private_key(ed25519_path))
    else:
        logger.info(f"Generating persistent Ed25519 host key at {ed25519_path}...")
        key = asyncssh.generate_private_key("ssh-ed25519")
        key.write_private_key(ed25519_path)
        os.chmod(ed25519_path, 0o600)
        keys.append(key)

    return keys


def compute_hassh_from_connection(conn: Any) -> tuple[str | None, str | None]:
    """Extracts HASSH client fingerprint and algorithm string from an asyncssh connection or mock."""
    client_kexinit = getattr(conn, "_client_kexinit", None)
    if not client_kexinit:
        hassh = getattr(conn, "hassh", None)
        hassh_algs = getattr(conn, "hassh_algorithms", None)
        return hassh, hassh_algs

    try:
        from asyncssh.packet import SSHPacket

        packet = SSHPacket(client_kexinit)
        packet.get_byte()  # packet type (SSH_MSG_KEXINIT = 20)
        packet.get_bytes(16)  # cookie
        kex_algs = packet.get_namelist()
        packet.get_namelist()  # server_host_key_algs
        enc_algs_cs = packet.get_namelist()
        packet.get_namelist()  # enc_algs_sc
        mac_algs_cs = packet.get_namelist()
        packet.get_namelist()  # mac_algs_sc
        comp_algs_cs = packet.get_namelist()
        packet.get_namelist()  # comp_algs_sc

        kex_str = ",".join(a.decode("ascii", "replace") if isinstance(a, bytes) else str(a) for a in kex_algs)
        enc_str = ",".join(a.decode("ascii", "replace") if isinstance(a, bytes) else str(a) for a in enc_algs_cs)
        mac_str = ",".join(a.decode("ascii", "replace") if isinstance(a, bytes) else str(a) for a in mac_algs_cs)
        cmp_str = ",".join(a.decode("ascii", "replace") if isinstance(a, bytes) else str(a) for a in comp_algs_cs)
        raw_hassh = f"{kex_str};{enc_str};{mac_str};{cmp_str}"
        hassh_md5 = hashlib.md5(raw_hassh.encode("utf-8"), usedforsecurity=False).hexdigest()
        return hassh_md5, raw_hassh
    except Exception as e:
        logger.debug(f"Failed to compute HASSH from connection: {e}")
        return None, None


def report_bruteforce_attack(
    src_ip: str,
    user: str,
    password: str,
    dst_ip: str,
    evidence: str | None = None,
    source_port: int | None = None,
    ssh_client_version: str | None = None,
    hassh: str | None = None,
    hassh_algorithms: str | None = None,
    auth_method: str = "password",
    pubkey_fingerprint: str | None = None,
    pubkey_algorithm: str | None = None,
    pubkey_comment: str | None = None,
    attempt_index_in_conn: int | None = None,
    inter_attempt_ms: int | None = None,
):
    """Submits standard low-interaction brute-force payload to Collector 2.0 without logging cleartext passwords."""
    test_mode = os.getenv("NETWATCH_TEST_MODE", "false").lower() != "false"
    allow_private = test_mode or os.getenv("NETWATCH_ALLOW_PRIVATE_IPS", "false").lower() == "true"
    if not allow_private and (is_private_ip(src_ip) or is_private_ip(dst_ip)):
        logger.debug(f"Skipping brute-force report from/to private IP (src={src_ip}, dst={dst_ip})")
        return

    url = f"{COLLECTOR_URL}/v2/add_attack/ssh_bruteforce"
    headers = {"Authorization": COLLECTOR_AUTH, "Content-Type": "application/json"}

    metadata: dict[str, Any] = {
        "username": user,
        "password": password,
        "auth_method": auth_method,
    }
    if source_port is not None and source_port > 0:
        metadata["source_port"] = source_port
    if ssh_client_version:
        metadata["ssh_client_version"] = ssh_client_version
    if hassh:
        metadata["hassh"] = hassh
    if hassh_algorithms:
        metadata["hassh_algorithms"] = hassh_algorithms
    if pubkey_fingerprint:
        metadata["pubkey_fingerprint"] = pubkey_fingerprint
    if pubkey_algorithm:
        metadata["pubkey_algorithm"] = pubkey_algorithm
    if pubkey_comment:
        metadata["pubkey_comment"] = pubkey_comment
    if attempt_index_in_conn is not None:
        metadata["attempt_index_in_conn"] = attempt_index_in_conn
    if inter_attempt_ms is not None:
        metadata["inter_attempt_ms"] = inter_attempt_ms

    if evidence is None:
        if auth_method == "publickey":
            evidence = (
                f"Probed public key {pubkey_algorithm or ''} {pubkey_fingerprint or ''} for {user} from {src_ip}"
            ).strip()
        else:
            evidence = f"Failed password attempt for {user} from {src_ip}"

    payload = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "uuid": SENSOR_UUID,
        "tlp": SENSOR_TLP,
        "source": src_ip,
        "destination": dst_ip,
        "attack_type": "SSH_BRUTE_FORCE",
        "source_type": "IP",
        "test_mode": test_mode,
        "evidence": evidence,
        "metadata": metadata,
    }
    try:
        requests.post(url, json=payload, headers=headers, timeout=3)
    except Exception as e:
        logger.debug(f"Failed to submit bruteforce attack to collector: {e}")


class CowrieRelaySession(asyncssh.SSHServerSession):
    def __init__(
        self,
        server: "GatewaySSHServer",
        max_session_seconds: int = MAX_SESSION_SECONDS,
        idle_timeout_seconds: int = IDLE_TIMEOUT_SECONDS,
    ):
        self.server = server
        self.max_session_seconds = max_session_seconds
        self.idle_timeout_seconds = idle_timeout_seconds
        self.channel: Any = None
        self.client_conn: Any = None
        self.cowrie_process: Any = None
        self.term_type = "xterm-256color"
        self.term_size = (80, 24, 0, 0)
        self.pty_enabled = False
        self.exec_command: str | None = None
        self.env: dict[str, str] = {}
        self.last_activity = time.monotonic()
        self._relay_task: asyncio.Task | None = None
        self._stdout_task: asyncio.Task | None = None
        self._stderr_task: asyncio.Task | None = None
        self._watchdog_task: asyncio.Task | None = None
        self._closed = False

    def connection_made(self, chan):
        self.channel = chan
        self.last_activity = time.monotonic()

    def pty_requested(self, term_type, term_size, _term_modes):
        self.term_type = term_type
        self.term_size = term_size
        self.pty_enabled = True
        return True

    def env_received(self, name, value):
        self.env[name] = value
        return True

    def terminal_size_changed(self, width, height, pixwidth, pixheight):
        self.term_size = (width, height, pixwidth, pixheight)
        if self.cowrie_process:
            self.cowrie_process.change_terminal_size(width, height, pixwidth, pixheight)

    def shell_requested(self):
        self._relay_task = asyncio.create_task(self._start_relay(command=None))
        return True

    def exec_requested(self, command):
        self.exec_command = command
        self._relay_task = asyncio.create_task(self._start_relay(command=command))
        return True

    async def _idle_watchdog(self):
        """Terminates the relay session if idle beyond idle_timeout_seconds."""
        check_interval = min(1.0, max(0.05, self.idle_timeout_seconds / 4.0))
        try:
            while not self._closed:
                await asyncio.sleep(check_interval)
                if (time.monotonic() - self.last_activity) >= self.idle_timeout_seconds:
                    logger.info(
                        f"Session {self.server.admitted_engagement_uuid} exceeded idle timeout "
                        f"({self.idle_timeout_seconds}s); terminating relay."
                    )
                    if self.cowrie_process:
                        try:
                            self.cowrie_process.terminate()
                        except Exception:
                            pass
                    if self.channel:
                        try:
                            self.channel.close()
                        except Exception:
                            pass
                    break
        except asyncio.CancelledError:
            pass

    async def _start_relay(self, command: str | None = None):
        try:
            self.last_activity = time.monotonic()
            self.client_conn = await asyncssh.connect(
                self.server.cowrie_host,
                port=self.server.cowrie_port,
                username=self.server.admitted_username or "root",
                password=self.server.relay_token,
                known_hosts=None,
            )
            term_size_pair = (self.term_size[0], self.term_size[1])
            self.cowrie_process = await self.client_conn.create_process(
                command=command,
                term_type=self.term_type if (self.pty_enabled or command is None) else None,
                term_size=term_size_pair if (self.pty_enabled or command is None) else None,
                env=self.env,
            )
            self._stdout_task = asyncio.create_task(self._pipe_cowrie_to_client())
            self._stderr_task = asyncio.create_task(self._pipe_cowrie_stderr_to_client())
            self._watchdog_task = asyncio.create_task(self._idle_watchdog())

            await asyncio.wait_for(self.cowrie_process.wait(), timeout=self.max_session_seconds)
            if self._stdout_task:
                await asyncio.gather(self._stdout_task, return_exceptions=True)
            if self._stderr_task:
                await asyncio.gather(self._stderr_task, return_exceptions=True)

            exit_status = self.cowrie_process.exit_status or 0
            if self.channel and not self._closed:
                self.channel.exit(exit_status)
                self.channel.close()
        except TimeoutError:
            logger.info(
                f"Session {self.server.admitted_engagement_uuid} reached max session duration "
                f"({self.max_session_seconds}s); closing relay."
            )
            if self.channel and not self._closed:
                self.channel.close()
        except (AttributeError, asyncssh.Error) as e:
            logger.debug(f"Relay channel closed prematurely: {e}")
            if self.channel and not self._closed:
                self.channel.close()
        except Exception as e:
            logger.error(f"Relay error to Cowrie: {e}")
            if self.channel and not self._closed:
                self.channel.close()
        finally:
            await self._cleanup_resources()

    async def _cleanup_resources(self):
        self._closed = True
        for task in (self._watchdog_task, self._stdout_task, self._stderr_task):
            if task and not task.done():
                task.cancel()
        if self.cowrie_process:
            try:
                self.cowrie_process.terminate()
            except Exception:
                pass
        if self.client_conn:
            try:
                self.client_conn.close()
                if hasattr(self.client_conn, "wait_closed"):
                    res = self.client_conn.wait_closed()
                    if asyncio.iscoroutine(res):
                        await res
            except Exception:
                pass

    async def _pipe_cowrie_to_client(self):
        try:
            while self.cowrie_process and not self.cowrie_process.stdout.at_eof():
                data = await self.cowrie_process.stdout.read(4096)
                if not data:
                    break
                self.last_activity = time.monotonic()
                self.server.bytes_out += len(data)
                if self.channel and not self._closed:
                    self.channel.write(data)
        except asyncio.CancelledError:
            pass
        except Exception:
            pass

    async def _pipe_cowrie_stderr_to_client(self):
        try:
            stderr = getattr(self.cowrie_process, "stderr", None)
            if stderr is None:
                return
            while self.cowrie_process and not stderr.at_eof():
                data = await stderr.read(4096)
                if not data:
                    break
                self.last_activity = time.monotonic()
                self.server.bytes_out += len(data)
                if self.channel and not self._closed:
                    if hasattr(self.channel, "write_stderr"):
                        self.channel.write_stderr(data)
                    else:
                        self.channel.write(data)
        except asyncio.CancelledError:
            pass
        except Exception:
            pass

    def data_received(self, data, _datatype):
        self.last_activity = time.monotonic()
        self.server.bytes_in += len(data)
        if self.cowrie_process and not self.cowrie_process.stdin.is_closing():
            self.cowrie_process.stdin.write(data)

    def eof_received(self):
        if self.cowrie_process and not self.cowrie_process.stdin.is_closing():
            self.cowrie_process.stdin.write_eof()
        return True

    def connection_lost(self, _exc):
        self._closed = True
        for task in (self._watchdog_task, self._stdout_task, self._stderr_task, self._relay_task):
            if task and not task.done():
                task.cancel()
        if self.cowrie_process:
            try:
                self.cowrie_process.terminate()
            except Exception:
                pass
        if self.client_conn:
            try:
                self.client_conn.close()
            except Exception:
                pass


class GatewaySSHServer(asyncssh.SSHServer):
    def __init__(self, admission_engine: AdmissionEngine, local_ip: str):
        self.engine = admission_engine
        self.local_ip = local_ip
        self.conn: Any = None
        self.peer_ip = ""
        self.peer_port = 0
        self.client_version = ""
        self.hassh: str | None = None
        self.hassh_algorithms: str | None = None
        self.conn_start_time = time.monotonic()
        self.last_attempt_time = self.conn_start_time
        self.attempt_count = 0
        self.current_session: CowrieRelaySession | None = None
        self.admitted_engagement_uuid: str | None = None
        self.admitted_metadata: dict[str, Any] | None = None
        self.admitted_username: str | None = None
        self.cowrie_host: str | None = None
        self.cowrie_port: int | None = None
        self.relay_token: str | None = None
        self.cowrie_client_conn: Any = None
        self.session_start_time: float | None = None
        self.bytes_in = 0
        self.bytes_out = 0

    def connection_made(self, conn):
        self.conn = conn
        peername = conn.get_extra_info("peername")
        self.peer_ip = peername[0] if peername else "0.0.0.0"  # nosec B104
        self.peer_port = peername[1] if peername else 0
        client_ver = conn.get_extra_info("client_version")
        self.client_version = client_ver if isinstance(client_ver, str) else ""
        self.conn_start_time = time.monotonic()
        self.last_attempt_time = self.conn_start_time
        self.attempt_count = 0
        logger.debug(f"Incoming connection from {self.peer_ip}:{self.peer_port}")

    def public_key_auth_supported(self):
        return True

    def validate_public_key(self, username, key):
        now = time.monotonic()
        self.attempt_count += 1
        inter_attempt_ms = int((now - self.last_attempt_time) * 1000)
        self.last_attempt_time = now

        if not self.hassh and self.conn:
            self.hassh, self.hassh_algorithms = compute_hassh_from_connection(self.conn)
        if not self.client_version and self.conn:
            cver = self.conn.get_extra_info("client_version")
            self.client_version = cver if isinstance(cver, str) else ""

        pubkey_algo = None
        pubkey_fp = None
        pubkey_comment = None
        if hasattr(key, "get_algorithm"):
            pubkey_algo = key.get_algorithm()
        if hasattr(key, "get_fingerprint"):
            pubkey_fp = key.get_fingerprint("sha256")
        if hasattr(key, "get_comment"):
            pubkey_comment = key.get_comment()

        report_bruteforce_attack(
            src_ip=self.peer_ip,
            user=username,
            password="",
            dst_ip=self.local_ip,
            source_port=self.peer_port,
            ssh_client_version=self.client_version,
            hassh=self.hassh,
            hassh_algorithms=self.hassh_algorithms,
            auth_method="publickey",
            pubkey_fingerprint=pubkey_fp,
            pubkey_algorithm=pubkey_algo,
            pubkey_comment=pubkey_comment,
            attempt_index_in_conn=self.attempt_count,
            inter_attempt_ms=inter_attempt_ms,
        )
        return False

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        now = time.monotonic()
        self.attempt_count += 1
        inter_attempt_ms = int((now - self.last_attempt_time) * 1000)
        self.last_attempt_time = now

        if not self.hassh and self.conn:
            self.hassh, self.hassh_algorithms = compute_hassh_from_connection(self.conn)
        if not self.client_version and self.conn:
            cver = self.conn.get_extra_info("client_version")
            self.client_version = cver if isinstance(cver, str) else ""

        decision, reason, meta = self.engine.evaluate_attempt(self.peer_ip, username, password)

        if decision == AdmissionDecision.REJECT:
            report_bruteforce_attack(
                src_ip=self.peer_ip,
                user=username,
                password=password,
                dst_ip=self.local_ip,
                source_port=self.peer_port,
                ssh_client_version=self.client_version,
                hassh=self.hassh,
                hassh_algorithms=self.hassh_algorithms,
                auth_method="password",
                attempt_index_in_conn=self.attempt_count,
                inter_attempt_ms=inter_attempt_ms,
            )
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
                    "matched_pairs_count": meta.get("matched_pairs_count", 0),
                },
                headers={"Authorization": COLLECTOR_AUTH},
                timeout=4,
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
                    "engagement_status": "ACTIVE",
                },
                headers={"Authorization": COLLECTOR_AUTH},
                timeout=4,
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
                    "username": username,
                },
                headers={"Authorization": f"Bearer {FARM_BROKER_TOKEN}"} if FARM_BROKER_TOKEN else {},
                timeout=5,
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

        # Farm unavailable fallback: reset admission state so disconnect does not emit ghost engagement
        self.admitted_engagement_uuid = None
        self.admitted_metadata = None
        self.session_start_time = None
        self.relay_token = None
        return False

    def session_requested(self):
        """Allows opening an interactive shell session channel."""
        session = CowrieRelaySession(self)
        self.current_session = session
        return session

    def connection_lost(self, _exc):
        """Finalizes engagement metrics on disconnect."""
        if self.admitted_engagement_uuid and self.session_start_time and self.relay_token:
            duration = int(time.time() - self.session_start_time)
            logger.info(f"Engagement {self.admitted_engagement_uuid} disconnected. Duration: {duration}s")
            try:
                eng_url = f"{COLLECTOR_URL}/v2/engagement"
                eng_payload: dict[str, Any] = {
                    "engagement_uuid": self.admitted_engagement_uuid,
                    "sensor_uuid": SENSOR_UUID,
                    "source_ip": self.peer_ip,
                    "username": self.admitted_username or "unknown",
                    "session_end": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "duration_seconds": duration,
                    "engagement_status": "COMPLETED",
                    "bytes_in": self.bytes_in,
                    "bytes_out": self.bytes_out,
                }
                if self.current_session:
                    if self.current_session.env:
                        eng_payload["env_vars"] = self.current_session.env
                    if getattr(self.current_session, "exec_command", None):
                        eng_payload["exec_command"] = self.current_session.exec_command
                requests.post(eng_url, json=eng_payload, headers={"Authorization": COLLECTOR_AUTH}, timeout=5)
            except Exception as e:
                logger.error(f"Failed to finalize engagement in Collector: {e}")


async def sync_fingerprints_bundle(admission_engine: AdmissionEngine, stop_event: asyncio.Event | None = None):
    """Background task syncing the cluster fingerprint bundle from Collector every 5 minutes."""
    while stop_event is None or not stop_event.is_set():
        try:
            url = f"{COLLECTOR_URL}/v2/sandbox/fingerprints"
            headers = {"Authorization": COLLECTOR_AUTH}
            resp = await asyncio.to_thread(requests.get, url, headers=headers, timeout=5)
            if resp.status_code == 200:
                bundle = resp.json()
                admission_engine.load_bundle(bundle)
        except Exception as e:
            logger.debug(f"Failed to sync fingerprint bundle from Collector: {e}")
        if stop_event is not None:
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=300)
                break
            except TimeoutError:
                pass
        else:
            await asyncio.sleep(300)


async def sync_accepted_credentials(admission_engine: AdmissionEngine, stop_event: asyncio.Event | None = None):
    """Background task syncing accepted credentials from Collector."""
    while stop_event is None or not stop_event.is_set():
        try:
            url = f"{COLLECTOR_URL}/v2/sandbox/accepted_credentials"
            headers = {"Authorization": COLLECTOR_AUTH}
            resp = await asyncio.to_thread(requests.get, url, headers=headers, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                creds = data.get("accepted_credentials", [])
                admission_engine.sync_accepted_credentials_list(creds)
        except Exception as e:
            logger.debug(f"Failed to sync accepted credentials from Collector: {e}")
        if stop_event is not None:
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=60)
                break
            except TimeoutError:
                pass
        else:
            await asyncio.sleep(60)


async def start_gateway_server():
    os.makedirs(CACHE_DIR, mode=0o700, exist_ok=True)
    sqlite_path = os.path.join(CACHE_DIR, "gateway_credentials.db")
    admission_engine = AdmissionEngine(sqlite_db_path=sqlite_path)

    # Local IP lookup
    local_ip = os.getenv("ATTACK_POD_IP", "127.0.0.1")

    # Load host keys
    host_keys = ensure_host_keys()

    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop_event.set)
        except NotImplementedError:
            pass

    # Start sync loops
    fp_task = asyncio.create_task(sync_fingerprints_bundle(admission_engine, stop_event))
    cred_task = asyncio.create_task(sync_accepted_credentials(admission_engine, stop_event))

    logger.info(f"Starting NetWatch SSH-Gateway on {LISTEN_HOST}:{LISTEN_PORT}...")
    server = await asyncssh.create_server(
        lambda: GatewaySSHServer(admission_engine, local_ip),
        LISTEN_HOST,
        LISTEN_PORT,
        server_host_keys=host_keys,
        server_version=SERVER_VERSION,
    )
    try:
        await stop_event.wait()
    finally:
        server.close()
        await server.wait_closed()
        for t in (fp_task, cred_task):
            t.cancel()
        await asyncio.gather(fp_task, cred_task, return_exceptions=True)
        admission_engine.close()


def main():
    asyncio.run(start_gateway_server())


if __name__ == "__main__":
    main()
