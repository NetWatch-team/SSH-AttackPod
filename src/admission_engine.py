"""
NetWatch SSH-Gateway: Sequence Admission Engine
Evaluates brute-force attempts on the sensor locally against cluster fingerprints.
Enforces multi-pair sequence scoring, username conflict prevention, daily limits, and stealth probability.
"""

import time
import random
import sqlite3
import logging
from typing import Dict, List, Tuple, Optional, Any

logger = logging.getLogger("admission_engine")


class AdmissionDecision:
    ADMIT = "ADMIT"
    REJECT = "REJECT"


class AdmissionReason:
    ACCEPTED_CREDENTIAL = "ACCEPTED_CREDENTIAL"
    FINGERPRINT_MATCH = "FINGERPRINT_MATCH"
    USERNAME_CONFLICT = "USERNAME_CONFLICT"
    NO_MATCH = "NO_MATCH"
    QUOTA_EXCEEDED = "QUOTA_EXCEEDED"
    PROBABILITY_SKIPPED = "PROBABILITY_SKIPPED"
    COOLDOWN_ACTIVE = "COOLDOWN_ACTIVE"


class AdmissionEngine:
    def __init__(
        self,
        sqlite_db_path: str = ":memory:",
        window_seconds: int = 180,
        min_distinct_pairs: int = 3,
        min_score: float = 12.0,
        admission_probability: float = 0.6,
        max_new_admissions_per_day: int = 3,
        max_accepted_credentials: int = 3,
        accepted_credential_ttl_days: int = 14,
        admission_cooldown_hours: int = 24
    ):
        self.sqlite_db_path = sqlite_db_path
        self.window_seconds = window_seconds
        self.min_distinct_pairs = max(3, min_distinct_pairs)
        self.min_score = min_score
        self.admission_probability = admission_probability
        self.max_new_admissions_per_day = max_new_admissions_per_day
        self.max_accepted_credentials = max_accepted_credentials
        self.accepted_credential_ttl_days = accepted_credential_ttl_days
        self.admission_cooldown_hours = admission_cooldown_hours

        # In-memory sliding window: src_ip -> list of (ts, username, password)
        self.attempts: Dict[str, List[Tuple[float, str, str]]] = {}
        # Cooldown tracker: src_ip -> timestamp of last admission
        self.admissions_cooldown: Dict[str, float] = {}
        # Daily counter: [(timestamp, src_ip)]
        self.daily_admissions: List[Tuple[float, str]] = []

        # Cluster fingerprints bundle: cluster_uuid -> { "pairs": { "username:password": weight } }
        self.fingerprint_bundle: Dict[str, Any] = {}
        self.bundle_version: str = ""

        # Initialize SQLite connection (check_same_thread=False for async/multithreaded access)
        self.conn = sqlite3.connect(self.sqlite_db_path, check_same_thread=False)
        self._init_sqlite()

    def _init_sqlite(self):
        with self.conn:
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS local_accepted_credentials (
                    username TEXT NOT NULL,
                    password TEXT NOT NULL,
                    origin_attackgroup_uuid TEXT,
                    matched_cluster_uuid TEXT,
                    accepted_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    times_used INTEGER DEFAULT 1,
                    PRIMARY KEY (username, password)
                )
            """)

    def load_bundle(self, bundle_dict: dict):
        """Loads and updates the cluster fingerprints bundle."""
        if not isinstance(bundle_dict, dict):
            return

        self.bundle_version = bundle_dict.get("version", "")
        self.fingerprint_bundle = bundle_dict.get("clusters", {})

        # Optional parameter overrides from bundle
        params = bundle_dict.get("params", {})
        if "window_seconds" in params:
            self.window_seconds = int(params["window_seconds"])
        if "min_distinct_pairs" in params:
            self.min_distinct_pairs = max(3, int(params["min_distinct_pairs"]))
        if "min_score" in params:
            self.min_score = float(params["min_score"])
        if "admission_probability" in params:
            self.admission_probability = float(params["admission_probability"])

        logger.info(
            f"Loaded fingerprint bundle v{self.bundle_version} with {len(self.fingerprint_bundle)} clusters. "
            f"(Params: window={self.window_seconds}s, min_pairs={self.min_distinct_pairs}, min_score={self.min_score})"
        )

    def sync_accepted_credentials_list(self, creds_list: List[dict]):
        """Synchronizes accepted credentials from central server, replacing local cache so pruned/expired credentials vanish."""
        now = time.time()
        expires = now + (self.accepted_credential_ttl_days * 86400)
        with self.conn:
            self.conn.execute("DELETE FROM local_accepted_credentials")
            for c in creds_list:
                self.conn.execute("""
                    INSERT INTO local_accepted_credentials 
                    (username, password, origin_attackgroup_uuid, matched_cluster_uuid, accepted_at, expires_at, times_used)
                    VALUES (?, ?, ?, ?, ?, ?, 1)
                """, (
                    c["username"],
                    c["password"],
                    c.get("origin_attackgroup_uuid"),
                    c.get("origin_attackcluster_uuid"),
                    now,
                    expires
                ))
        logger.info(f"Synchronized {len(creds_list)} accepted credentials into local cache.")

    def get_active_accepted_credentials(self) -> List[dict]:
        """Returns all currently valid accepted credentials from local cache."""
        now = time.time()
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT username, password, origin_attackgroup_uuid, matched_cluster_uuid, accepted_at, expires_at, times_used
            FROM local_accepted_credentials
            WHERE expires_at > ?
        """, (now,))
        rows = cursor.fetchall()

        results = []
        for r in rows:
            results.append({
                "username": r[0],
                "password": r[1],
                "origin_attackgroup_uuid": r[2],
                "matched_cluster_uuid": r[3],
                "accepted_at": r[4],
                "expires_at": r[5],
                "times_used": r[6]
            })
        return results

    def add_accepted_credential(
        self,
        username: str,
        password: str,
        origin_attackgroup_uuid: Optional[str] = None,
        matched_cluster_uuid: Optional[str] = None
    ):
        """Stores a newly accepted credential with TTL."""
        now = time.time()
        expires = now + (self.accepted_credential_ttl_days * 86400)
        with self.conn:
            self.conn.execute("""
                INSERT INTO local_accepted_credentials 
                (username, password, origin_attackgroup_uuid, matched_cluster_uuid, accepted_at, expires_at, times_used)
                VALUES (?, ?, ?, ?, ?, ?, 1)
                ON CONFLICT(username, password) DO UPDATE SET
                    times_used = times_used + 1,
                    expires_at = excluded.expires_at
            """, (username, password, origin_attackgroup_uuid, matched_cluster_uuid, now, expires))

    def evaluate_attempt(
        self,
        src_ip: str,
        username: str,
        password: str
    ) -> Tuple[str, str, Dict[str, Any]]:
        """
        Evaluates a single password authentication attempt against the sequence admission rules.
        Returns:
            (Decision: ADMIT or REJECT, Reason: str, Metadata: dict)
        """
        now = time.time()

        # Step 1: Active Accepted Credential check (ADR-004)
        active_creds = self.get_active_accepted_credentials()
        for cred in active_creds:
            if cred["username"] == username and cred["password"] == password:
                # Check source IP cooldown to protect against rapid bot scanner flooding
                last_adm = self.admissions_cooldown.get(src_ip, 0)
                if (now - last_adm) < 60:
                    logger.info(f"[GATE] Accepted credential skipped: IP {src_ip} in cooldown window")
                    return (
                        AdmissionDecision.REJECT,
                        AdmissionReason.COOLDOWN_ACTIVE,
                        {}
                    )

                self.admissions_cooldown[src_ip] = now
                # Increment usage count
                self.add_accepted_credential(
                    username, 
                    password,
                    origin_attackgroup_uuid=cred.get("origin_attackgroup_uuid"),
                    matched_cluster_uuid=cred.get("matched_cluster_uuid")
                )
                logger.info(f"[ADMISSION] IP {src_ip} admitted via strictly unique accepted credential for '{username}'")
                return (
                    AdmissionDecision.ADMIT,
                    AdmissionReason.ACCEPTED_CREDENTIAL,
                    {
                        "matched_cluster_uuid": cred.get("matched_cluster_uuid"),
                        "origin_attackgroup_uuid": cred.get("origin_attackgroup_uuid")
                    }
                )

        # Step 2: Username conflict prevention (Stealth consistency)
        # If the sensor already has an active accepted credential for 'username' with a different password, REJECT!
        for cred in active_creds:
            if cred["username"] == username and cred["password"] != password:
                logger.debug(f"[REJECT] Username conflict: sensor already accepts a different password for '{username}'")
                return (
                    AdmissionDecision.REJECT,
                    AdmissionReason.USERNAME_CONFLICT,
                    {}
                )

        # Step 3: Record attempt in sliding window per source IP
        window = self.attempts.setdefault(src_ip, [])
        # Prune old attempts outside window_seconds
        cutoff = now - self.window_seconds
        window = [att for att in window if att[0] >= cutoff]
        window.append((now, username, password))
        self.attempts[src_ip] = window

        # If no cluster fingerprints loaded, cannot admit via fingerprint
        if not self.fingerprint_bundle:
            return (AdmissionDecision.REJECT, AdmissionReason.NO_MATCH, {})

        # Step 4: Evaluate against cluster fingerprints
        # Collect distinct pairs in current window
        distinct_window_pairs = set((u, p) for _, u, p in window)
        current_pair_str = f"{username}:{password}"

        best_cluster_uuid = None
        best_score = 0.0
        best_matched_pairs = []

        for cluster_uuid, cluster_data in self.fingerprint_bundle.items():
            cluster_pairs = cluster_data.get("pairs", {})
            # Current attempt must be part of this cluster's fingerprint
            if current_pair_str not in cluster_pairs:
                continue

            matched_pairs = []
            score = 0.0
            for u, p in distinct_window_pairs:
                pk = f"{u}:{p}"
                if pk in cluster_pairs:
                    matched_pairs.append(pk)
                    score += float(cluster_pairs[pk])

            if len(matched_pairs) >= self.min_distinct_pairs and score > best_score:
                best_score = score
                best_cluster_uuid = cluster_uuid
                best_matched_pairs = matched_pairs

        # Check if thresholds met
        if not best_cluster_uuid or best_score < self.min_score:
            return (AdmissionDecision.REJECT, AdmissionReason.NO_MATCH, {})

        # Step 5: Quotas, Cooldowns & Stealth Probability Checks
        # Prune daily admissions (older than 24h)
        day_ago = now - 86400
        self.daily_admissions = [adm for adm in self.daily_admissions if adm[0] >= day_ago]

        if len(self.daily_admissions) >= self.max_new_admissions_per_day:
            logger.info(f"[GATE] Admission skipped: daily quota ({self.max_new_admissions_per_day}) reached")
            return (AdmissionDecision.REJECT, AdmissionReason.QUOTA_EXCEEDED, {})

        if len(active_creds) >= self.max_accepted_credentials:
            logger.info(f"[GATE] Admission skipped: max active accepted credentials ({self.max_accepted_credentials}) reached")
            return (AdmissionDecision.REJECT, AdmissionReason.QUOTA_EXCEEDED, {})

        # Cooldown per source IP
        last_adm = self.admissions_cooldown.get(src_ip, 0)
        if (now - last_adm) < (self.admission_cooldown_hours * 3600):
            logger.info(f"[GATE] Admission skipped: IP {src_ip} in cooldown window")
            return (AdmissionDecision.REJECT, AdmissionReason.COOLDOWN_ACTIVE, {})

        # Stealth probability roll
        if random.random() >= self.admission_probability:
            logger.info(f"[GATE] Admission skipped for {src_ip}: probability roll failed")
            return (AdmissionDecision.REJECT, AdmissionReason.PROBABILITY_SKIPPED, {})

        # Step 6: All criteria met -> ADMIT via Fingerprint Match!
        self.daily_admissions.append((now, src_ip))
        self.admissions_cooldown[src_ip] = now
        self.add_accepted_credential(username, password, matched_cluster_uuid=best_cluster_uuid)

        logger.info(
            f"[ADMISSION] IP {src_ip} ADMITTED via cluster {best_cluster_uuid}! "
            f"(Score: {best_score:.1f}, Matched {len(best_matched_pairs)} pairs: {best_matched_pairs})"
        )
        return (
            AdmissionDecision.ADMIT,
            AdmissionReason.FINGERPRINT_MATCH,
            {
                "matched_cluster_uuid": best_cluster_uuid,
                "score": best_score,
                "matched_pairs_count": len(best_matched_pairs),
                "matched_pairs": best_matched_pairs
            }
        )
