import unittest
import time
from src.admission_engine import AdmissionEngine, AdmissionDecision, AdmissionReason


class TestAdmissionEngine(unittest.TestCase):
    def setUp(self):
        # Create an in-memory engine with probability=1.0 for deterministic testing
        self.engine = AdmissionEngine(
            sqlite_db_path=":memory:",
            window_seconds=180,
            min_distinct_pairs=3,
            min_score=12.0,
            admission_probability=1.0,
            max_new_admissions_per_day=3,
            max_accepted_credentials=3,
            accepted_credential_ttl_days=14,
            admission_cooldown_hours=24
        )

        # Load dummy bundle
        self.cluster_uuid = "cluster-test-123"
        self.bundle = {
            "version": "2026-10-15T12:00:00Z",
            "clusters": {
                self.cluster_uuid: {
                    "pairs": {
                        "pi:raspberryP1!": 5.0,
                        "ubnt:ubnt2019": 5.0,
                        "support:sup@rt#": 5.0,
                        "cisco:cisco_vpn!": 4.5
                    }
                }
            }
        }
        self.engine.load_bundle(self.bundle)

    def test_single_pair_rejected(self):
        """A single characteristic credential pair must NOT trigger admission on its own."""
        dec, reason, _ = self.engine.evaluate_attempt("198.51.100.1", "pi", "raspberryP1!")
        self.assertEqual(dec, AdmissionDecision.REJECT)
        self.assertEqual(reason, AdmissionReason.NO_MATCH)

    def test_multi_pair_sequence_admitted(self):
        """A sequence of 3 characteristic pairs meeting score >= 12.0 MUST trigger admission."""
        ip = "198.51.100.2"

        # Attempt 1: pi:raspberryP1! (Score 5.0, 1 pair) -> REJECT
        dec1, _, _ = self.engine.evaluate_attempt(ip, "pi", "raspberryP1!")
        self.assertEqual(dec1, AdmissionDecision.REJECT)

        # Attempt 2: ubnt:ubnt2019 (Cumulative Score 10.0, 2 pairs) -> REJECT
        dec2, _, _ = self.engine.evaluate_attempt(ip, "ubnt", "ubnt2019")
        self.assertEqual(dec2, AdmissionDecision.REJECT)

        # Attempt 3: support:sup@rt# (Cumulative Score 15.0, 3 pairs >= 3) -> ADMIT!
        dec3, reason3, meta3 = self.engine.evaluate_attempt(ip, "support", "sup@rt#")
        self.assertEqual(dec3, AdmissionDecision.ADMIT)
        self.assertEqual(reason3, AdmissionReason.FINGERPRINT_MATCH)
        self.assertEqual(meta3["matched_cluster_uuid"], self.cluster_uuid)
        self.assertEqual(meta3["matched_pairs_count"], 3)
        self.assertAlmostEqual(meta3["score"], 15.0)

    def test_accepted_credential_persists_across_ips(self):
        """An accepted credential must admit secondary logins from a DIFFERENT IP."""
        scanner_ip = "198.51.100.10"
        loader_ip = "203.0.113.50"

        # Scanner triggers admission for support:sup@rt#
        self.engine.evaluate_attempt(scanner_ip, "pi", "raspberryP1!")
        self.engine.evaluate_attempt(scanner_ip, "ubnt", "ubnt2019")
        dec, _, _ = self.engine.evaluate_attempt(scanner_ip, "support", "sup@rt#")
        self.assertEqual(dec, AdmissionDecision.ADMIT)

        # Loader IP connects hours later with the accepted credential
        dec_loader, reason_loader, _ = self.engine.evaluate_attempt(loader_ip, "support", "sup@rt#")
        self.assertEqual(dec_loader, AdmissionDecision.ADMIT)
        self.assertEqual(reason_loader, AdmissionReason.ACCEPTED_CREDENTIAL)

    def test_username_conflict_rejected(self):
        """If a sensor already accepted passwordA for user X, passwordB for user X is REJECTED."""
        ip1 = "198.51.100.20"
        ip2 = "198.51.100.21"

        # pi:raspberryP1! is accepted
        self.engine.add_accepted_credential("pi", "raspberryP1!")

        # Client attempts pi with a different password -> Must be rejected for consistency
        dec, reason, _ = self.engine.evaluate_attempt(ip2, "pi", "wrong_password_123")
        self.assertEqual(dec, AdmissionDecision.REJECT)
        self.assertEqual(reason, AdmissionReason.USERNAME_CONFLICT)

    def test_daily_quota_limit(self):
        """Daily admission limit is strictly enforced."""
        self.engine.max_new_admissions_per_day = 1
        self.engine.max_accepted_credentials = 10

        ip1 = "198.51.100.30"
        ip2 = "198.51.100.31"

        # Admit IP 1
        self.engine.evaluate_attempt(ip1, "pi", "raspberryP1!")
        self.engine.evaluate_attempt(ip1, "ubnt", "ubnt2019")
        dec1, _, _ = self.engine.evaluate_attempt(ip1, "support", "sup@rt#")
        self.assertEqual(dec1, AdmissionDecision.ADMIT)

        # IP 2 attempts valid sequence, but quota reached -> REJECT
        self.engine.evaluate_attempt(ip2, "pi", "raspberryP1!")
        self.engine.evaluate_attempt(ip2, "ubnt", "ubnt2019")
        dec2, reason2, _ = self.engine.evaluate_attempt(ip2, "cisco", "cisco_vpn!")
        self.assertEqual(dec2, AdmissionDecision.REJECT)
        self.assertEqual(reason2, AdmissionReason.QUOTA_EXCEEDED)


if __name__ == "__main__":
    unittest.main()
