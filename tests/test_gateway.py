import unittest
import os
import sys
import time
import asyncio
from unittest.mock import patch, MagicMock, AsyncMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from admission_engine import AdmissionEngine, AdmissionDecision, AdmissionReason, mask_credential_pair
import gateway
import monitor


class TestGatewayAndRelay(unittest.TestCase):
    def setUp(self):
        self.engine = AdmissionEngine(
            sqlite_db_path=":memory:",
            window_seconds=180,
            min_distinct_pairs=3,
            min_score=12.0,
            admission_probability=1.0,
            max_new_admissions_per_day=3,
            max_accepted_credentials=3,
            accepted_credential_ttl_days=14,
            admission_cooldown_hours=24,
        )
        self.cluster_uuid = "cluster-gw-999"
        self.engine.load_bundle({
            "version": "2026-10-17T00:00:00Z",
            "clusters": {
                self.cluster_uuid: {
                    "pairs": {
                        "pi:raspberryP1!": 5.0,
                        "ubnt:ubnt2019": 5.0,
                        "support:sup@rt#": 5.0,
                    }
                }
            },
            "params": {
                "window_seconds": 180,
                "min_distinct_pairs": 3,
                "min_score": 12.0,
                "admission_probability": 1.0,
            }
        })

    def tearDown(self):
        self.engine.close()

    def test_credential_pair_masking_in_logs(self):
        """Ensure matched credential pairs have passwords masked in INFO logs."""
        self.assertEqual(mask_credential_pair("root:SuperSecret123"), "root:***")
        ip = "198.51.100.55"
        with self.assertLogs("admission_engine", level="INFO") as cm:
            self.engine.evaluate_attempt(ip, "pi", "raspberryP1!")
            self.engine.evaluate_attempt(ip, "ubnt", "ubnt2019")
            dec, reason, meta = self.engine.evaluate_attempt(ip, "support", "sup@rt#")

        self.assertEqual(dec, AdmissionDecision.ADMIT)
        self.assertEqual(reason, AdmissionReason.FINGERPRINT_MATCH)
        # Metadata retains full pairs for Collector API reporting
        self.assertIn("support:sup@rt#", meta["matched_pairs"])
        # Logs must NEVER contain cleartext passwords
        combined_logs = "\n".join(cm.output)
        self.assertNotIn("raspberryP1!", combined_logs)
        self.assertNotIn("ubnt2019", combined_logs)
        self.assertNotIn("sup@rt#", combined_logs)
        self.assertIn("support:***", combined_logs)

    def test_sliding_window_pruning_and_caps(self):
        """Ensure stale IPs and excess attempts are pruned to prevent unbounded memory growth."""
        engine = AdmissionEngine(
            sqlite_db_path=":memory:",
            window_seconds=10,
            max_attempts_per_ip=5,
            max_tracked_ips=3,
        )
        for i in range(10):
            engine.evaluate_attempt("198.51.100.1", f"user{i}", f"pass{i}")
        self.assertEqual(len(engine.attempts["198.51.100.1"]), 5)

        for idx in range(6):
            engine.evaluate_attempt(f"198.51.100.{10 + idx}", "u", "p")
        self.assertLessEqual(len(engine.attempts), 3)
        engine.close()

    def test_sync_accepted_credentials_replaces_stale_entries(self):
        """Verify sync_accepted_credentials_list replaces local cache cleanly."""
        self.engine.add_accepted_credential("old_user", "old_pass")
        self.engine.sync_accepted_credentials_list([
            {
                "username": "synced_user",
                "password": "synced_pass",
                "origin_attackgroup_uuid": "ag-1",
                "origin_attackcluster_uuid": "ac-1",
            }
        ])
        active = self.engine.get_active_accepted_credentials()
        self.assertEqual(len(active), 1)
        self.assertEqual(active[0]["username"], "synced_user")
        self.assertEqual(active[0]["origin_attackgroup_uuid"], "ag-1")
        self.assertEqual(active[0]["matched_cluster_uuid"], "ac-1")

    @patch("gateway.requests.post")
    def test_gateway_server_rejects_and_reports_bruteforce(self, mock_post):
        """Rejected login attempts report SSH_BRUTE_FORCE to Collector and return False."""
        srv = gateway.GatewaySSHServer(self.engine, "203.0.113.10")
        mock_conn = MagicMock()
        mock_conn.get_extra_info.return_value = ("198.51.100.77", 54321)
        srv.connection_made(mock_conn)

        result = srv.validate_password("root", "wrongpass")
        self.assertFalse(result)
        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args
        self.assertIn("/v2/add_attack/ssh_bruteforce", args[0])
        self.assertEqual(kwargs["json"]["source"], "198.51.100.77")
        self.assertEqual(kwargs["json"]["metadata"]["username"], "root")
        self.assertEqual(kwargs["json"]["metadata"]["password"], "wrongpass")

    @patch("gateway.requests.post")
    def test_gateway_server_admits_and_requests_broker_session(self, mock_post):
        """Admitted sequence notifies Collector, registers Engagement, obtains Cowrie relay token, and finalizes on disconnect."""
        broker_response = MagicMock()
        broker_response.status_code = 200
        broker_response.json.return_value = {
            "cowrie_host": "10.20.255.2",
            "cowrie_port": 2222,
            "relay_token": "tok-secret-999",
        }
        ok_response = MagicMock()
        ok_response.status_code = 200
        mock_post.side_effect = lambda url, *args, **kwargs: (
            broker_response if "/broker/v1/sessions" in url else ok_response
        )

        srv = gateway.GatewaySSHServer(self.engine, "203.0.113.10")
        mock_conn = MagicMock()
        mock_conn.get_extra_info.return_value = ("198.51.100.88", 51111)
        srv.connection_made(mock_conn)

        self.assertFalse(srv.validate_password("pi", "raspberryP1!"))
        self.assertFalse(srv.validate_password("ubnt", "ubnt2019"))
        self.assertTrue(srv.validate_password("support", "sup@rt#"))

        self.assertEqual(srv.cowrie_host, "10.20.255.2")
        self.assertEqual(srv.cowrie_port, 2222)
        self.assertEqual(srv.relay_token, "tok-secret-999")
        self.assertIsNotNone(srv.admitted_engagement_uuid)

        srv.bytes_in = 128
        srv.bytes_out = 512
        srv.connection_lost(None)

        last_call = mock_post.call_args_list[-1]
        self.assertIn("/v2/engagement", last_call[0][0])
        self.assertEqual(last_call[1]["json"]["engagement_status"], "COMPLETED")
        self.assertEqual(last_call[1]["json"]["bytes_in"], 128)
        self.assertEqual(last_call[1]["json"]["bytes_out"], 512)

    def test_cowrie_relay_session_interactive_and_cleanup(self):
        """Test CowrieRelaySession relays stdout/stderr/stdin and cleans up connections properly."""
        async def run_test():
            srv = gateway.GatewaySSHServer(self.engine, "203.0.113.10")
            srv.admitted_engagement_uuid = "eng-123"
            srv.admitted_username = "support"
            srv.cowrie_host = "10.20.255.2"
            srv.cowrie_port = 2222
            srv.relay_token = "relay-tok"

            session = gateway.CowrieRelaySession(srv, max_session_seconds=5, idle_timeout_seconds=5)
            mock_chan = MagicMock()
            session.connection_made(mock_chan)
            session.pty_requested("xterm", (100, 30, 0, 0), {})
            session.env_received("LANG", "en_US.UTF-8")

            # Mock Cowrie process stdout/stderr/stdin
            stdout_chunks = ["Linux srv 6.1\n", ""]
            stderr_chunks = ["warn: test\n", ""]

            mock_proc = MagicMock()
            mock_proc.exit_status = 0
            mock_proc.stdout.at_eof.side_effect = [False, True]
            mock_proc.stdout.read = AsyncMock(side_effect=stdout_chunks)
            mock_proc.stderr.at_eof.side_effect = [False, True]
            mock_proc.stderr.read = AsyncMock(side_effect=stderr_chunks)
            mock_proc.stdin.is_closing.return_value = False
            mock_proc.wait = AsyncMock(return_value=0)

            mock_client_conn = MagicMock()
            mock_client_conn.create_process = AsyncMock(return_value=mock_proc)
            mock_client_conn.wait_closed = AsyncMock(return_value=None)

            with patch("gateway.asyncssh.connect", new=AsyncMock(return_value=mock_client_conn)):
                await session._start_relay(command="uname -a")
                session.data_received("id\n", None)

            mock_chan.write.assert_any_call("Linux srv 6.1\n")
            mock_chan.write_stderr.assert_called_once_with("warn: test\n")
            mock_chan.exit.assert_called_once_with(0)
            mock_chan.close.assert_called()
            mock_client_conn.close.assert_called()
            self.assertEqual(srv.bytes_in, 3)
            self.assertGreater(srv.bytes_out, 0)

        asyncio.run(run_test())

    def test_cowrie_relay_session_enforces_idle_timeout(self):
        """Test CowrieRelaySession terminates idle sessions exceeding idle_timeout_seconds."""
        async def run_test():
            srv = gateway.GatewaySSHServer(self.engine, "203.0.113.10")
            srv.admitted_engagement_uuid = "eng-idle"
            srv.admitted_username = "root"
            srv.cowrie_host = "10.20.255.2"
            srv.cowrie_port = 2222
            srv.relay_token = "relay-tok"

            session = gateway.CowrieRelaySession(srv, max_session_seconds=10, idle_timeout_seconds=0.1)
            mock_chan = MagicMock()
            session.connection_made(mock_chan)

            proc_done = asyncio.Event()

            async def _wait_until_terminated():
                await proc_done.wait()
                return 0

            mock_proc = MagicMock()
            mock_proc.exit_status = 0
            mock_proc.stdout.at_eof.return_value = True
            mock_proc.stderr.at_eof.return_value = True
            mock_proc.terminate.side_effect = lambda: proc_done.set()
            mock_proc.wait = _wait_until_terminated

            mock_client_conn = MagicMock()
            mock_client_conn.create_process = AsyncMock(return_value=mock_proc)
            mock_client_conn.wait_closed = AsyncMock(return_value=None)

            with patch("gateway.asyncssh.connect", new=AsyncMock(return_value=mock_client_conn)):
                await session._start_relay(command=None)

            mock_proc.terminate.assert_called()
            mock_chan.close.assert_called()

        asyncio.run(run_test())

    def test_monitor_password_masking_and_bounded_queue(self):
        """Verify monitor.py masks passwords in log payloads and enforces drop-oldest queue bounding."""
        payload = {
            "source": "198.51.100.1",
            "metadata": {"username": "admin", "password": "MyCleartextPassword!"},
        }
        masked = monitor.mask_payload_for_log(payload)
        self.assertEqual(masked["metadata"]["password"], "***")
        self.assertEqual(payload["metadata"]["password"], "MyCleartextPassword!")

        raw_line = "Login attempt by username 'root', password 'SuperSecretPassword', from ip '198.51.100.1'"
        redacted = monitor.redact_sshd_line(raw_line)
        self.assertNotIn("SuperSecretPassword", redacted)
        self.assertIn("password '***'", redacted)

        import queue as q_mod
        small_q = q_mod.Queue(maxsize=2)
        monitor.enqueue_attack({"id": 1}, small_q)
        monitor.enqueue_attack({"id": 2}, small_q)
        monitor.enqueue_attack({"id": 3}, small_q)
        items = [small_q.get_nowait(), small_q.get_nowait()]
        self.assertEqual([i["id"] for i in items], [2, 3])


if __name__ == "__main__":
    unittest.main()
