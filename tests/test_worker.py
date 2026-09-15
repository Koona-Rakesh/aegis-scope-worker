import importlib.util
import pathlib
import sys
import unittest
from unittest.mock import Mock, patch


SPEC = importlib.util.spec_from_file_location("worker", pathlib.Path(__file__).parents[1] / "worker.py")
worker = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
sys.modules[SPEC.name] = worker
SPEC.loader.exec_module(worker)


class WorkerPolicyTests(unittest.TestCase):
    def job(self):
        return {
            "id": "scan-1",
            "mode": "standard",
            "target": {"origin": "https://example.com", "hostname": "example.com"},
            "policy": {
                "allowedOrigins": ["https://example.com"],
                "destructiveActions": False,
            },
        }

    @patch.object(worker, "assert_public_dns")
    def test_accepts_locked_passive_job(self, dns):
        self.assertEqual(worker.enforce_policy(self.job()), ("https://example.com", "example.com"))
        dns.assert_called_once_with("example.com")

    @patch.object(worker, "assert_public_dns")
    def test_rejects_advanced_mode(self, _dns):
        job = self.job()
        job["mode"] = "advanced"
        with self.assertRaisesRegex(RuntimeError, "Standard passive"):
            worker.enforce_policy(job)

    @patch.object(worker, "assert_public_dns")
    def test_rejects_origin_outside_allowlist(self, _dns):
        job = self.job()
        job["policy"]["allowedOrigins"] = ["https://www.example.com"]
        with self.assertRaisesRegex(RuntimeError, "outside its allowlist"):
            worker.enforce_policy(job)

    @patch.object(worker.socket, "getaddrinfo")
    def test_rejects_private_dns_answer(self, getaddrinfo):
        getaddrinfo.return_value = [(2, 1, 6, "", ("10.0.0.1", 443))]
        with self.assertRaisesRegex(RuntimeError, "private or reserved"):
            worker.assert_public_dns("example.com")

    def test_normalizes_finding(self):
        finding = worker.normalize_alert({
            "alert": "Content Security Policy Header Not Set",
            "risk": "Medium",
            "confidence": "High",
            "url": "https://example.com/",
            "cweid": "693",
            "description": "A policy header is missing.",
            "solution": "Set a restrictive policy.\nTest it before enforcement.",
        })
        self.assertEqual(finding["severity"], "Medium")
        self.assertEqual(finding["confidence"], "High")
        self.assertEqual(finding["cwe"], "CWE-693")
        self.assertEqual(len(finding["fingerprint"]), 64)
        self.assertEqual(len(finding["remediation"]), 2)

    def test_boolean_env(self):
        with patch.dict(worker.os.environ, {"RUN_ONCE": "true"}, clear=False):
            self.assertTrue(worker.boolean_env("RUN_ONCE"))
        with patch.dict(worker.os.environ, {"RUN_ONCE": "0"}, clear=False):
            self.assertFalse(worker.boolean_env("RUN_ONCE"))

    @patch.object(worker, "json_request")
    def test_control_uses_private_site_safe_token_header(self, json_request):
        config = worker.Config(
            control_plane_url="https://control.example",
            worker_token="token",
            zap_api_key="zap-key",
            worker_id="test-worker",
            zap_url="http://127.0.0.1:8080",
            poll_seconds=2,
            max_scan_seconds=60,
            run_once=True,
        )
        worker.control(config, "POST", "/api/internal/jobs/claim", {"workerId": "test-worker"})
        self.assertEqual(
            json_request.call_args.kwargs["headers"],
            {"x-aegis-scanner-token": "token"},
        )

    @patch.object(worker, "sleep_interruptibly")
    @patch.object(worker, "shutdown_zap")
    @patch.object(worker, "wait_for_zap")
    @patch.object(worker, "start_zap")
    @patch.object(worker, "load_config")
    def test_run_once_exits_after_control_plane_error(
        self,
        load_config,
        start_zap,
        _wait_for_zap,
        _shutdown_zap,
        sleep_interruptibly,
    ):
        load_config.return_value = worker.Config(
            control_plane_url="https://control.example",
            worker_token="token",
            zap_api_key="zap-key",
            worker_id="test-worker",
            zap_url="http://127.0.0.1:8080",
            poll_seconds=2,
            max_scan_seconds=60,
            run_once=True,
        )
        start_zap.return_value = Mock()
        with patch.object(worker, "claim_job", side_effect=RuntimeError("HTTP 401")):
            self.assertEqual(worker.main(), 1)
        sleep_interruptibly.assert_not_called()


if __name__ == "__main__":
    unittest.main()
