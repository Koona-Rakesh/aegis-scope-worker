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
    def config(self):
        return worker.Config(
            control_plane_url="https://control.example",
            worker_token="token",
            site_dispatch_token="dispatch-token",
            zap_api_key="zap-key",
            worker_id="test-worker",
            zap_url="http://127.0.0.1:8080",
            poll_seconds=2,
            max_scan_seconds=600,
            run_once=True,
        )

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
        with self.assertRaisesRegex(RuntimeError, "passive API surface"):
            worker.enforce_policy(job)

    @patch.object(worker, "assert_public_dns")
    def test_accepts_bounded_basic_policy(self, dns):
        job = self.job()
        job["mode"] = "basic"
        job["policy"].update({
            "activeScan": True,
            "allowedActiveRuleIds": ["40012", "40018"],
            "allowedMethods": ["GET"],
            "maxRequests": 250,
            "maxDurationSeconds": 600,
            "maxEndpoints": 20,
            "maxConcurrentRequests": 1,
        })
        self.assertEqual(worker.enforce_policy(job), ("https://example.com", "example.com"))
        dns.assert_called_once_with("example.com")

    @patch.object(worker, "assert_public_dns")
    def test_accepts_safe_resilience_policy(self, dns):
        job = self.job()
        job["mode"] = "resilience"
        job["policy"].update({
            "activeScan": False,
            "resilienceObservation": True,
            "allowedMethods": ["GET"],
            "maxRequests": 12,
            "maxDurationSeconds": 30,
            "intervalMilliseconds": 500,
            "maxConcurrentRequests": 1,
            "stagingOrMaintenanceConfirmed": True,
        })
        self.assertEqual(worker.enforce_policy(job), ("https://example.com", "example.com"))
        dns.assert_called_once_with("example.com")

    @patch.object(worker, "assert_public_dns")
    def test_accepts_passive_openapi_inventory_policy(self, dns):
        job = self.job()
        job["mode"] = "api"
        job["policy"].update({
            "activeScan": False,
            "apiDiscovery": True,
            "openApiUrl": "https://example.com/openapi.json",
            "allowedMethods": ["GET"],
            "maxRequests": 1,
            "maxDocumentBytes": 2_000_000,
            "maxEndpoints": 500,
            "resolveExternalReferences": False,
        })
        self.assertEqual(worker.enforce_policy(job), ("https://example.com", "example.com"))
        dns.assert_called_once_with("example.com")

    @patch.object(worker, "assert_public_dns")
    def test_accepts_specification_free_api_surface_policy(self, dns):
        job = self.job()
        job["mode"] = "api"
        job["policy"].update({
            "activeScan": False,
            "apiDiscovery": True,
            "apiSurfaceDiscovery": True,
            "allowedMethods": ["GET"],
            "maxRequests": 10,
            "maxAssetBytes": 1_000_000,
            "maxTotalBytes": 4_000_000,
            "maxEndpoints": 200,
            "resolveExternalReferences": False,
        })
        self.assertEqual(worker.enforce_policy(job), ("https://example.com", "example.com"))
        dns.assert_called_once_with("example.com")

    @patch.object(worker, "assert_public_dns")
    def test_rejects_api_surface_request_volume_above_ceiling(self, _dns):
        job = self.job()
        job["mode"] = "api"
        job["policy"].update({
            "activeScan": False,
            "apiDiscovery": True,
            "apiSurfaceDiscovery": True,
            "allowedMethods": ["GET"],
            "maxRequests": 11,
            "maxAssetBytes": 1_000_000,
            "maxTotalBytes": 4_000_000,
            "maxEndpoints": 200,
            "resolveExternalReferences": False,
        })
        with self.assertRaisesRegex(RuntimeError, "maxRequests"):
            worker.enforce_policy(job)

    @patch.object(worker, "assert_public_dns")
    def test_rejects_cross_origin_openapi_document(self, _dns):
        job = self.job()
        job["mode"] = "api"
        job["policy"].update({
            "activeScan": False,
            "apiDiscovery": True,
            "openApiUrl": "https://docs.example.net/openapi.json",
            "allowedMethods": ["GET"],
            "maxRequests": 1,
            "maxDocumentBytes": 2_000_000,
            "maxEndpoints": 500,
            "resolveExternalReferences": False,
        })
        with self.assertRaisesRegex(RuntimeError, "verified origin"):
            worker.enforce_policy(job)

    @patch.object(worker, "assert_public_dns")
    def test_rejects_resilience_request_volume_above_ceiling(self, _dns):
        job = self.job()
        job["mode"] = "resilience"
        job["policy"].update({
            "activeScan": False,
            "resilienceObservation": True,
            "allowedMethods": ["GET"],
            "maxRequests": 13,
            "maxDurationSeconds": 30,
            "intervalMilliseconds": 500,
            "maxConcurrentRequests": 1,
            "stagingOrMaintenanceConfirmed": True,
        })
        with self.assertRaisesRegex(RuntimeError, "maxRequests"):
            worker.enforce_policy(job)

    @patch.object(worker, "assert_public_dns")
    def test_rejects_prohibited_basic_rule(self, _dns):
        job = self.job()
        job["mode"] = "basic"
        job["policy"].update({
            "activeScan": True,
            "allowedActiveRuleIds": ["40018", "90020"],
            "allowedMethods": ["GET"],
            "maxRequests": 250,
            "maxDurationSeconds": 600,
            "maxEndpoints": 20,
            "maxConcurrentRequests": 1,
        })
        with self.assertRaisesRegex(RuntimeError, "prohibited active rule"):
            worker.enforce_policy(job)

    @patch.object(worker, "assert_public_dns")
    def test_rejects_post_body_active_policy(self, _dns):
        job = self.job()
        job["mode"] = "basic"
        job["policy"].update({
            "activeScan": True,
            "allowedActiveRuleIds": ["40012"],
            "allowedMethods": ["GET", "POST"],
            "maxRequests": 100,
            "maxDurationSeconds": 300,
            "maxEndpoints": 5,
            "maxConcurrentRequests": 1,
        })
        with self.assertRaisesRegex(RuntimeError, "GET query parameters only"):
            worker.enforce_policy(job)

    def test_basic_targets_only_include_same_origin_query_urls(self):
        urls = [
            "https://example.com/",
            "https://example.com/search?q=one#fragment",
            "https://example.com/search?q=one",
            "https://example.com/item?id=2",
            "https://third-party.example/search?q=one",
        ]
        self.assertEqual(worker.basic_active_targets(urls, "https://example.com", 20), [
            "https://example.com/search?q=one",
            "https://example.com/item?id=2",
        ])

    def test_basic_targets_honor_endpoint_cap(self):
        urls = [f"https://example.com/item?id={index}" for index in range(10)]
        self.assertEqual(len(worker.basic_active_targets(urls, "https://example.com", 3)), 3)

    @patch.object(worker, "progress")
    @patch.object(worker, "control", return_value={})
    @patch.object(worker, "zap")
    def test_basic_scan_enables_only_approved_rules_and_get(self, zap, _control, _progress):
        job = self.job()
        job["mode"] = "basic"
        job["policy"].update({
            "activeScan": True,
            "allowedActiveRuleIds": ["40018", "40012"],
            "allowedMethods": ["GET"],
            "maxRequests": 20,
            "maxDurationSeconds": 120,
            "maxEndpoints": 2,
            "maxConcurrentRequests": 1,
        })
        message_counts = iter([10, 10, 11, 11])

        def response(_config, path, params=None):
            if path == "core/view/numberOfMessages":
                return {"numberOfMessages": str(next(message_counts))}
            if path == "ascan/action/scan":
                return {"scan": "7"}
            if path == "ascan/view/status":
                return {"status": "100"}
            return {}

        zap.side_effect = response
        requests, truncated = worker.run_basic_active_scan(
            self.config(), job, "https://example.com", ["https://example.com/search?q=test"], 1,
        )
        self.assertEqual((requests, truncated), (1, False))
        enabled = [call for call in zap.call_args_list if call.args[1] == "ascan/action/enableScanners"]
        self.assertEqual(enabled[0].args[2]["ids"], "40012,40018")
        scans = [call for call in zap.call_args_list if call.args[1] == "ascan/action/scan"]
        self.assertEqual(scans[0].args[2]["method"], "GET")

    @patch.object(worker, "progress")
    @patch.object(worker, "control", return_value={})
    @patch.object(worker, "zap")
    def test_basic_scan_stops_at_request_budget(self, zap, _control, _progress):
        job = self.job()
        job["mode"] = "basic"
        job["policy"].update({
            "activeScan": True,
            "allowedActiveRuleIds": ["40012"],
            "allowedMethods": ["GET"],
            "maxRequests": 1,
            "maxDurationSeconds": 120,
            "maxEndpoints": 1,
            "maxConcurrentRequests": 1,
        })
        message_counts = iter([20, 20, 21, 21])

        def response(_config, path, params=None):
            if path == "core/view/numberOfMessages":
                return {"numberOfMessages": str(next(message_counts))}
            if path == "ascan/action/scan":
                return {"scan": "8"}
            return {}

        zap.side_effect = response
        self.assertEqual(worker.run_basic_active_scan(
            self.config(), job, "https://example.com", ["https://example.com/search?q=test"], 1,
        ), (1, True))
        stopped = [call for call in zap.call_args_list if call.args[1] == "ascan/action/stop"]
        self.assertEqual(stopped[0].args[2]["scanId"], "8")

    @patch.object(worker, "sleep_interruptibly")
    @patch.object(worker, "basic_control_check")
    @patch.object(worker, "progress")
    @patch.object(worker, "scoped_get")
    def test_resilience_observer_stops_on_throttling_signal(
        self,
        scoped_get,
        _progress,
        _control_check,
        _sleep,
    ):
        scoped_get.side_effect = [
            {"status": 200, "latencySeconds": 0.05, "rateHeaders": {}},
            {"status": 200, "latencySeconds": 0.06, "rateHeaders": {}},
            {"status": 429, "latencySeconds": 0.04, "rateHeaders": {"retry-after": "5"}},
        ]
        job = self.job()
        job["mode"] = "resilience"
        job["policy"].update({
            "activeScan": False,
            "resilienceObservation": True,
            "allowedMethods": ["GET"],
            "maxRequests": 12,
            "maxDurationSeconds": 30,
            "intervalMilliseconds": 500,
            "maxConcurrentRequests": 1,
            "stagingOrMaintenanceConfirmed": True,
        })
        with patch.object(worker, "assert_public_dns"):
            observation = worker.run_resilience_observation(
                self.config(), job, "https://example.com",
            )
        self.assertTrue(observation["observed"])
        self.assertEqual(observation["requestsSent"], 3)
        self.assertEqual(observation["statuses"], [200, 200, 429])
        self.assertEqual(observation["finding"]["severity"], "Info")
        self.assertIn("Rate limiting observed", observation["finding"]["title"])

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

    def test_groups_same_risk_across_endpoints(self):
        alerts = [
            {"alert": "Strict-Transport-Security Header Not Set", "pluginId": "10035", "risk": "Medium", "url": "https://example.com/", "cweid": "319"},
            {"alert": "Strict-Transport-Security Header Not Set", "pluginId": "10035", "risk": "Medium", "url": "https://example.com/app.js", "cweid": "319"},
        ]
        findings = worker.normalize_alerts(alerts)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["observationCount"], 2)
        self.assertEqual(len(findings[0]["affectedEndpoints"]), 2)

    def test_suppresses_document_controls_on_static_assets(self):
        alerts = [
            {"alert": "Missing Anti-clickjacking Header", "risk": "Medium", "url": "https://example.com/"},
            {"alert": "Missing Anti-clickjacking Header", "risk": "Medium", "url": "https://example.com/favicon.svg"},
            {"alert": "CSP: style-src unsafe-inline", "risk": "Low", "url": "https://example.com/sitemap.xml"},
        ]
        findings = worker.normalize_alerts(alerts)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["affectedEndpoints"], ["https://example.com/"])

    def test_information_and_invalid_cwe_are_not_scored_as_low(self):
        finding = worker.normalize_alert({
            "alert": "Modern Web Application",
            "risk": "Informational",
            "url": "https://example.com/",
            "cweid": "-1",
        })
        self.assertEqual(finding["severity"], "Info")
        self.assertIsNone(finding["cwe"])

    def test_parses_openapi_inventory_without_invoking_operations(self):
        inventory = worker.parse_openapi_inventory({
            "openapi": "3.1.0",
            "info": {"title": "Orders API"},
            "paths": {
                "/orders": {"get": {"operationId": "listOrders"}, "post": {"operationId": "createOrder"}},
                "/orders/{id}": {"get": {"operationId": "getOrder"}, "parameters": []},
            },
        }, "https://example.com", 500)
        self.assertEqual(inventory["title"], "Orders API")
        self.assertEqual(len(inventory["operations"]), 3)
        self.assertEqual(inventory["methodCounts"], {"GET": 2, "POST": 1})
        self.assertFalse(inventory["truncated"])

    def test_openapi_inventory_honors_operation_ceiling(self):
        inventory = worker.parse_openapi_inventory({
            "swagger": "2.0",
            "paths": {f"/items/{index}": {"get": {}} for index in range(4)},
        }, "https://example.com", 2)
        self.assertEqual(len(inventory["operations"]), 2)
        self.assertTrue(inventory["truncated"])

    def test_discovers_only_same_origin_script_assets(self):
        html = """
        <script src="/assets/app.js"></script>
        <script src="https://example.com/assets/vendor.js?v=2"></script>
        <script src="https://third-party.example/tracker.js"></script>
        <script src="/assets/app.js"></script>
        """
        self.assertEqual(worker.first_party_script_urls(html, "https://example.com", 5), [
            "https://example.com/assets/app.js",
            "https://example.com/assets/vendor.js?v=2",
        ])

    def test_discovers_api_references_without_calling_operations(self):
        discovery = worker.discover_api_references([
            'fetch("/api/orders")\nconst profile = "/api/users/{id}";',
            'const graph = `/graphql`; const image = "/api/logo.svg";',
        ], "https://example.com", 200)
        self.assertEqual(discovery["endpoints"], [
            "https://example.com/api/orders",
            "https://example.com/api/users/{id}",
            "https://example.com/graphql",
        ])
        self.assertEqual(discovery["sensitiveEndpoints"], [
            "https://example.com/api/orders",
            "https://example.com/api/users/{id}",
        ])
        self.assertFalse(discovery["truncated"])

    def test_api_reference_discovery_honors_endpoint_ceiling(self):
        discovery = worker.discover_api_references([
            '"/api/one"; "/api/two"; "/api/three";'
        ], "https://example.com", 2)
        self.assertEqual(len(discovery["endpoints"]), 2)
        self.assertTrue(discovery["truncated"])

    @patch.object(worker, "progress")
    @patch.object(worker, "assert_public_dns")
    @patch.object(worker, "basic_control_check")
    @patch.object(worker, "bounded_surface_get")
    def test_api_surface_reviews_assets_but_does_not_call_discovered_endpoints(
        self, bounded_get, _control_check, _dns, _progress,
    ):
        bounded_get.side_effect = [
            {"text": '<script src="/assets/app.js"></script>', "bytes": 45, "contentType": "text/html"},
            {"text": 'fetch("/api/orders")', "bytes": 20, "contentType": "application/javascript"},
        ]
        job = self.job()
        job["mode"] = "api"
        job["policy"].update({
            "activeScan": False,
            "apiDiscovery": True,
            "apiSurfaceDiscovery": True,
            "allowedMethods": ["GET"],
            "maxRequests": 10,
            "maxAssetBytes": 1_000_000,
            "maxTotalBytes": 4_000_000,
            "maxEndpoints": 200,
            "resolveExternalReferences": False,
        })
        discovery = worker.run_api_surface_discovery(self.config(), job, "https://example.com")
        self.assertEqual(discovery["endpoints"], ["https://example.com/api/orders"])
        self.assertEqual(discovery["requestsSent"], 2)
        self.assertEqual([call.args[0] for call in bounded_get.call_args_list], [
            "https://example.com",
            "https://example.com/assets/app.js",
        ])

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
            site_dispatch_token="dispatch-token",
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
            {
                "x-aegis-scanner-token": "token",
                "oai-sites-authorization": "Bearer dispatch-token",
            },
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
            site_dispatch_token="dispatch-token",
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
