#!/usr/bin/env python3
"""AegisScope controlled web security scanner worker.

The worker claims authorized jobs from the AegisScope control plane and drives
the OWASP ZAP daemon bundled in the official stable container image. It only
accepts Standard passive scans, tightly bounded Basic active scans, a separate
low-rate resilience observation, passive OpenAPI inventory, and bounded
specification-free API surface discovery against one verified HTTPS origin.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import os
import re
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from typing import Any


BASIC_ACTIVE_RULE_IDS = frozenset({"40012", "40018"})
BASIC_MAX_REQUESTS = 250
BASIC_MAX_DURATION_SECONDS = 600
BASIC_MAX_ENDPOINTS = 20
RESILIENCE_MAX_REQUESTS = 12
RESILIENCE_MAX_DURATION_SECONDS = 30
RESILIENCE_MIN_INTERVAL_MILLISECONDS = 500
API_MAX_DOCUMENT_BYTES = 2_000_000
API_MAX_ENDPOINTS = 500
API_SURFACE_MAX_REQUESTS = 10
API_SURFACE_MAX_ASSET_BYTES = 1_000_000
API_SURFACE_MAX_TOTAL_BYTES = 4_000_000
API_SURFACE_MAX_ENDPOINTS = 200
OPENAPI_OPERATION_METHODS = frozenset({"get", "post", "put", "patch", "delete", "options", "head", "trace"})
API_PATH_PATTERN = re.compile(
    r'''["'`](\/(?:api|graphql|rest|v[1-9][0-9]*|auth)(?:\/[A-Za-z0-9._~!$&()*+,;=:@%{}\-]*)*(?:\?[A-Za-z0-9._~!$&()*+,;=:@%{}\-\/?]*)?)["'`]''',
    re.IGNORECASE,
)
SCRIPT_SOURCE_PATTERN = re.compile(r'''<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["'][^>]*>''', re.IGNORECASE)
SENSITIVE_API_TERMS = frozenset({
    "admin", "account", "accounts", "auth", "billing", "delete", "invoice", "invoices",
    "order", "orders", "password", "payment", "payments", "profile", "reset", "role",
    "roles", "token", "upload", "user", "users",
})
RATE_LIMIT_HEADERS = frozenset({
    "ratelimit-limit",
    "ratelimit-remaining",
    "ratelimit-reset",
    "retry-after",
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "x-ratelimit-reset",
})


class StopRequestedError(RuntimeError):
    pass


class ShutdownRequestedError(RuntimeError):
    pass


@dataclass(frozen=True)
class Config:
    control_plane_url: str
    worker_token: str
    site_dispatch_token: str
    zap_api_key: str
    worker_id: str
    zap_url: str
    poll_seconds: float
    max_scan_seconds: int
    run_once: bool


shutdown_requested = False
current_job_id: str | None = None
zap_process: subprocess.Popen[str] | None = None


def required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


def bounded_number(name: str, fallback: float, minimum: float, maximum: float) -> float:
    try:
        value = float(os.environ.get(name, fallback))
    except ValueError:
        return fallback
    return max(minimum, min(maximum, value))


def boolean_env(name: str, fallback: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return fallback
    return value.strip().lower() in {"1", "true", "yes", "on"}


def load_config() -> Config:
    worker_suffix = os.environ.get("RENDER_INSTANCE_ID") or socket.gethostname() or uuid.uuid4().hex[:8]
    return Config(
        control_plane_url=required("CONTROL_PLANE_URL").rstrip("/"),
        worker_token=required("SCANNER_CALLBACK_TOKEN"),
        site_dispatch_token=required("SITE_DISPATCH_TOKEN"),
        zap_api_key=required("ZAP_API_KEY"),
        worker_id=os.environ.get("WORKER_ID", f"render-zap-{worker_suffix}")[:100],
        zap_url=os.environ.get("ZAP_URL", "http://127.0.0.1:8080").rstrip("/"),
        poll_seconds=bounded_number("POLL_SECONDS", 5, 1, 60),
        max_scan_seconds=int(bounded_number("MAX_SCAN_SECONDS", 3600, 60, 7200)),
        run_once=boolean_env("RUN_ONCE"),
    )


def log(event: str, **fields: Any) -> None:
    print(json.dumps({"event": event, **fields}, separators=(",", ":")), flush=True)


def on_shutdown(signum: int, _frame: Any) -> None:
    global shutdown_requested
    shutdown_requested = True
    log("shutdown_requested", signal=signum, jobId=current_job_id)


def sleep_interruptibly(seconds: float) -> None:
    deadline = time.monotonic() + seconds
    while not shutdown_requested and time.monotonic() < deadline:
        time.sleep(min(0.25, max(0, deadline - time.monotonic())))


def json_request(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: dict[str, Any] | None = None,
    timeout: float = 15,
    allow_empty: bool = False,
) -> dict[str, Any] | None:
    data = json.dumps(body).encode() if body is not None else None
    request_headers = {"user-agent": "AegisScope-Scanner/0.2", **(headers or {})}
    if data is not None:
        request_headers["content-type"] = "application/json"
    request = urllib.request.Request(url, data=data, headers=request_headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            if allow_empty and response.status == 204:
                return None
            raw = response.read()
            return json.loads(raw or b"{}")
    except urllib.error.HTTPError as error:
        if allow_empty and error.code == 204:
            return None
        try:
            payload = json.loads(error.read() or b"{}")
        except (json.JSONDecodeError, UnicodeDecodeError):
            payload = {}
        raise RuntimeError(f"HTTP {error.code}: {payload.get('error', 'request failed')}") from error


def control(config: Config, method: str, path: str, body: dict[str, Any] | None = None, *, allow_empty: bool = False) -> dict[str, Any] | None:
    return json_request(
        f"{config.control_plane_url}{path}",
        method=method,
        headers={
            "x-aegis-scanner-token": config.worker_token,
            "oai-sites-authorization": f"Bearer {config.site_dispatch_token}",
        },
        body=body,
        allow_empty=allow_empty,
    )


def zap(config: Config, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    query = {str(key): str(value) for key, value in (params or {}).items()}
    query["apikey"] = config.zap_api_key
    url = f"{config.zap_url}/JSON/{path}/?{urllib.parse.urlencode(query)}"
    payload = json_request(url, timeout=30)
    if payload is None:
        raise RuntimeError("ZAP returned an empty response")
    if payload.get("code"):
        raise RuntimeError(f"ZAP request failed: {payload.get('message', payload['code'])}")
    return payload


def start_zap(config: Config) -> subprocess.Popen[str]:
    command = [
        "zap.sh",
        "-daemon",
        "-host",
        "127.0.0.1",
        "-port",
        "8080",
        "-dir",
        "/tmp/aegis-zap",
        "-config",
        "api.disablekey=false",
        "-config",
        f"api.key={config.zap_api_key}",
        "-config",
        "api.addrs.addr.name=127.0.0.1",
        "-config",
        "api.addrs.addr.regex=false",
        "-config",
        "spider.maxChildren=1000",
        "-config",
        "spider.maxDepth=10",
    ]
    return subprocess.Popen(command, stdout=sys.stdout, stderr=sys.stderr, text=True)


def wait_for_zap(config: Config, timeout_seconds: int = 180) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if shutdown_requested:
            raise ShutdownRequestedError("Worker is shutting down")
        if zap_process and zap_process.poll() is not None:
            raise RuntimeError(f"ZAP exited during startup with code {zap_process.returncode}")
        try:
            zap(config, "core/view/version")
            return
        except Exception:
            sleep_interruptibly(2)
    raise RuntimeError("ZAP did not become ready")


def claim_job(config: Config) -> dict[str, Any] | None:
    response = control(
        config,
        "POST",
        "/api/internal/jobs/claim",
        {"workerId": config.worker_id},
        allow_empty=True,
    )
    return None if response is None else response.get("job")


def progress(config: Config, job_id: str, phase: str, percent: int, **stats: int) -> None:
    control(
        config,
        "POST",
        f"/api/internal/jobs/{job_id}/progress",
        {"workerId": config.worker_id, "phase": phase, "progress": percent, **stats},
    )


def complete(config: Config, job_id: str, result: dict[str, Any]) -> None:
    control(
        config,
        "POST",
        f"/api/internal/jobs/{job_id}/complete",
        {"workerId": config.worker_id, **result},
    )


def enforce_policy(job: dict[str, Any]) -> tuple[str, str]:
    target = job.get("target") or {}
    policy = job.get("policy") or {}
    origin = str(target.get("origin") or "")
    hostname = str(target.get("hostname") or "").lower().rstrip(".")
    parsed = urllib.parse.urlsplit(origin)
    if parsed.scheme != "https" or not parsed.hostname or parsed.hostname.lower().rstrip(".") != hostname:
        raise RuntimeError("Job target violates its locked scope")
    if parsed.username or parsed.password or parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise RuntimeError("Job target must be an HTTPS origin")
    if parsed.port not in (None, 443, 8443):
        raise RuntimeError("Job target port is not permitted")
    if policy.get("destructiveActions") is not False:
        raise RuntimeError("Worker accepts only non-destructive policies")
    if origin not in (policy.get("allowedOrigins") or []):
        raise RuntimeError("Job origin is outside its allowlist")
    mode = job.get("mode")
    if mode not in ("standard", "basic", "resilience", "api"):
        raise RuntimeError("Worker permits only Standard, Basic, Safe resilience and passive API surface assessments")
    if mode == "standard" and policy.get("activeScan") not in (None, False):
        raise RuntimeError("Standard assessments must remain passive")
    if mode == "basic":
        validate_basic_policy(policy)
    if mode == "resilience":
        validate_resilience_policy(policy)
    if mode == "api":
        validate_api_policy(policy, origin)
    assert_public_dns(hostname)
    return origin, hostname


def policy_integer(policy: dict[str, Any], name: str, minimum: int, maximum: int) -> int:
    value = policy.get(name)
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum or value > maximum:
        raise RuntimeError(f"Basic policy {name} is outside its safe boundary")
    return value


def validate_basic_policy(policy: dict[str, Any]) -> None:
    if policy.get("activeScan") is not True:
        raise RuntimeError("Basic assessment requires an explicit active-scan policy")
    rule_ids = {str(value) for value in (policy.get("allowedActiveRuleIds") or [])}
    if not rule_ids or not rule_ids.issubset(BASIC_ACTIVE_RULE_IDS):
        raise RuntimeError("Basic assessment requested a prohibited active rule")
    if policy.get("allowedMethods") != ["GET"]:
        raise RuntimeError("Basic assessment permits GET query parameters only")
    policy_integer(policy, "maxRequests", 1, BASIC_MAX_REQUESTS)
    policy_integer(policy, "maxDurationSeconds", 60, BASIC_MAX_DURATION_SECONDS)
    policy_integer(policy, "maxEndpoints", 1, BASIC_MAX_ENDPOINTS)
    if policy_integer(policy, "maxConcurrentRequests", 1, 1) != 1:
        raise RuntimeError("Basic assessment permits one active request thread")


def validate_resilience_policy(policy: dict[str, Any]) -> None:
    if policy.get("activeScan") is not False or policy.get("resilienceObservation") is not True:
        raise RuntimeError("Safe resilience requires its dedicated non-exploit policy")
    if policy.get("allowedMethods") != ["GET"]:
        raise RuntimeError("Safe resilience permits GET requests only")
    if policy.get("stagingOrMaintenanceConfirmed") is not True:
        raise RuntimeError("Safe resilience requires staging or an approved maintenance window")
    policy_integer(policy, "maxRequests", 2, RESILIENCE_MAX_REQUESTS)
    policy_integer(policy, "maxDurationSeconds", 5, RESILIENCE_MAX_DURATION_SECONDS)
    policy_integer(policy, "intervalMilliseconds", RESILIENCE_MIN_INTERVAL_MILLISECONDS, 2_000)
    if policy_integer(policy, "maxConcurrentRequests", 1, 1) != 1:
        raise RuntimeError("Safe resilience permits one request thread")


def validate_api_policy(policy: dict[str, Any], origin: str) -> None:
    if policy.get("activeScan") is not False or policy.get("apiDiscovery") is not True:
        raise RuntimeError("API surface review requires its dedicated passive policy")
    if policy.get("allowedMethods") != ["GET"]:
        raise RuntimeError("API surface review permits GET requests only")
    if policy.get("resolveExternalReferences") is not False:
        raise RuntimeError("API surface review cannot resolve external references")
    document_url = str(policy.get("openApiUrl") or "")
    if document_url:
        if policy.get("maxRequests") != 1:
            raise RuntimeError("API inventory permits one OpenAPI document GET only")
        policy_integer(policy, "maxDocumentBytes", 1, API_MAX_DOCUMENT_BYTES)
        policy_integer(policy, "maxEndpoints", 1, API_MAX_ENDPOINTS)
        if not same_origin(document_url, origin):
            raise RuntimeError("OpenAPI document left the verified origin")
        parsed = urllib.parse.urlsplit(document_url)
        if parsed.scheme != "https" or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path in ("", "/"):
            raise RuntimeError("OpenAPI document URL violates the passive inventory boundary")
        return
    if policy.get("apiSurfaceDiscovery") is not True:
        raise RuntimeError("Specification-free API review requires an explicit discovery policy")
    policy_integer(policy, "maxRequests", 1, API_SURFACE_MAX_REQUESTS)
    policy_integer(policy, "maxAssetBytes", 1, API_SURFACE_MAX_ASSET_BYTES)
    policy_integer(policy, "maxTotalBytes", 1, API_SURFACE_MAX_TOTAL_BYTES)
    policy_integer(policy, "maxEndpoints", 1, API_SURFACE_MAX_ENDPOINTS)


def assert_public_dns(hostname: str) -> None:
    try:
        answers = socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)
    except socket.gaierror as error:
        raise RuntimeError("Target DNS resolution failed") from error
    addresses = {answer[4][0] for answer in answers}
    if not addresses:
        raise RuntimeError("Target DNS returned no addresses")
    for address in addresses:
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError as error:
            raise RuntimeError("Target DNS returned an invalid address") from error
        if not parsed.is_global:
            raise RuntimeError("Target resolves to a private or reserved address")


def same_origin(value: str, origin: str) -> bool:
    try:
        parsed = urllib.parse.urlsplit(value)
        expected = urllib.parse.urlsplit(origin)
        return (parsed.scheme.lower(), parsed.hostname.lower() if parsed.hostname else "", parsed.port) == (
            expected.scheme.lower(), expected.hostname.lower() if expected.hostname else "", expected.port
        )
    except (ValueError, AttributeError):
        return False


def basic_active_targets(urls: list[str], origin: str, maximum: int) -> list[str]:
    targets: list[str] = []
    for value in urls:
        if not same_origin(value, origin):
            continue
        try:
            parsed = urllib.parse.urlsplit(value)
        except ValueError:
            continue
        if not urllib.parse.parse_qsl(parsed.query, keep_blank_values=True):
            continue
        normalized = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))
        if normalized not in targets:
            targets.append(normalized)
        if len(targets) >= maximum:
            break
    return targets


def zap_message_count(config: Config) -> int:
    payload = zap(config, "core/view/numberOfMessages")
    return max(0, int(payload.get("numberOfMessages", 0)))


def stop_active_scan(config: Config, scan_id: str | None) -> None:
    if not scan_id:
        return
    try:
        zap(config, "ascan/action/stop", {"scanId": scan_id})
    except Exception:
        pass


def basic_control_check(config: Config, job: dict[str, Any], scan_id: str | None) -> None:
    if shutdown_requested:
        stop_active_scan(config, scan_id)
        raise ShutdownRequestedError("Worker is shutting down")
    response = control(
        config,
        "GET",
        f"/api/internal/jobs/{job['id']}/control?workerId={urllib.parse.quote(config.worker_id)}",
    )
    if response and response.get("stopRequested"):
        stop_active_scan(config, scan_id)
        raise StopRequestedError("Operator requested a safe stop")


class ScopedRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, origin: str) -> None:
        self.origin = origin
        super().__init__()

    def redirect_request(
        self,
        request: urllib.request.Request,
        fp: Any,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> urllib.request.Request | None:
        if not same_origin(new_url, self.origin):
            raise RuntimeError("Safe resilience redirect left the verified origin")
        return super().redirect_request(request, fp, code, message, headers, new_url)


def scoped_get(endpoint: str, origin: str, timeout: float = 8) -> dict[str, Any]:
    if not same_origin(endpoint, origin):
        raise RuntimeError("Safe resilience endpoint left the verified origin")
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        ScopedRedirectHandler(origin),
    )
    request = urllib.request.Request(
        endpoint,
        method="GET",
        headers={
            "user-agent": "AegisScope-Resilience/0.1",
            "cache-control": "no-cache",
            "accept": "text/html,application/json;q=0.9,*/*;q=0.1",
        },
    )
    started = time.monotonic()
    try:
        with opener.open(request, timeout=timeout) as response:
            response.read(1024)
            status = response.status
            headers = {key.lower(): value for key, value in response.headers.items()}
    except urllib.error.HTTPError as error:
        error.read(1024)
        status = error.code
        headers = {key.lower(): value for key, value in error.headers.items()}
    return {
        "status": int(status),
        "latencySeconds": max(0.0, time.monotonic() - started),
        "rateHeaders": {key: value for key, value in headers.items() if key in RATE_LIMIT_HEADERS},
    }


def parse_openapi_inventory(document: Any, origin: str, maximum: int) -> dict[str, Any]:
    if not isinstance(document, dict):
        raise RuntimeError("OpenAPI document must be a JSON object")
    openapi_version = str(document.get("openapi") or "")
    swagger_version = str(document.get("swagger") or "")
    if not (openapi_version.startswith("3.") or swagger_version == "2.0"):
        raise RuntimeError("Document is not OpenAPI 3.x or Swagger 2.0 JSON")
    paths = document.get("paths")
    if not isinstance(paths, dict):
        raise RuntimeError("OpenAPI document does not contain a paths object")

    operations: list[dict[str, str]] = []
    method_counts: dict[str, int] = {}
    truncated = False
    for raw_path, path_item in paths.items():
        if not isinstance(raw_path, str) or not raw_path.startswith("/") or not isinstance(path_item, dict):
            continue
        endpoint = urllib.parse.urljoin(f"{origin}/", raw_path.lstrip("/"))
        if not same_origin(endpoint, origin):
            continue
        for raw_method, operation in path_item.items():
            method = str(raw_method).lower()
            if method not in OPENAPI_OPERATION_METHODS or not isinstance(operation, dict):
                continue
            if len(operations) >= maximum:
                truncated = True
                break
            upper_method = method.upper()
            operations.append({
                "method": upper_method,
                "path": raw_path,
                "endpoint": endpoint,
                "operationId": truncate(str(operation.get("operationId") or ""), 240),
            })
            method_counts[upper_method] = method_counts.get(upper_method, 0) + 1
        if truncated:
            break
    return {
        "version": openapi_version or swagger_version,
        "title": truncate(str((document.get("info") or {}).get("title") or "Unnamed API"), 240) if isinstance(document.get("info"), dict) else "Unnamed API",
        "operations": operations,
        "methodCounts": method_counts,
        "truncated": truncated,
    }


def openapi_inventory_finding(document_url: str, inventory: dict[str, Any], maximum: int) -> dict[str, Any]:
    operations = inventory["operations"]
    method_summary = ", ".join(f"{method} {count}" for method, count in sorted(inventory["methodCounts"].items())) or "none"
    evidence = (
        f"Read one same-origin OpenAPI JSON document. API: {inventory['title']}; "
        f"specification: {inventory['version']}; operations: {len(operations)}/{maximum}; "
        f"methods: {method_summary}; external references: not resolved; documented operations: not invoked."
    )
    if inventory["truncated"]:
        evidence += " Inventory stopped at the operation safety ceiling."
    return {
        "fingerprint": hashlib.sha256(f"openapi-inventory|{document_url}".encode()).hexdigest(),
        "pluginId": "aegis-openapi-inventory-v1",
        "title": "OpenAPI inventory discovered",
        "severity": "Info",
        "confidence": "High",
        "endpoint": document_url,
        "observationCount": max(1, len(operations)),
        "affectedEndpoints": [f"{item['method']} {item['endpoint']}" for item in operations],
        "parameter": "",
        "category": "API inventory",
        "cwe": None,
        "evidence": truncate(evidence, 8000),
        "impact": "This is a passive API inventory, not a confirmed vulnerability. It establishes the reviewed operation scope for later authorized API security tests.",
        "remediation": [
            "Remove obsolete operations from the published specification and deployment.",
            "Require explicit authorization before enabling authenticated or active tests for any inventoried operation.",
            "Keep the specification free of embedded credentials and sensitive examples.",
        ],
    }


def run_openapi_inventory(config: Config, job: dict[str, Any], origin: str) -> dict[str, Any]:
    policy = job["policy"]
    maximum_bytes = policy_integer(policy, "maxDocumentBytes", 1, API_MAX_DOCUMENT_BYTES)
    maximum_endpoints = policy_integer(policy, "maxEndpoints", 1, API_MAX_ENDPOINTS)
    document_url = str(policy.get("openApiUrl") or "")
    if not same_origin(document_url, origin):
        raise RuntimeError("OpenAPI document left the verified origin")
    hostname = str((job.get("target") or {}).get("hostname") or "").lower().rstrip(".")
    basic_control_check(config, job, None)
    if hostname:
        assert_public_dns(hostname)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), ScopedRedirectHandler(origin))
    request = urllib.request.Request(
        document_url,
        method="GET",
        headers={"user-agent": "AegisScope-OpenAPI-Inventory/0.1", "accept": "application/json"},
    )
    try:
        with opener.open(request, timeout=15) as response:
            raw = response.read(maximum_bytes + 1)
    except urllib.error.HTTPError as error:
        raise RuntimeError(f"OpenAPI document returned HTTP {error.code}") from error
    if len(raw) > maximum_bytes:
        raise RuntimeError("OpenAPI document exceeded the size safety ceiling")
    try:
        document = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise RuntimeError("OpenAPI document is not valid JSON") from error
    inventory = parse_openapi_inventory(document, origin, maximum_endpoints)
    inventory["finding"] = openapi_inventory_finding(document_url, inventory, maximum_endpoints)
    return inventory


def first_party_script_urls(html: str, origin: str, maximum: int) -> list[str]:
    if maximum <= 0:
        return []
    urls: list[str] = []
    for raw_source in SCRIPT_SOURCE_PATTERN.findall(html):
        candidate = urllib.parse.urljoin(f"{origin}/", raw_source.strip())
        if not same_origin(candidate, origin):
            continue
        try:
            parsed = urllib.parse.urlsplit(candidate)
        except ValueError:
            continue
        if parsed.username or parsed.password or parsed.fragment:
            continue
        normalized = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))
        if normalized not in urls:
            urls.append(normalized)
        if len(urls) >= maximum:
            break
    return urls


def discover_api_references(documents: list[str], origin: str, maximum: int) -> dict[str, Any]:
    endpoints: list[str] = []
    sensitive: list[str] = []
    for document in documents:
        for raw_path in API_PATH_PATTERN.findall(document):
            path = raw_path.replace("\\/", "/")
            try:
                parsed_path = urllib.parse.urlsplit(path)
            except ValueError:
                continue
            normalized_path = parsed_path.path or "/"
            if len(normalized_path) > 500 or normalized_path.lower().endswith((".css", ".gif", ".ico", ".jpg", ".jpeg", ".js", ".png", ".svg", ".webp")):
                continue
            endpoint = urllib.parse.urljoin(f"{origin}/", normalized_path.lstrip("/"))
            if not same_origin(endpoint, origin) or endpoint in endpoints:
                continue
            endpoints.append(endpoint)
            terms = {part.lower() for part in re.split(r"[^A-Za-z0-9]+", normalized_path) if part}
            if terms.intersection(SENSITIVE_API_TERMS):
                sensitive.append(endpoint)
            if len(endpoints) >= maximum:
                return {"endpoints": endpoints, "sensitiveEndpoints": sensitive, "truncated": True}
    return {"endpoints": endpoints, "sensitiveEndpoints": sensitive, "truncated": False}


def bounded_surface_get(endpoint: str, origin: str, maximum_bytes: int, total_remaining: int) -> dict[str, Any]:
    if not same_origin(endpoint, origin):
        raise RuntimeError("API discovery asset left the verified origin")
    read_limit = min(maximum_bytes, total_remaining)
    if read_limit < 1:
        raise RuntimeError("API discovery reached its total byte ceiling")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), ScopedRedirectHandler(origin))
    request = urllib.request.Request(
        endpoint,
        method="GET",
        headers={
            "user-agent": "AegisScope-API-Surface/0.1",
            "accept": "text/html,application/javascript,text/javascript;q=0.9,*/*;q=0.1",
        },
    )
    try:
        with opener.open(request, timeout=15) as response:
            content_length = response.headers.get("content-length")
            if content_length:
                try:
                    if int(content_length) > read_limit:
                        raise RuntimeError("API discovery asset exceeded its byte ceiling")
                except ValueError:
                    pass
            raw = response.read(read_limit + 1)
            content_type = str(response.headers.get("content-type") or "").lower()
    except urllib.error.HTTPError as error:
        raise RuntimeError(f"API discovery asset returned HTTP {error.code}") from error
    if len(raw) > read_limit:
        raise RuntimeError("API discovery asset exceeded its byte ceiling")
    return {
        "text": raw.decode("utf-8", errors="replace"),
        "bytes": len(raw),
        "contentType": content_type,
    }


def api_surface_finding(origin: str, discovery: dict[str, Any], maximum: int) -> dict[str, Any]:
    endpoints = discovery["endpoints"]
    sensitive = discovery["sensitiveEndpoints"]
    title = "First-party API references discovered" if endpoints else "No API references found in bounded public assets"
    evidence = (
        f"Reviewed {discovery['requestsSent']} same-origin public documents ({discovery['bytesRead']} bytes); "
        f"API references: {len(endpoints)}/{maximum}; sensitive-name review signals: {len(sensitive)}; "
        "authentication credentials: not supplied; discovered operations: not invoked."
    )
    if discovery["truncated"]:
        evidence += " Discovery stopped at a configured request, byte or endpoint ceiling."
    return {
        "fingerprint": hashlib.sha256(f"api-surface-discovery-v1|{origin}".encode()).hexdigest(),
        "pluginId": "aegis-api-surface-discovery-v1",
        "title": title,
        "severity": "Info",
        "confidence": "Medium",
        "endpoint": origin,
        "observationCount": max(1, len(endpoints)),
        "affectedEndpoints": endpoints or [origin],
        "parameter": "",
        "category": "API inventory",
        "cwe": None,
        "evidence": truncate(evidence, 8000),
        "impact": "This is passive attack-surface evidence, not a confirmed vulnerability. Public client code may reveal routes worth reviewing, but it does not prove that a route exists, is reachable or lacks authorization.",
        "remediation": [
            "Maintain an OpenAPI document so intended operations, authentication and schemas can be reviewed accurately.",
            "Confirm every sensitive route enforces server-side authentication and object-level authorization.",
            "Remove obsolete endpoint references and sensitive implementation details from production client bundles.",
        ],
    }


def run_api_surface_discovery(config: Config, job: dict[str, Any], origin: str) -> dict[str, Any]:
    policy = job["policy"]
    maximum_requests = policy_integer(policy, "maxRequests", 1, API_SURFACE_MAX_REQUESTS)
    maximum_asset_bytes = policy_integer(policy, "maxAssetBytes", 1, API_SURFACE_MAX_ASSET_BYTES)
    maximum_total_bytes = policy_integer(policy, "maxTotalBytes", 1, API_SURFACE_MAX_TOTAL_BYTES)
    maximum_endpoints = policy_integer(policy, "maxEndpoints", 1, API_SURFACE_MAX_ENDPOINTS)
    hostname = str((job.get("target") or {}).get("hostname") or "").lower().rstrip(".")
    documents: list[str] = []
    requests_sent = 0
    bytes_read = 0

    basic_control_check(config, job, None)
    if hostname:
        assert_public_dns(hostname)
    homepage = bounded_surface_get(origin, origin, maximum_asset_bytes, maximum_total_bytes)
    requests_sent += 1
    bytes_read += homepage["bytes"]
    documents.append(homepage["text"])

    script_urls = first_party_script_urls(homepage["text"], origin, max(0, maximum_requests - 1))
    truncated = len(SCRIPT_SOURCE_PATTERN.findall(homepage["text"])) > len(script_urls)
    for script_url in script_urls:
        if requests_sent >= maximum_requests or bytes_read >= maximum_total_bytes:
            truncated = True
            break
        basic_control_check(config, job, None)
        if hostname:
            assert_public_dns(hostname)
        asset = bounded_surface_get(script_url, origin, maximum_asset_bytes, maximum_total_bytes - bytes_read)
        requests_sent += 1
        bytes_read += asset["bytes"]
        documents.append(asset["text"])
        progress(
            config,
            str(job.get("id") or ""),
            "Reviewing first-party API references",
            min(80, 20 + round(60 * requests_sent / maximum_requests)),
            requestsSent=requests_sent,
        )

    discovery = discover_api_references(documents, origin, maximum_endpoints)
    discovery.update({
        "requestsSent": requests_sent,
        "bytesRead": bytes_read,
        "assetsReviewed": len(documents),
        "truncated": truncated or discovery["truncated"],
    })
    discovery["finding"] = api_surface_finding(origin, discovery, maximum_endpoints)
    return discovery


def resilience_finding(origin: str, observation: dict[str, Any]) -> dict[str, Any]:
    statuses = observation["statuses"]
    rate_headers = observation["rateHeaders"]
    observed = observation["observed"]
    stopped_reason = observation["stoppedReason"]
    status_counts = {str(status): statuses.count(status) for status in sorted(set(statuses))}
    maximum_latency_ms = round(max(observation["latenciesSeconds"] or [0]) * 1000)
    if observed:
        title = "Rate limiting observed during safe sample"
        confidence = "High"
        impact = "The sampled endpoint returned an explicit throttling signal before the safety ceiling. This is a positive control observation, not a vulnerability."
        remediation = [
            "Document the observed threshold and confirm sensitive endpoints use equivalent or stricter server-side controls.",
            "Keep denial-of-service and capacity testing in a separately approved staging exercise.",
        ]
    elif stopped_reason:
        title = "Safe resilience observation stopped by health guard"
        confidence = "High"
        impact = "The observer stopped early because the target became slow, returned a server error, redirected out of scope or became unreachable. No load test was attempted."
        remediation = [
            "Review service health and logs for the observation window before any retest.",
            "Retest only in staging or an approved maintenance window.",
        ]
    else:
        title = "Rate limiting not observed within safe sample"
        confidence = "Medium"
        impact = "No explicit throttling signal appeared during this small sequential sample. This does not prove rate limiting is absent and is not a capacity or denial-of-service test."
        remediation = [
            "Apply server-side limits to sensitive unauthenticated endpoints and return 429 with a Retry-After or RateLimit header.",
            "Validate endpoint-specific thresholds in staging; do not increase production traffic to force a failure.",
        ]
    evidence = (
        f"Sequential GET sample {observation['requestsSent']}/{observation['requestBudget']}; "
        f"interval {observation['intervalMilliseconds']} ms; statuses {json.dumps(status_counts, sort_keys=True)}; "
        f"maximum latency {maximum_latency_ms} ms; rate-limit headers "
        f"{json.dumps(rate_headers, sort_keys=True) if rate_headers else 'none'}; "
        f"health stop {stopped_reason or 'none'}."
    )
    return {
        "fingerprint": hashlib.sha256(f"aegis-rate-limit-v1|{origin}".encode()).hexdigest(),
        "pluginId": "aegis-rate-limit-observer-v1",
        "title": title,
        "severity": "Info",
        "confidence": confidence,
        "endpoint": origin,
        "observationCount": 1,
        "affectedEndpoints": [origin],
        "parameter": "",
        "category": "Resilience",
        "cwe": None,
        "evidence": evidence,
        "impact": impact,
        "remediation": remediation,
    }


def run_resilience_observation(
    config: Config,
    job: dict[str, Any],
    origin: str,
    endpoint: str | None = None,
) -> dict[str, Any]:
    policy = job["policy"]
    request_budget = policy_integer(policy, "maxRequests", 2, RESILIENCE_MAX_REQUESTS)
    duration_seconds = policy_integer(policy, "maxDurationSeconds", 5, RESILIENCE_MAX_DURATION_SECONDS)
    interval_milliseconds = policy_integer(
        policy,
        "intervalMilliseconds",
        RESILIENCE_MIN_INTERVAL_MILLISECONDS,
        2_000,
    )
    target = endpoint or f"{origin}/"
    if not same_origin(target, origin):
        raise RuntimeError("Safe resilience endpoint left the verified origin")
    samples: list[dict[str, Any]] = []
    rate_headers: dict[str, str] = {}
    observed = False
    stopped_reason: str | None = None
    started = time.monotonic()
    baseline_latency = 0.0
    hostname = str((job.get("target") or {}).get("hostname") or "").lower().rstrip(".")
    for index in range(request_budget):
        basic_control_check(config, job, None)
        if time.monotonic() - started >= duration_seconds:
            stopped_reason = "time ceiling"
            break
        if index:
            sleep_interruptibly(interval_milliseconds / 1000)
        if time.monotonic() - started >= duration_seconds:
            stopped_reason = "time ceiling"
            break
        if hostname:
            assert_public_dns(hostname)
        try:
            sample = scoped_get(target, origin)
        except Exception as error:
            stopped_reason = f"request failure: {type(error).__name__}"
            break
        samples.append(sample)
        if index == 0:
            baseline_latency = sample["latencySeconds"]
            if baseline_latency > 2.5:
                stopped_reason = "slow baseline"
        rate_headers.update(sample["rateHeaders"])
        if sample["status"] == 429 or sample["rateHeaders"]:
            observed = True
        elif sample["status"] >= 500:
            stopped_reason = f"server status {sample['status']}"
        elif index and sample["latencySeconds"] > max(5.0, baseline_latency * 3):
            stopped_reason = "latency guard"
        progress(
            config,
            current_job_id or job["id"],
            "Safe rate-limit observation",
            min(95, 10 + round((len(samples) / request_budget) * 85)),
            endpointsDiscovered=1,
            requestsSent=len(samples),
        )
        if observed or stopped_reason:
            break
    observation = {
        "observed": observed,
        "requestsSent": len(samples),
        "requestBudget": request_budget,
        "intervalMilliseconds": interval_milliseconds,
        "statuses": [sample["status"] for sample in samples],
        "latenciesSeconds": [sample["latencySeconds"] for sample in samples],
        "rateHeaders": rate_headers,
        "stoppedReason": stopped_reason,
        "truncated": bool(stopped_reason),
    }
    observation["finding"] = resilience_finding(origin, observation)
    return observation


def run_basic_active_scan(
    config: Config,
    job: dict[str, Any],
    origin: str,
    discovered_urls: list[str],
    endpoint_count: int,
) -> tuple[int, bool]:
    policy = job["policy"]
    maximum_endpoints = policy_integer(policy, "maxEndpoints", 1, BASIC_MAX_ENDPOINTS)
    targets = basic_active_targets(discovered_urls, origin, maximum_endpoints)
    if not targets:
        progress(config, current_job_id or job["id"], "No GET query parameters found; active checks skipped", 94,
                 endpointsDiscovered=endpoint_count, requestsSent=endpoint_count)
        return 0, False

    rule_ids = sorted({str(value) for value in policy["allowedActiveRuleIds"]})
    duration_seconds = policy_integer(policy, "maxDurationSeconds", 60, BASIC_MAX_DURATION_SECONDS)
    request_budget = policy_integer(policy, "maxRequests", 1, BASIC_MAX_REQUESTS)
    scan_policy_name = f"aegis-basic-{job['id']}"
    zap(config, "ascan/action/addScanPolicy", {
        "scanPolicyName": scan_policy_name,
        "alertThreshold": "MEDIUM",
        "attackStrength": "LOW",
    })
    zap(config, "ascan/action/disableAllScanners", {"scanPolicyName": scan_policy_name})
    zap(config, "ascan/action/enableScanners", {
        "ids": ",".join(rule_ids),
        "scanPolicyName": scan_policy_name,
    })
    zap(config, "ascan/action/setOptionThreadPerHost", {"Integer": "1"})
    zap(config, "ascan/action/setOptionMaxScanDurationInMins", {
        "Integer": str(max(1, math.ceil(duration_seconds / 60))),
    })
    zap(config, "ascan/action/setOptionMaxRuleDurationInMins", {
        "Integer": str(max(1, math.ceil(duration_seconds / 60))),
    })

    baseline_messages = zap_message_count(config)
    deadline = time.monotonic() + duration_seconds
    truncated = False
    for index, target in enumerate(targets):
        basic_control_check(config, job, None)
        if time.monotonic() >= deadline or zap_message_count(config) - baseline_messages >= request_budget:
            truncated = True
            break
        started = zap(config, "ascan/action/scan", {
            "url": target,
            "recurse": "false",
            "inScopeOnly": "true",
            "scanPolicyName": scan_policy_name,
            "method": "GET",
        })
        active_scan_id = str(started.get("scan", ""))
        if not active_scan_id:
            raise RuntimeError("ZAP did not return an active scan id")
        active_scan_completed = False
        try:
            while True:
                basic_control_check(config, job, active_scan_id)
                used = zap_message_count(config) - baseline_messages
                if time.monotonic() >= deadline or used >= request_budget:
                    truncated = True
                    break
                status = zap(config, "ascan/view/status", {"scanId": active_scan_id})
                percent = max(0, min(100, int(float(status.get("status", 0)))))
                overall = 70 + round(((index + percent / 100) / len(targets)) * 23)
                progress(config, current_job_id or job["id"], "Bounded SQLi and XSS validation", min(93, overall),
                         endpointsDiscovered=endpoint_count, requestsSent=endpoint_count + used)
                if percent >= 100:
                    active_scan_completed = True
                    break
                sleep_interruptibly(1.5)
        finally:
            if not active_scan_completed:
                stop_active_scan(config, active_scan_id)
        if truncated:
            break
    active_requests = max(0, zap_message_count(config) - baseline_messages)
    return min(active_requests, request_budget), truncated


def runtime_check(config: Config, job: dict[str, Any], spider_id: str, started_at: float) -> None:
    if shutdown_requested:
        try:
            zap(config, "spider/action/stop", {"scanId": spider_id})
        except Exception:
            pass
        raise ShutdownRequestedError("Worker is shutting down")
    if time.monotonic() - started_at > config.max_scan_seconds:
        try:
            zap(config, "spider/action/stop", {"scanId": spider_id})
        except Exception:
            pass
        raise RuntimeError("Maximum assessment duration exceeded")
    response = control(
        config,
        "GET",
        f"/api/internal/jobs/{job['id']}/control?workerId={urllib.parse.quote(config.worker_id)}",
    )
    if response and response.get("stopRequested"):
        raise StopRequestedError("Operator requested a safe stop")


def normalize_risk(value: Any) -> str:
    risk = str(value or "").lower()
    if risk in ("critical", "high"):
        return "High"
    if risk == "medium":
        return "Medium"
    if risk in ("info", "informational"):
        return "Info"
    return "Low"


def normalize_confidence(value: Any) -> str:
    confidence = str(value or "").lower()
    if confidence == "confirmed":
        return "Confirmed"
    if confidence == "high":
        return "High"
    return "Medium"


def truncate(value: str, length: int) -> str:
    return value if len(value) <= length else f"{value[:length - 1]}…"


def is_html_document(endpoint: str) -> bool:
    try:
        path = urllib.parse.urlsplit(endpoint).path.lower()
    except ValueError:
        return True
    if path == "/" or path.endswith("/"):
        return True
    leaf = path.rsplit("/", 1)[-1]
    return "." not in leaf or leaf.endswith((".html", ".htm"))


def is_applicable_alert(alert: dict[str, Any]) -> bool:
    title = str(alert.get("alert") or "").lower()
    document_only = any(marker in title for marker in (
        "anti-clickjacking",
        "x-frame-options",
        "content security policy",
        "sub resource integrity",
    )) or title.startswith("csp:")
    return not document_only or is_html_document(str(alert.get("url") or ""))


def normalize_alert(alert: dict[str, Any]) -> dict[str, Any]:
    title = str(alert.get("alert") or "Security finding")
    endpoint = str(alert.get("url") or "")
    parameter = str(alert.get("param") or "")
    cwe_raw = str(alert.get("cweid") or "")
    cwe = f"CWE-{cwe_raw}" if cwe_raw not in ("", "0", "-1") else None
    plugin_id = str(alert.get("pluginId") or alert.get("alertRef") or "")
    fingerprint = hashlib.sha256("|".join((plugin_id, title.lower().strip(), parameter.lower().strip(), cwe or "")).encode()).hexdigest()
    solution = [item.strip() for item in re.split(r"\r?\n+", str(alert.get("solution") or "")) if item.strip()]
    return {
        "fingerprint": fingerprint,
        "pluginId": plugin_id or None,
        "title": title,
        "severity": normalize_risk(alert.get("risk")),
        "confidence": normalize_confidence(alert.get("confidence")),
        "endpoint": endpoint,
        "observationCount": 1,
        "affectedEndpoints": [endpoint],
        "parameter": parameter,
        "category": "Web application",
        "cwe": cwe,
        "evidence": truncate(str(alert.get("evidence") or alert.get("other") or alert.get("description") or "ZAP passive scan evidence"), 8000),
        "impact": truncate(str(alert.get("description") or "The application exposes a security weakness that requires review."), 2000),
        "remediation": (solution or ["Review the affected response and apply the vendor-recommended security control."])[:12],
    }


def normalize_alerts(alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    severity_order = {"Info": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
    confidence_order = {"Medium": 1, "High": 2, "Confirmed": 3}
    groups: dict[str, dict[str, Any]] = {}
    for alert in alerts:
        if not is_applicable_alert(alert):
            continue
        finding = normalize_alert(alert)
        existing = groups.get(finding["fingerprint"])
        if existing is None:
            groups[finding["fingerprint"]] = finding
            continue
        existing["affectedEndpoints"] = list(dict.fromkeys(existing["affectedEndpoints"] + finding["affectedEndpoints"]))
        existing["observationCount"] = len(existing["affectedEndpoints"])
        if severity_order[finding["severity"]] > severity_order[existing["severity"]]:
            existing["severity"] = finding["severity"]
        if confidence_order[finding["confidence"]] > confidence_order[existing["confidence"]]:
            existing["confidence"] = finding["confidence"]
    return list(groups.values())


def run_job(config: Config, job: dict[str, Any]) -> None:
    global current_job_id
    current_job_id = str(job.get("id") or "")
    started_at = time.monotonic()
    spider_id: str | None = None
    endpoint_count = 0
    discovered_urls: list[str] = []
    active_requests = 0
    active_truncated = False
    try:
        origin, _hostname = enforce_policy(job)
        if job.get("mode") == "resilience":
            progress(config, current_job_id, "Preparing safe rate-limit observation", 5)
            observation = run_resilience_observation(config, job, origin)
            complete(
                config,
                current_job_id,
                {
                    "status": "completed",
                    "findings": [observation["finding"]],
                    "stats": {
                        "endpointsDiscovered": 1,
                        "requestsSent": observation["requestsSent"],
                        "candidatesFound": 1,
                        "activeRequests": observation["requestsSent"],
                        "activeTruncated": observation["truncated"],
                    },
                },
            )
            log(
                "resilience_job_completed",
                jobId=current_job_id,
                requests=observation["requestsSent"],
                rateLimitObserved=observation["observed"],
                stoppedReason=observation["stoppedReason"],
            )
            return
        if job.get("mode") == "api":
            has_openapi_document = bool((job.get("policy") or {}).get("openApiUrl"))
            progress(
                config,
                current_job_id,
                "Reading bounded OpenAPI document" if has_openapi_document else "Reviewing public first-party API surface",
                15,
            )
            inventory = run_openapi_inventory(config, job, origin) if has_openapi_document else run_api_surface_discovery(config, job, origin)
            operation_count = len(inventory.get("operations") or inventory.get("endpoints") or [])
            requests_sent = 1 if has_openapi_document else int(inventory["requestsSent"])
            progress(
                config,
                current_job_id,
                "Normalizing API surface inventory",
                85,
                endpointsDiscovered=operation_count,
                requestsSent=requests_sent,
            )
            complete(
                config,
                current_job_id,
                {
                    "status": "completed",
                    "findings": [inventory["finding"]],
                    "stats": {
                        "endpointsDiscovered": operation_count,
                        "requestsSent": requests_sent,
                        "candidatesFound": 1,
                        "activeRequests": 0,
                        "activeTruncated": inventory["truncated"],
                    },
                },
            )
            log(
                "api_surface_review_completed",
                jobId=current_job_id,
                operations=operation_count,
                documentRequests=requests_sent,
                source="openapi" if has_openapi_document else "first_party_assets",
                truncated=inventory["truncated"],
            )
            return
        progress(config, current_job_id, "Preparing isolated crawler", 4)
        zap(config, "core/action/newSession", {"name": "", "overwrite": "true"})
        context_name = f"aegis-{current_job_id}"
        zap(config, "context/action/newContext", {"contextName": context_name})
        zap(
            config,
            "context/action/includeInContext",
            {"contextName": context_name, "regex": f"^{re.escape(origin)}(?:/.*)?$"},
        )
        progress(config, current_job_id, "Crawling verified scope", 10)
        spider = zap(
            config,
            "spider/action/scan",
            {
                "url": origin,
                "maxChildren": "1000",
                "recurse": "true",
                "contextName": context_name,
                "subtreeOnly": "true",
            },
        )
        spider_id = str(spider.get("scan", ""))
        if not spider_id:
            raise RuntimeError("ZAP did not return a spider scan id")

        while True:
            runtime_check(config, job, spider_id, started_at)
            status = zap(config, "spider/view/status", {"scanId": spider_id})
            percent = max(0, min(100, int(float(status.get("status", 0)))))
            results = zap(config, "spider/view/results", {"scanId": spider_id, "start": "0", "count": "10000"})
            discovered_urls = list(dict.fromkeys(
                str(url) for url in results.get("results", []) if same_origin(str(url), origin)
            ))
            endpoint_count = len(discovered_urls)
            progress(
                config,
                current_job_id,
                "Crawling verified scope",
                10 + round(percent * 0.5),
                endpointsDiscovered=endpoint_count,
                requestsSent=endpoint_count,
            )
            if percent >= 100:
                break
            sleep_interruptibly(2.5)

        progress(config, current_job_id, "Completing passive analysis", 65, endpointsDiscovered=endpoint_count)
        while True:
            runtime_check(config, job, spider_id, started_at)
            queue = zap(config, "pscan/view/recordsToScan")
            remaining = max(0, int(queue.get("recordsToScan", 0)))
            passive_progress = min(94, 65 + max(0, 29 - (remaining + 9) // 10))
            progress(
                config,
                current_job_id,
                "Completing passive analysis",
                passive_progress,
                endpointsDiscovered=endpoint_count,
                requestsSent=endpoint_count,
            )
            if remaining <= 0:
                break
            sleep_interruptibly(2.5)

        if job.get("mode") == "basic":
            progress(config, current_job_id, "Preparing bounded active validation", 68,
                     endpointsDiscovered=endpoint_count, requestsSent=endpoint_count)
            active_requests, active_truncated = run_basic_active_scan(
                config, job, origin, discovered_urls, endpoint_count,
            )

        result = zap(config, "core/view/alerts", {"baseurl": origin, "start": "0", "count": "5000"})
        scoped_alerts = [alert for alert in result.get("alerts", []) if same_origin(str(alert.get("url", "")), origin)]
        findings = normalize_alerts(scoped_alerts)
        complete(
            config,
            current_job_id,
            {
                "status": "completed",
                "findings": findings,
                "stats": {
                    "endpointsDiscovered": endpoint_count,
                    "requestsSent": endpoint_count + active_requests,
                    "candidatesFound": len(scoped_alerts),
                    "activeRequests": active_requests,
                    "activeTruncated": active_truncated,
                },
            },
        )
        log("job_completed", jobId=current_job_id, findings=len(findings), activeRequests=active_requests,
            activeTruncated=active_truncated)
    except (StopRequestedError, ShutdownRequestedError) as error:
        if spider_id:
            try:
                zap(config, "spider/action/stop", {"scanId": spider_id})
            except Exception:
                pass
        try:
            complete(config, current_job_id, {"status": "stopped", "error": str(error), "stats": {"endpointsDiscovered": endpoint_count}})
        except Exception as callback_error:
            log("completion_callback_failed", jobId=current_job_id, message=str(callback_error))
    except Exception as error:
        if spider_id:
            try:
                zap(config, "spider/action/stop", {"scanId": spider_id})
            except Exception:
                pass
        try:
            complete(config, current_job_id, {"status": "failed", "error": str(error), "stats": {"endpointsDiscovered": endpoint_count}})
        except Exception as callback_error:
            log("completion_callback_failed", jobId=current_job_id, message=str(callback_error))
        log("job_failed", jobId=current_job_id, message=str(error))
    finally:
        current_job_id = None


def shutdown_zap(config: Config) -> None:
    if zap_process is None or zap_process.poll() is not None:
        return
    try:
        zap(config, "core/action/shutdown")
        zap_process.wait(timeout=10)
    except Exception:
        zap_process.terminate()
        try:
            zap_process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            zap_process.kill()


def main() -> int:
    global zap_process
    config = load_config()
    signal.signal(signal.SIGTERM, on_shutdown)
    signal.signal(signal.SIGINT, on_shutdown)
    log("worker_starting", workerId=config.worker_id)
    zap_process = start_zap(config)
    try:
        wait_for_zap(config)
        log("worker_started", workerId=config.worker_id)
        while not shutdown_requested:
            try:
                job = claim_job(config)
                if job:
                    run_job(config, job)
                    if config.run_once:
                        break
                elif config.run_once:
                    break
                else:
                    sleep_interruptibly(config.poll_seconds)
            except Exception as error:
                log("worker_loop_error", message=str(error))
                if config.run_once:
                    return 1
                sleep_interruptibly(config.poll_seconds)
        return 0
    finally:
        shutdown_zap(config)
        log("worker_stopped", workerId=config.worker_id)


if __name__ == "__main__":
    raise SystemExit(main())
