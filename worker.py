#!/usr/bin/env python3
"""AegisScope controlled web security scanner worker.

The worker claims authorized jobs from the AegisScope control plane and drives
the OWASP ZAP daemon bundled in the official stable container image. It only
accepts Standard passive scans and tightly bounded Basic active scans against
one verified HTTPS origin.
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
    if mode not in ("standard", "basic"):
        raise RuntimeError("Worker permits only Standard and Basic assessments")
    if mode == "standard" and policy.get("activeScan") not in (None, False):
        raise RuntimeError("Standard assessments must remain passive")
    if mode == "basic":
        validate_basic_policy(policy)
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
