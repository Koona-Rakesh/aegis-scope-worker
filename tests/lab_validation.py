#!/usr/bin/env python3
"""Validate bounded Basic and safe resilience engines against the loopback lab."""

from __future__ import annotations

import importlib.util
import json
import pathlib
import re
import sys
import uuid

from lab_fixture import VulnerableLab


WORKER_PATH = pathlib.Path("/opt/aegis/worker.py")
SPEC = importlib.util.spec_from_file_location("aegis_worker", WORKER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"Unable to load worker from {WORKER_PATH}")
worker = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = worker
SPEC.loader.exec_module(worker)


def main() -> int:
    lab = VulnerableLab()
    lab.start()
    config = worker.Config(
        control_plane_url="https://unused.invalid",
        worker_token="validation-only",
        site_dispatch_token="validation-only",
        zap_api_key=uuid.uuid4().hex,
        worker_id="basic-engine-validation",
        zap_url="http://127.0.0.1:8080",
        poll_seconds=1,
        max_scan_seconds=600,
        run_once=True,
    )
    worker.shutdown_requested = False
    worker.current_job_id = "loopback-lab"
    worker.basic_control_check = lambda *_args, **_kwargs: None
    worker.progress = lambda *_args, **_kwargs: None
    worker.zap_process = worker.start_zap(config)
    try:
        worker.wait_for_zap(config)
        worker.zap(config, "core/action/newSession", {"name": "", "overwrite": "true"})
        context_name = "aegis-basic-loopback-validation"
        worker.zap(config, "context/action/newContext", {"contextName": context_name})
        worker.zap(
            config,
            "context/action/includeInContext",
            {"contextName": context_name, "regex": f"^{re.escape(lab.origin)}(?:/.*)?$"},
        )
        targets = [
            f"{lab.origin}/search?q=baseline",
            f"{lab.origin}/product?id=1",
        ]
        for target in targets:
            worker.zap(config, "core/action/accessUrl", {"url": target, "followRedirects": "true"})

        job = {
            "id": "loopback-lab",
            "mode": "basic",
            "policy": {
                "activeScan": True,
                "allowedActiveRuleIds": ["40012", "40018"],
                "allowedMethods": ["GET"],
                "maxRequests": 250,
                "maxDurationSeconds": 600,
                "maxEndpoints": 2,
                "maxConcurrentRequests": 1,
            },
        }
        active_requests, truncated = worker.run_basic_active_scan(
            config,
            job,
            lab.origin,
            targets,
            len(targets),
        )
        response = worker.zap(
            config,
            "core/view/alerts",
            {"baseurl": lab.origin, "start": "0", "count": "5000"},
        )
        observed = {
            str(alert.get("pluginId") or alert.get("alertRef") or "")
            for alert in response.get("alerts", [])
        }
        required = worker.BASIC_ACTIVE_RULE_IDS
        missing = sorted(required - observed)
        if missing:
            raise AssertionError(f"Basic engine did not detect required lab rules: {', '.join(missing)}")
        if active_requests < 1 or active_requests > 250:
            raise AssertionError(f"Active request count {active_requests} violated the validation budget")
        if truncated:
            raise AssertionError("Basic engine exhausted its safety budget in the two-endpoint lab")
        resilience_job = {
            "id": "loopback-resilience-lab",
            "mode": "resilience",
            "policy": {
                "activeScan": False,
                "resilienceObservation": True,
                "allowedMethods": ["GET"],
                "maxRequests": 12,
                "maxDurationSeconds": 30,
                "intervalMilliseconds": 500,
                "maxConcurrentRequests": 1,
                "stagingOrMaintenanceConfirmed": True,
            },
        }
        resilience = worker.run_resilience_observation(
            config,
            resilience_job,
            lab.origin,
            f"{lab.origin}/rate-limit",
        )
        if not resilience["observed"]:
            raise AssertionError("Safe resilience observer did not identify the lab throttle")
        if resilience["requestsSent"] > 12 or resilience["truncated"]:
            raise AssertionError("Safe resilience observer violated its request or health boundary")
        print(json.dumps({
            "status": "passed",
            "scope": "loopback-only",
            "network": "disabled",
            "rules": sorted(required),
            "activeRequests": active_requests,
            "requestBudget": 250,
            "truncated": truncated,
            "rateLimitObserved": resilience["observed"],
            "rateLimitRequests": resilience["requestsSent"],
            "rateLimitRequestBudget": resilience["requestBudget"],
        }, separators=(",", ":")))
        return 0
    finally:
        worker.shutdown_zap(config)
        lab.stop()


if __name__ == "__main__":
    raise SystemExit(main())
