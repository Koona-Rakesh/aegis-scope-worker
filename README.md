# AegisScope scanner worker

Open-source deployment source for the AegisScope scanner worker.

The worker runs the official OWASP ZAP stable image and accepts authorized
Standard passive scans, bounded Basic scans, separate safe resilience and passive OpenAPI inventory
observations from the AegisScope control plane. It enforces one verified HTTPS
origin, blocks private/reserved DNS answers, normalizes findings, renews job
leases through progress callbacks, and handles shutdown signals safely.

## Safety boundary

- Standard mode remains passive-only
- Basic mode permits only release rules 40012 (reflected XSS) and 40018 (SQL injection)
- Basic active checks are limited to discovered GET query parameters
- Basic limits: one thread, 20 endpoints, 250 requests, ten minutes
- POST bodies, cookies, headers, uploads, time-based rules and denial-of-service patterns are excluded
- Safe resilience is a separate mode: 12 sequential GET requests, 500 ms minimum spacing, 30 seconds maximum
- Safe resilience requires an explicit staging-or-maintenance confirmation and aborts on 5xx, slow responses, request failures or out-of-scope redirects
- Pro API inventory fetches one same-origin OpenAPI 3.x or Swagger 2.0 JSON document, caps it at 2 MB and 500 operations, never invokes documented operations and never resolves external references
- Exact verified HTTPS origin and control-plane allowlist required
- Private, reserved, loopback, multicast, and link-local DNS answers rejected
- ZAP API listens on `127.0.0.1` with a generated API key
- One scan at a time per worker instance
- Runtime ceilings, request-budget stops and operator stop polling
- No credentials, tokens, or secrets stored in Git

## Free local development

Install Podman Desktop/Podman Engine (or Docker Engine where its license fits),
copy `.env.example` to `.env`, replace both secrets, and start the worker:

```sh
podman compose up --build -d
```

Configure the AegisScope Site's `SCANNER_CALLBACK_TOKEN` with the exact same
value. The worker uses the existing computer's CPU and memory, so there is no
cloud-worker subscription. It processes jobs only while that computer is on.

Set `RUN_ONCE=true` to claim at most one queued job and then exit. This supports
future event-driven runners without turning the worker into a permanent server.

## Production without a hosting subscription

Run the same Compose service on an existing company server, workstation, NAS,
or VM. There is no paid AegisScope or scanner software dependency, but the
machine, electricity, network, patching, and backups remain operational costs.

GitHub-hosted Actions are the current zero-subscription development runner. The
public repository runs one isolated job at a time on its schedule; an owner-only
dispatch sentinel can start a queued job when free schedules are delayed.

## Basic and resilience engine validation

The `Basic engine validation` workflow starts an intentionally vulnerable
application and ZAP inside the same network-disabled container. The fixture is
bound to loopback only and is never deployed. The build fails unless release
rules 40012 (reflected XSS) and 40018 (SQL injection) are both detected without
exceeding the 250-request Basic safety budget. The same isolated run also fails
unless the safe resilience observer detects an intentional HTTP 429 throttle in
no more than 12 sequential requests.

## Local checks

```sh
python3 -m unittest discover -s tests -v
python3 -m py_compile worker.py
```
