# AegisScope scanner worker

Open-source deployment source for the Milestone 2 scanner worker.

The worker runs the official OWASP ZAP stable image and accepts only authorized
Standard scans from the AegisScope control plane. It enforces one verified HTTPS
origin, blocks private/reserved DNS answers, performs traditional crawling plus
passive analysis, normalizes findings, renews the job lease through progress
callbacks, and handles Render shutdown signals safely.

## Safety boundary

- Standard passive assessments only; no active scanner actions
- Exact verified HTTPS origin and control-plane allowlist required
- Private, reserved, loopback, multicast, and link-local DNS answers rejected
- ZAP API listens on `127.0.0.1` with a generated API key
- One scan at a time per worker instance
- One-hour runtime ceiling and safe operator stop polling
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

GitHub-hosted Actions are another development option. Standard runners are free
for public repositories; private repositories have a monthly minute allowance.
The repository remains private and scheduled scans remain disabled until the
owner explicitly chooses that tradeoff.

## Local checks

```sh
python3 -m unittest discover -s tests -v
python3 -m py_compile worker.py
```
