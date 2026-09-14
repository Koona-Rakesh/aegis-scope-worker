# AegisScope scanner worker

Private Render deployment source for the Milestone 2 scanner worker.

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

## Render

`render.yaml` defines one Docker background worker in Singapore on the `1c-2g`
plan. Render generates the local ZAP API key. Set `SCANNER_CALLBACK_TOKEN` in
the Blueprint setup form to the same secret configured on the AegisScope Site.

Background workers do not have a free compute plan. The `1c-2g` plan is chosen
because OWASP ZAP is a Java application and 512 MB is not a sustainable memory
ceiling for crawling and passive analysis.

## Local checks

```sh
python3 -m unittest discover -s tests -v
python3 -m py_compile worker.py
```
