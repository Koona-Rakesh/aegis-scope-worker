"""Loopback-only vulnerable application for AegisScope engine validation.

This fixture is intentionally vulnerable and must never be exposed outside the
validation container. The CI workflow starts it on 127.0.0.1 with Docker
networking disabled.
"""

from __future__ import annotations

import sqlite3
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


class VulnerableLab:
    def __init__(self, host: str = "127.0.0.1", port: int = 8765) -> None:
        self._database = sqlite3.connect(":memory:", check_same_thread=False)
        self._database.execute("CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT NOT NULL)")
        self._database.executemany(
            "INSERT INTO products (id, name) VALUES (?, ?)",
            [(1, "alpha"), (2, "beta")],
        )
        self._database.commit()
        self._lock = threading.Lock()
        self._rate_limit_requests = 0
        lab = self

        class Handler(BaseHTTPRequestHandler):
            server_version = "AegisScopeLab/1.0"

            def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
                parsed = urllib.parse.urlsplit(self.path)
                params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                if parsed.path == "/":
                    self._html(
                        '<a href="/search?q=baseline">search</a>'
                        '<a href="/product?id=1">product</a>'
                    )
                    return
                if parsed.path == "/search":
                    value = params.get("q", [""])[0]
                    self._html(f"<h1>Search results</h1><p>{value}</p>")
                    return
                if parsed.path == "/product":
                    value = params.get("id", ["1"])[0]
                    try:
                        with lab._lock:
                            rows = lab._database.execute(
                                f"SELECT name FROM products WHERE id = {value}"
                            ).fetchall()
                    except sqlite3.Error as error:
                        self._html(f"SQLite error: {error}", status=500)
                        return
                    self._html("<br>".join(str(row[0]) for row in rows) or "No product")
                    return
                if parsed.path == "/rate-limit":
                    with lab._lock:
                        lab._rate_limit_requests += 1
                        request_number = lab._rate_limit_requests
                    if request_number >= 5:
                        self._html(
                            "Safe lab threshold reached",
                            status=429,
                            headers={"Retry-After": "5", "RateLimit-Limit": "4"},
                        )
                        return
                    self._html(f"Safe lab request {request_number}")
                    return
                self.send_error(404)

            def _html(self, body: str, status: int = 200, headers: dict[str, str] | None = None) -> None:
                payload = f"<!doctype html><html><body>{body}</body></html>".encode()
                self.send_response(status)
                self.send_header("content-type", "text/html; charset=utf-8")
                self.send_header("content-length", str(len(payload)))
                self.send_header("cache-control", "no-store")
                for key, value in (headers or {}).items():
                    self.send_header(key, value)
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, _format: str, *args: Any) -> None:
                return

        self.server = ThreadingHTTPServer((host, port), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.origin = f"http://{host}:{self.server.server_port}"

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self._database.close()
