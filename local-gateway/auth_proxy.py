"""Sentinel local gateway — a bearer-token gate in front of Ollama.

Run this on the DGX Spark and point the ngrok tunnel at it (instead of directly at
Ollama). It rejects any request without the correct `Authorization: Bearer <token>` and
forwards authorized requests to local Ollama. Combined with the Managed Agent's network
allowlist `transform`, this is the privacy boundary:

  agent sandbox  --(no creds in code)-->  egress proxy injects Authorization  -->  here

so the token never lives inside sandbox code, and an unauthenticated caller gets 401.

Pure standard library — zero install on the Spark.

    SENTINEL_LOCAL_TOKEN=your-secret python3 auth_proxy.py        # listens on :8788
    # then:  ngrok http 8788

Environment:
    SENTINEL_LOCAL_TOKEN   required; the shared secret the egress proxy injects.
    OLLAMA_URL             upstream Ollama (default http://127.0.0.1:11434).
    PORT                   listen port (default 8788).
"""

from __future__ import annotations

import os
import sys
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOKEN = os.environ.get("SENTINEL_LOCAL_TOKEN", "")
OLLAMA = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434").rstrip("/")
PORT = int(os.environ.get("PORT", "8788"))

_HOP_BY_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
               "te", "trailers", "transfer-encoding", "upgrade", "host", "content-length"}


class Gateway(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _authorized(self) -> bool:
        expected = f"Bearer {TOKEN}"
        return bool(TOKEN) and self.headers.get("Authorization") == expected

    def _deny(self) -> None:
        body = b'{"error":"unauthorized"}'
        self.send_response(401)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _forward(self, method: str) -> None:
        if not self._authorized():
            return self._deny()
        length = int(self.headers.get("Content-Length", 0) or 0)
        payload = self.rfile.read(length) if length else None
        fwd_headers = {k: v for k, v in self.headers.items() if k.lower() not in _HOP_BY_HOP}
        req = urllib.request.Request(OLLAMA + self.path, data=payload, headers=fwd_headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=600) as resp:
                data = resp.read()
                self.send_response(resp.status)
                ctype = resp.headers.get("Content-Type", "application/json")
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
        except urllib.error.HTTPError as exc:
            data = exc.read()
            self.send_response(exc.code)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except Exception as exc:  # noqa: BLE001
            msg = f'{{"error":"upstream","detail":{exc!r}}}'.encode()
            self.send_response(502)
            self.send_header("Content-Length", str(len(msg)))
            self.end_headers()
            self.wfile.write(msg)

    def do_GET(self) -> None:
        self._forward("GET")

    def do_POST(self) -> None:
        self._forward("POST")

    def log_message(self, fmt: str, *args) -> None:
        auth = "ok" if self._authorized() else "DENIED"
        sys.stderr.write(f"[gateway] {self.command} {self.path} auth={auth}\n")


if __name__ == "__main__":
    if not TOKEN:
        sys.exit("Set SENTINEL_LOCAL_TOKEN before starting the gateway.")
    print(f"Sentinel gateway on :{PORT} -> {OLLAMA} (bearer-token required)")
    ThreadingHTTPServer(("0.0.0.0", PORT), Gateway).serve_forever()
