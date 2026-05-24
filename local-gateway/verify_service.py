"""Sentinel local verification service — the privacy-preserving callback target.

Runs on the operator's hardware (the DGX Spark), behind the bearer-token gate, exposed via
the tunnel. It is what the cloud Managed Agent calls back to when it needs to *verify* a
sensitive fact it does NOT possess.

The contract that makes this privacy-preserving:
  * The agent never has raw sensitive values — only masked previews + a span id.
  * The agent calls POST /verify {session_id, span_id, check}. It sends a *reference*
    (span id) and a check name, NEVER a raw value.
  * This service holds the raw values locally (registered by the local backend via
    POST /session) and returns ONLY a verdict (valid/invalid + a short safe note).
    Raw values never appear in any response.
  * /verify requires `Authorization: Bearer <SENTINEL_LOCAL_TOKEN>`. In production the
    Managed Agent's egress proxy injects this header from the network allowlist transform,
    so the credential never lives in sandbox code.

Pure standard library. Also proxies /api/* and /v1/* to Ollama so one tunnel serves both
the local model and the verification channel.

    SENTINEL_LOCAL_TOKEN=secret python3 verify_service.py     # listens on :8799
    # then point the tunnel at :8799

Env: SENTINEL_LOCAL_TOKEN (required), OLLAMA_URL (default http://127.0.0.1:11434),
     PORT (default 8799).
"""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.request
from datetime import date
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOKEN = os.environ.get("SENTINEL_LOCAL_TOKEN", "")
OLLAMA = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434").rstrip("/")
PORT = int(os.environ.get("PORT", "8799"))

# session_id -> { span_id -> raw_value }. Raw values live ONLY here, in local memory.
_SESSIONS: dict[str, dict[str, str]] = {}
# session_id -> [ {span_id, check, valid, note} ]  — verdict log for the audit trail (no raw).
_QUERY_LOG: dict[str, list] = {}


# --- verification checks: each takes the raw value, returns (valid, note). No raw in note. ---
def _check_ssn_format(v: str) -> tuple[bool, str]:
    # search (not fullmatch): the stored value may include a label, e.g. "SSN: 524-71-9384".
    return bool(re.search(r"\b\d{3}-\d{2}-\d{4}\b", v)), "US SSN format ###-##-####"


def _luhn(digits: str) -> bool:
    ds = [int(c) for c in digits if c.isdigit()]
    if len(ds) < 13:
        return False
    chk = 0
    for i, d in enumerate(reversed(ds)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        chk += d
    return chk % 10 == 0


def _check_card_luhn(v: str) -> tuple[bool, str]:
    head = re.split(r"exp", v, flags=re.I)[0]   # card digits only, drop the expiry digits
    return _luhn(re.sub(r"\D", "", head)), "Passes Luhn checksum"


def _check_card_expired(v: str) -> tuple[bool, str]:
    m = re.search(r"(0[1-9]|1[0-2])\s*/\s*(\d{2})", v)
    if not m:
        return False, "No MM/YY found"
    mm, yy = int(m.group(1)), 2000 + int(m.group(2))
    today = date.today()
    expired = (yy, mm) < (today.year, today.month)
    return (not expired), ("Not expired" if not expired else "Expired")


def _check_email_format(v: str) -> tuple[bool, str]:
    return bool(re.search(r"[^@\s]+@[^@\s]+\.[^@\s]+", v)), "Valid email shape"


def _check_routing_aba(v: str) -> tuple[bool, str]:
    for m in re.findall(r"\d{9}", v):   # find a 9-digit routing run (value may include an account no.)
        d = [int(c) for c in m]
        if (3 * (d[0] + d[3] + d[6]) + 7 * (d[1] + d[4] + d[7]) + (d[2] + d[5] + d[8])) % 10 == 0:
            return True, "ABA routing checksum"
    return False, "No valid 9-digit routing number"


_CHECKS = {
    "ssn_format": _check_ssn_format,
    "card_luhn": _check_card_luhn,
    "card_expired": _check_card_expired,
    "email_format": _check_email_format,
    "routing_aba": _check_routing_aba,
}


class Verify(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _json(self, code: int, obj: dict) -> None:
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self) -> bool:
        return bool(TOKEN) and self.headers.get("Authorization") == f"Bearer {TOKEN}"

    def _body(self) -> dict:
        n = int(self.headers.get("Content-Length", 0) or 0)
        return json.loads(self.rfile.read(n)) if n else {}

    def do_POST(self) -> None:
        path = self.path.split("?")[0]
        # Local-only registration of a session's raw values (called by the backend on-device).
        if path == "/session":
            b = self._body()
            sid = str(b.get("session_id", ""))
            _SESSIONS[sid] = {str(k): str(v) for k, v in (b.get("fields") or {}).items()}
            return self._json(200, {"ok": True, "session_id": sid, "fields": len(_SESSIONS[sid])})

        # The privacy-preserving verification callback (called by the cloud agent via tunnel).
        if path == "/verify":
            if not self._authorized():
                return self._json(401, {"error": "unauthorized"})
            b = self._body()
            sid, span, check = str(b.get("session_id", "")), str(b.get("span_id", "")), str(b.get("check", ""))
            raw = _SESSIONS.get(sid, {}).get(span)
            if raw is None:
                return self._json(404, {"error": "unknown span", "span_id": span})
            fn = _CHECKS.get(check)
            if fn is None:
                return self._json(400, {"error": "unknown check", "check": check, "available": list(_CHECKS)})
            valid, note = fn(raw)
            entry = {"span_id": span, "check": check, "valid": valid, "note": note}
            _QUERY_LOG.setdefault(sid, []).append(entry)
            # VERDICT ONLY — never the raw value.
            return self._json(200, {**entry, "raw_returned": False})

        # Otherwise proxy to Ollama (bearer required), so one tunnel serves the model too.
        if not self._authorized():
            return self._json(401, {"error": "unauthorized"})
        self._proxy("POST")

    def do_GET(self) -> None:
        path = self.path.split("?")[0]
        if path == "/checks":
            return self._json(200, {"checks": list(_CHECKS)})
        # Local-only verdict log for the audit trail (called by the backend on-device).
        m = re.fullmatch(r"/session/([^/]+)/log", path)
        if m:
            return self._json(200, {"session_id": m.group(1), "queries": _QUERY_LOG.get(m.group(1), [])})
        if not self._authorized():
            return self._json(401, {"error": "unauthorized"})
        self._proxy("GET")

    def _proxy(self, method: str) -> None:
        n = int(self.headers.get("Content-Length", 0) or 0)
        payload = self.rfile.read(n) if n else None
        fwd = {k: v for k, v in self.headers.items()
               if k.lower() not in ("host", "content-length", "authorization", "connection")}
        req = urllib.request.Request(OLLAMA + self.path, data=payload, headers=fwd, method=method)
        try:
            with urllib.request.urlopen(req, timeout=600) as resp:
                data = resp.read()
                self.send_response(resp.status)
                self.send_header("Content-Type", resp.headers.get("Content-Type", "application/json"))
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
        except Exception as exc:  # noqa: BLE001
            self._json(502, {"error": "upstream", "detail": repr(exc)})

    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write(f"[verify] {self.command} {self.path.split('?')[0]} auth={'ok' if self._authorized() else 'DENIED'}\n")


if __name__ == "__main__":
    if not TOKEN:
        sys.exit("Set SENTINEL_LOCAL_TOKEN before starting the verification service.")
    print(f"Sentinel verify-service on :{PORT} -> Ollama {OLLAMA} (bearer required; /verify returns verdicts only)")
    ThreadingHTTPServer(("0.0.0.0", PORT), Verify).serve_forever()
