"""Local-First mode (the primary, most-honest architecture).

Flow:
  1. Redact ON-DEVICE: classify locally, the local model derives safe notes, mask
     deterministically. Raw values are kept ONLY in a local session map. The raw document
     never goes to Google.
  2. Register that session's raw values with the local verify-service (localhost).
  3. Hand the cloud Managed Agent ONLY the redacted bundle, plus the network allowlist so it
     can call back to the verify-service for VERDICTS (egress proxy injects the bearer token).
  4. Multi-turn chat: the user converses with the agent (previous_interaction_id); the agent
     verifies sensitive fields by reference (span id), never possessing the raw value.
  5. The audit log records every verification verdict, keeping
     raw_sensitive_bytes_processed_in_cloud: 0.

Reuses classifier (backend/classifier.py), sentinel_local redaction helpers, report.py, and
orchestrator.AGENT / _collect_stdout.
"""

from __future__ import annotations

import json
import os
import re
import sys
import threading
import time
import uuid
import urllib.request
from datetime import datetime, timezone
from typing import Iterator
from urllib.parse import urlparse

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "agent", "tools"))
import sentinel_local as local  # noqa: E402

import classifier  # noqa: E402
import report as report_mod  # noqa: E402
import orchestrator  # noqa: E402
from google.genai import Client  # noqa: E402

VERIFY_LOCAL_URL = os.environ.get("VERIFY_LOCAL_URL", "http://127.0.0.1:8799").rstrip("/")
VERIFY_URL = (os.environ.get("VERIFY_URL", "") or VERIFY_LOCAL_URL).rstrip("/")
CHECKS = ["ssn_format", "card_luhn", "card_expired", "routing_aba", "email_format"]
CHECK_FACT = {
    "ssn_format": "the Social Security Number format",
    "card_expired": "the credit card expiry",
    "card_luhn": "the credit card number",
    "routing_aba": "the routing number",
    "email_format": "the email format",
}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _post(url: str, body: dict, timeout: int = 30) -> dict:
    req = urllib.request.Request(url, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


def _get(url: str, timeout: int = 10) -> dict:
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.loads(r.read().decode())


def _verify_event(v: dict, field_of: dict) -> dict:
    """Shape a verify-log entry into a live SSE event (verdict only, no raw)."""
    sid, chk = v.get("span_id"), v.get("check")
    return {"phase": "verify", "span_id": sid, "field": field_of.get((sid, chk), sid),
            "check": chk, "valid": v.get("valid"), "note": v.get("note")}


def redact_on_device(text: str) -> dict:
    """Classify + redact locally. Returns masked spans, a redacted document, and the raw
    field map (which stays on-device — never returned to the cloud)."""
    spans = classifier.classify_document(text)
    sensitive = [s for s in spans if s["destination"] == "local-gemma"]
    notes: dict[str, dict] = {}
    host = ""
    if sensitive:
        try:
            r = local.route_to_local(sensitive)  # local model contributes safe notes
            notes = {d.get("id"): d for d in r.get("derivatives", [])}
            host = r.get("endpoint_host", "")
        except Exception:
            notes = {}

    out_spans, fields, redacted_text = [], {}, text
    for s in spans:
        sens = s["destination"] == "local-gemma"
        masked = local._mask(s["text"]) if sens else s["text"]
        if sens:
            fields[s["id"]] = s["text"]                 # raw kept LOCAL only
            redacted_text = redacted_text.replace(s["text"], masked)
        d = notes.get(s["id"]) or {}
        out_spans.append({
            "id": s["id"], "category": s["category"], "destination": s["destination"],
            "preview": masked if sens else s["text"][:80],
            "sha256": local.sha256(s["text"]),
            "safe_derivative": ({"display": masked, "valid_format": bool(d.get("valid_format", True)),
                                 "note": str(d.get("note", "Redacted locally"))[:80]} if sens else None),
        })
    return {"spans": out_spans, "redacted_text": redacted_text, "fields": fields,
            "sensitive_count": len(sensitive), "endpoint_host": host}


def _verify_env(redacted_text: str | None = None, spans: list | None = None) -> dict:
    """Environment for the cloud agent: ONLY redacted sources + the verification allowlist.

    The raw document is never mounted. The allowlist lets the agent reach the verify-service,
    and its transform injects the bearer token (never in sandbox code).
    """
    host = urlparse(VERIFY_URL).hostname
    token = os.environ.get("SENTINEL_LOCAL_TOKEN", "")
    rule = {"domain": host}
    if token:
        rule["transform"] = [{"Authorization": f"Bearer {token}"}]
    env = {"type": "remote", "network": {"allowlist": [rule]}}
    if redacted_text is not None:
        env["sources"] = [
            {"type": "inline", "target": "redacted.md", "content": redacted_text},
            {"type": "inline", "target": "spans.json",
             "content": json.dumps([{k: s[k] for k in ("id", "category", "preview")} for s in (spans or [])])},
        ]
    return env


def _instruction(session_id: str, checks: list) -> str:
    pairs = ", ".join(f'("{c["span_id"]}","{c["check"]}")' for c in checks)
    return (
        "You are Sentinel's cloud reviewer. The document in redacted.md was ALREADY redacted on the "
        "operator's local hardware — you only have masked values. You do NOT have raw sensitive values "
        "and must never ask for them.\n\n"
        "Do EXACTLY this and nothing else — do NOT list files or read other paths:\n"
        "1. Run ONE code_execution Python script that loops over these (span_id, check) pairs and POSTs "
        f"each to {VERIFY_URL}/verify (use urllib.request — the 'requests' library is NOT available; do "
        "NOT set an Authorization header, the egress proxy injects it). Pairs: [" + pairs + "]. "
        'Each request body: {"session_id":"' + session_id + '","span_id":<id>,"check":<check>}, with '
        'header "ngrok-skip-browser-warning: true". Print each response.\n'
        "2. Reply in AT MOST 3 short sentences. Refer to fields by NAME (Social Security Number, credit "
        "card, bank routing number, email), NEVER by span id. Summarize the verdicts and ask the user "
        "ONE concise question about whether it is safe to forward to billing. Never reveal a raw value."
    )


_CLIENT: Client | None = None


def _client() -> Client:
    # Hold a single long-lived client; a fresh-per-call client gets its httpx transport
    # closed ("Cannot send a request, as the client has been closed.").
    global _CLIENT
    if _CLIENT is None:
        _CLIENT = Client(api_key=os.environ["GEMINI_API_KEY"])
    return _CLIENT


def run_localfirst_pipeline(text: str, outdir: str, document: str = "input.md") -> Iterator[dict]:
    os.makedirs(outdir, exist_ok=True)
    session_id = uuid.uuid4().hex[:12]
    yield {"phase": "start", "mode": "local-first", "document": document, "session_id": session_id}

    red = redact_on_device(text)
    for s in red["spans"]:
        yield {"phase": "classify", "span_id": s["id"], "category": s["category"],
               "destination": s["destination"], "preview": s["preview"], "sha256": s["sha256"]}

    # Register the session's raw values with the local verify-service (on-device).
    try:
        _post(f"{VERIFY_LOCAL_URL}/session", {"session_id": session_id, "fields": red["fields"]})
    except Exception as exc:  # noqa: BLE001
        yield {"phase": "notice", "message": f"verify-service unavailable: {exc}"}

    yield {"phase": "handoff", "to": "managed-agent", "sent": "redacted-only",
           "sensitive_local": red["sensitive_count"]}

    # Build the report from masked spans (raw never used here).
    rep = {
        "document": document, "generated_at": _now(),
        "summary": {
            "spans_total": len(red["spans"]), "routed_local": red["sensitive_count"],
            "processed_cloud": len(red["spans"]) - red["sensitive_count"],
            "raw_sensitive_bytes_processed_in_cloud": 0,
            "local_model": local._config()["model"], "local_endpoint_host": red["endpoint_host"],
            "mode": "local-first",
        },
        "spans": red["spans"],
    }

    # Pick the exact spans to verify (no guessing). Richer demo: SSN format, card expiry, card
    # number (Luhn), bank routing (ABA), email — all run by the agent in one code_execution script.
    def _find(cat: str, pat: str):
        return next((s["id"] for s in red["spans"]
                     if s["category"] == cat and re.search(pat, red["fields"].get(s["id"], ""), re.I)), None)
    ssn_id = _find("pii", r"\d{3}-\d{2}-\d{4}")
    card_id = _find("financial", r"(0[1-9]|1[0-2])\s*/\s*\d{2}")
    routing_id = _find("financial", r"routing")
    email_id = _find("pii", r"[^@\s]+@[^@\s]+\.[^@\s]+")

    checks = []
    if ssn_id:
        checks.append({"span_id": ssn_id, "field": "Social Security Number", "check": "ssn_format"})
    if card_id:
        checks.append({"span_id": card_id, "field": "Credit card", "check": "card_expired"})
        checks.append({"span_id": card_id, "field": "Credit card number", "check": "card_luhn"})
    if routing_id:
        checks.append({"span_id": routing_id, "field": "Bank routing number", "check": "routing_aba"})
    if email_id:
        checks.append({"span_id": email_id, "field": "Email", "check": "email_format"})
    field_of = {(c["span_id"], c["check"]): c["field"] for c in checks}

    # Show the planned checks immediately as "pending" so the wait reads as live action.
    yield {"phase": "verify_pending", "items": checks}

    # Run the agent in a thread; meanwhile poll the verify-service log and stream each callback
    # the instant the Spark answers — that's the live "wow" of cloud-verifying-without-possessing.
    box: dict = {}

    def _run_agent() -> None:
        try:
            client = _client()
            box["it"] = client.interactions.create(
                agent=orchestrator.AGENT, input=_instruction(session_id, checks),
                environment=_verify_env(red["redacted_text"], red["spans"]),
                tools=[{"type": "code_execution"}], store=True, timeout=300,
            )
        except Exception as exc:  # noqa: BLE001
            box["err"] = exc

    th = threading.Thread(target=_run_agent, daemon=True)
    th.start()
    emitted = 0

    def _poll_log() -> list:
        try:
            return _get(f"{VERIFY_LOCAL_URL}/session/{session_id}/log").get("queries", [])
        except Exception:
            return []

    while th.is_alive():
        q = _poll_log()
        for v in q[emitted:]:
            yield _verify_event(v, field_of)
        emitted = max(emitted, len(q))
        time.sleep(1.0)
    th.join()
    for v in _poll_log()[emitted:]:   # flush any verdicts that landed right before completion
        yield _verify_event(v, labels)

    interaction_id = None
    agent_text = ""
    if "err" in box:
        yield {"phase": "notice",
               "message": f"Cloud agent unavailable ({box['err']}); redaction + report still produced locally."}
    elif box.get("it") is not None:
        interaction_id = box["it"].id
        agent_text = box["it"].output_text or ""

    # Pull the verification verdict log into the audit (no raw).
    try:
        rep["verifications"] = _get(f"{VERIFY_LOCAL_URL}/session/{session_id}/log").get("queries", [])
    except Exception:
        rep["verifications"] = []

    audit_path = os.path.join(outdir, "audit-log.json")
    pdf_path = os.path.join(outdir, "report.pdf")
    report_mod.write_audit_log(rep, audit_path)
    report_mod.render_pdf(rep, pdf_path)

    if agent_text:
        yield {"phase": "agent_message", "text": agent_text}
    yield {"phase": "report", "audit_log": audit_path, "pdf": pdf_path}
    yield {"phase": "done", "summary": rep["summary"],
           "interaction_id": interaction_id, "session_id": session_id}


CHAT_MODEL = os.environ.get("CHAT_MODEL", "gemini-2.5-flash")


def continue_interaction(interaction_id: str, message: str, session_id: str | None = None) -> dict:
    """Fast chat turn on Gemini Flash.

    Follow-up questions reason over the verdicts the local model already returned — they need no
    new egress — so we answer with a fast plain-model interaction (~4s) instead of the ~30s agent.
    (The secure verification callback still runs on the antigravity agent during the initial run;
    the egress allowlist is only honored for agent interactions.)
    """
    verifications = []
    if session_id:
        try:
            verifications = _get(f"{VERIFY_LOCAL_URL}/session/{session_id}/log").get("queries", [])
        except Exception:
            verifications = []
    facts = "; ".join(
        f"{CHECK_FACT.get(v.get('check'), v.get('check'))} is {'valid' if v.get('valid') else 'invalid'}"
        for v in verifications
    ) or "none verified yet"

    prompt = (
        "You are Sentinel's privacy reviewer. The document was redacted on the operator's LOCAL "
        "hardware; you only know these locally-verified facts and NEVER the raw values: " + facts + ". "
        "Answer the user's question in AT MOST 3 short sentences, referring to fields by name (the "
        "Social Security Number, the credit card). If they ask to verify something not in the facts, "
        "say it would need a new local verification.\n\nUser: " + message
    )
    client = _client()
    it = client.interactions.create(
        model=CHAT_MODEL, input=prompt, environment={"type": "remote"}, store=True, timeout=60,
    )
    return {"reply": it.output_text or "", "interaction_id": it.id, "verifications": verifications}
