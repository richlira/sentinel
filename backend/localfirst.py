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
import sys
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


def _instruction(session_id: str) -> str:
    return (
        "You are Sentinel's cloud reviewer. The document in redacted.md was ALREADY redacted on "
        "the operator's local hardware — you only have masked values (e.g. '•••-••-9384'). You do "
        "NOT have, and must never ask for, raw sensitive values.\n\n"
        "To VERIFY a sensitive field, use code_execution to POST to the operator's local "
        f"verification endpoint: {VERIFY_URL}/verify with JSON body "
        f'{{"session_id":"{session_id}","span_id":"<id from spans.json>","check":"<check>"}} and header '
        '\"ngrok-skip-browser-warning: true\". Do NOT add an Authorization header — the egress proxy '
        f"injects it. Available checks: {', '.join(CHECKS)}. The endpoint returns ONLY a verdict.\n\n"
        "Now: greet the user briefly, summarize what you see (counts by category), VERIFY at least "
        "the SSN format and the card expiry to demonstrate, state the verdicts, then ask the user ONE "
        "concise question about how to proceed. Never reveal or guess a raw value."
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

    interaction_id = None
    agent_text = ""
    try:
        client = _client()
        it = client.interactions.create(
            agent=orchestrator.AGENT, input=_instruction(session_id),
            environment=_verify_env(red["redacted_text"], red["spans"]),
            tools=[{"type": "code_execution"}], store=True, timeout=300,
        )
        interaction_id = it.id
        agent_text = it.output_text or ""
    except Exception as exc:  # noqa: BLE001
        yield {"phase": "notice", "message": f"Cloud agent unavailable ({exc}); redaction + report still produced locally."}

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


def continue_interaction(interaction_id: str, message: str, session_id: str | None = None) -> dict:
    """One more chat turn. Context (the redacted bundle) is carried by previous_interaction_id;
    the allowlist is re-supplied so the agent can still verify fields mid-conversation."""
    client = _client()
    it = client.interactions.create(
        agent=orchestrator.AGENT, input=message, previous_interaction_id=interaction_id,
        environment=_verify_env(), tools=[{"type": "code_execution"}], store=True, timeout=300,
    )
    verifications = []
    if session_id:
        try:
            verifications = _get(f"{VERIFY_LOCAL_URL}/session/{session_id}/log").get("queries", [])
        except Exception:
            verifications = []
    return {"reply": it.output_text or "", "interaction_id": it.id, "verifications": verifications}
