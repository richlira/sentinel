"""Sentinel local-routing helper — mounted into the Managed Agent sandbox.

Standard library only: the sandbox may not have third-party packages, and this same
file is reused for local self-tests. It standardizes four things the agent relies on:

  emit(event)        -> print a SENTINEL_EVENT line the orchestrator streams to the UI
  redact(text)       -> a cloud-safe preview (never the raw value)
  sha256(text)       -> integrity hash of the raw value
  route_to_local(..) -> ONE consolidated POST of pre-classified spans (local fallback path)
  redact_document(.) -> send the RAW document FIRST; get back redacted text + classified spans

Privacy invariants:
  * route_to_local never sets an Authorization header. In the sandbox the egress proxy
    injects it from the network allowlist, so the credential never lives here. For local
    self-tests, set SENTINEL_LOCAL_TOKEN to add it yourself.
  * Raw sensitive values appear only inside the outbound request body. Everything this
    module returns or prints is a redacted derivative or a hash.
"""

from __future__ import annotations

import json
import os
import re
import time
import hashlib
import urllib.request
from urllib.parse import urlparse

_HERE = os.path.dirname(os.path.abspath(__file__))


def _config() -> dict:
    # Config file wins (orchestrator templates it); env vars override for self-tests.
    cfg = {"local_url": "", "model": "gemma4:e4b"}
    path = os.path.join(_HERE, "sentinel_config.json")
    if os.path.exists(path):
        with open(path) as fh:
            cfg.update(json.load(fh))
    cfg["local_url"] = os.environ.get("NGROK_URL") or os.environ.get("SENTINEL_LOCAL_URL") or cfg["local_url"]
    cfg["model"] = os.environ.get("GEMMA_MODEL") or os.environ.get("SENTINEL_LOCAL_MODEL") or cfg["model"]
    return cfg


def emit(event: dict) -> None:
    """Print one structured event the orchestrator parses out of stdout."""
    print("SENTINEL_EVENT " + json.dumps(event, separators=(",", ":")), flush=True)


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def redact(text: str) -> str:
    """Cloud-safe preview: keep a field label, mask the value to its last 4 alnum chars."""
    text = text.strip()
    label, sep, value = text.partition(":")
    if sep and value.strip():
        return f"{label.strip()}: {_mask(value)}"
    return _mask(text)


def _mask(value: str, keep: int = 4, cap: int = 48) -> str:
    value = value.strip()
    alnum = [i for i, c in enumerate(value) if c.isalnum()]
    if len(alnum) <= keep:
        masked = value
    else:
        mask_set = set(alnum[:-keep])
        masked = "".join("•" if i in mask_set else c for i, c in enumerate(value))
    return masked[:cap] + ("…" if len(masked) > cap else "")


_LOCAL_PROMPT = (
    "You are a LOCAL privacy processor running on the operator's own hardware. "
    "You receive sensitive spans extracted from a document. For EACH span return a safe, "
    "redacted derivative only — NEVER echo the full raw value. "
    "Reply with ONLY a JSON array, one object per span, each: "
    '{"id": str, "category": str, "display": str (masked, reveal at most the last 4 chars), '
    '"valid_format": bool, "note": str (<=12 words)}. No prose, no markdown fences.'
)


def _extract_json_array(text: str):
    # Strip markdown fences the model may wrap the JSON in.
    text = re.sub(r"```(?:json)?", "", text)
    start = text.find("[")
    end = text.rfind("]")
    if start == -1 or end == -1 or end < start:
        return None
    try:
        return json.loads(text[start : end + 1])
    except json.JSONDecodeError:
        return None


def _extract_json_object(text: str):
    text = re.sub(r"```(?:json)?", "", text)
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end < start:
        return None
    try:
        return json.loads(text[start : end + 1])
    except json.JSONDecodeError:
        return None


_REDACT_PROMPT = (
    "You are a LOCAL privacy redactor on the operator's own hardware. You receive a FULL "
    "document. Find every SENSITIVE value (pii, financial, medical). Reply with ONLY a JSON "
    "array — no prose, no markdown fences — one object per sensitive value, each: "
    '{"id": "s1", "category": "pii|financial|medical", "value": "<the exact sensitive value>", '
    '"valid_format": true, "note": "<=10 words"}. Skip non-sensitive boilerplate.'
)


def _endpoint(cfg: dict) -> str:
    # Ollama native /api/chat (same server as /v1, different path) so we can disable thinking.
    base = cfg["local_url"].rstrip("/")
    if base.endswith("/v1"):
        base = base[:-3]
    return base.rstrip("/") + "/api/chat"


def _chat(messages: list, num_predict: int = 1024, timeout: int = 180) -> dict:
    """One /api/chat call with thinking off + bounded context (keeps gemma4:e4b fast).

    No Authorization header is set here — in the sandbox the egress proxy injects it from the
    network allowlist, so the credential never lives in this code.
    """
    cfg = _config()
    if not cfg["local_url"]:
        raise RuntimeError("local_url not configured")
    url = _endpoint(cfg)
    payload = {
        "model": cfg["model"],
        "messages": messages,
        "think": False,
        "stream": False,
        "options": {"num_predict": num_predict, "num_ctx": 8192, "temperature": 0},
    }
    headers = {"Content-Type": "application/json", "ngrok-skip-browser-warning": "true"}
    token = os.environ.get("SENTINEL_LOCAL_TOKEN")  # self-test only; proxy injects in sandbox
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), headers=headers, method="POST")
    t0 = time.time()
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = json.loads(resp.read().decode())
    latency_ms = int((time.time() - t0) * 1000)
    if "choices" in body:                       # OpenAI-compatible shape
        msg = body["choices"][0]["message"]
        content = (msg.get("content") or msg.get("reasoning") or "").strip()
    else:                                        # Ollama native shape
        content = (body.get("message", {}).get("content") or "").strip()
    return {"content": content, "model": body.get("model", cfg["model"]),
            "endpoint_host": urlparse(url).hostname, "latency_ms": latency_ms}


def route_to_local(spans: list[dict], timeout: int = 180) -> dict:
    """Consolidated POST of pre-classified spans -> safe derivatives (local fallback path)."""
    r = _chat(
        [{"role": "system", "content": _LOCAL_PROMPT},
         {"role": "user", "content": json.dumps(
             [{"id": s["id"], "category": s["category"], "value": s["text"]} for s in spans])}],
        num_predict=1024, timeout=timeout,
    )
    out = {
        "model": r["model"], "endpoint_host": r["endpoint_host"], "latency_ms": r["latency_ms"],
        "derivatives": _extract_json_array(r["content"]) or [],
        "raw_content_len": len(r["content"]),
    }
    if os.environ.get("SENTINEL_DEBUG_RAW"):
        out["raw_content"] = r["content"]
    return out


def redact_document(raw_text: str, timeout: int = 180) -> dict:
    """Privacy boundary: the RAW document goes to the LOCAL model FIRST.

    The local model (on the operator's hardware) does the classification — the reasoning over
    raw content. This helper runs inside the egress sandbox and re-masks every returned value
    deterministically with _mask(), so even if the model echoes a raw value it never reaches
    the cloud agent, the audit log, or stdout. The cloud agent only sees the masked spans.
    """
    r = _chat(
        [{"role": "system", "content": _REDACT_PROMPT},
         {"role": "user", "content": raw_text}],
        num_predict=1024, timeout=timeout,
    )
    found = _extract_json_array(r["content"]) or []
    spans = []
    for i, s in enumerate(found, 1):
        masked = _mask(str(s.get("value", s.get("display", ""))))
        spans.append({
            "id": s.get("id") or f"s{i}",
            "category": s.get("category", "pii"),
            "destination": "local-gemma",
            "preview": masked,
            "safe_derivative": {
                "display": masked,
                "valid_format": bool(s.get("valid_format", True)),
                "note": str(s.get("note", ""))[:80],
            },
        })
    out = {
        "model": r["model"], "endpoint_host": r["endpoint_host"], "latency_ms": r["latency_ms"],
        "document_sha256": sha256(raw_text),
        "spans": spans,
        "raw_content_len": len(r["content"]),
    }
    if os.environ.get("SENTINEL_DEBUG_RAW"):
        out["raw_content"] = r["content"]
    return out


def warm_up(timeout: int = 60) -> dict | None:
    """Load the local model into memory before the demo. Non-fatal."""
    try:
        return _chat([{"role": "user", "content": "ok"}], num_predict=1, timeout=timeout)
    except Exception:
        return None


# --- standalone self-test against the real tunnel ----------------------------------------
if __name__ == "__main__":
    here = os.path.dirname(os.path.abspath(__file__))
    doc_path = os.path.join(here, "..", "..", "backend", "data", "synthetic_intake.md")
    raw = open(doc_path).read()
    print(f"redact_document() on {os.path.basename(doc_path)} via {_config()['model']} ...")
    result = redact_document(raw)
    spans = result["spans"]
    print(f"latency_ms={result['latency_ms']}  spans={len(spans)}  host={result['endpoint_host']}")
    leaks = [t for t in ["524-71-9384", "0049917283", "102000076", "Delgado", "Larkspur",
                         "marcus.delgado.fake@example.com", "555-0148"]
             if t in json.dumps(result)]
    print("RAW LEAKS:", leaks or "NONE")
    print("sample spans:", json.dumps(spans[:4], indent=1))
