"""Sentinel local-routing helper — mounted into the Managed Agent sandbox.

Standard library only: the sandbox may not have third-party packages, and this same
file is reused for local self-tests. It standardizes four things the agent relies on:

  emit(event)        -> print a SENTINEL_EVENT line the orchestrator streams to the UI
  redact(text)       -> a cloud-safe preview (never the raw value)
  sha256(text)       -> integrity hash of the raw value
  route_to_local(..) -> ONE consolidated POST to the operator's local endpoint

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
    cfg = {"local_url": "", "model": "gemma4:31b"}
    path = os.path.join(_HERE, "sentinel_config.json")
    if os.path.exists(path):
        with open(path) as fh:
            cfg.update(json.load(fh))
    cfg["local_url"] = os.environ.get("SENTINEL_LOCAL_URL", cfg["local_url"])
    cfg["model"] = os.environ.get("SENTINEL_LOCAL_MODEL", cfg["model"])
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


def route_to_local(spans: list[dict], timeout: int = 180) -> dict:
    """Send ALL sensitive spans in one request to the local endpoint.

    `spans` items: {"id", "category", "text"}. Returns derivatives + telemetry; the raw
    text is sent in the body but is not retained in the returned object.
    """
    cfg = _config()
    if not cfg["local_url"]:
        raise RuntimeError("local_url not configured")

    # Use Ollama's native endpoint with thinking disabled. gemma4:31b is a reasoning model;
    # full thinking makes a 15-span batch take >3 min. think=false drops it to seconds with
    # no quality loss for redaction/validation. Same server as /v1, just a different path.
    base = cfg["local_url"].rstrip("/")
    if base.endswith("/v1"):
        base = base[:-3]
    url = base.rstrip("/") + "/api/chat"

    payload = {
        "model": cfg["model"],
        "messages": [
            {"role": "system", "content": _LOCAL_PROMPT},
            {"role": "user", "content": json.dumps(
                [{"id": s["id"], "category": s["category"], "value": s["text"]} for s in spans]
            )},
        ],
        "think": False,
        "stream": False,
        "options": {"num_predict": 4096, "temperature": 0},
    }
    headers = {"Content-Type": "application/json", "ngrok-skip-browser-warning": "true"}
    # Self-test only; in the sandbox the egress proxy injects this header.
    token = os.environ.get("SENTINEL_LOCAL_TOKEN")
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
    derivatives = _extract_json_array(content) or []

    out = {
        "model": body.get("model", cfg["model"]),
        "endpoint_host": urlparse(url).hostname,
        "latency_ms": latency_ms,
        "derivatives": derivatives,
        "raw_content_len": len(content),
    }
    if os.environ.get("SENTINEL_DEBUG_RAW"):
        out["raw_content"] = content
    return out


# --- standalone self-test against the real tunnel ----------------------------------------
if __name__ == "__main__":
    sample = [
        {"id": "s1", "category": "pii", "text": "Social Security Number: 524-71-9384"},
        {"id": "s2", "category": "financial", "text": "Bank account: Routing 102000076, Account 0049917283"},
        {"id": "s3", "category": "medical", "text": "Primary diagnosis: Type 2 diabetes mellitus (ICD-10 E11.9)"},
    ]
    print("redact() preview:")
    for s in sample:
        emit({"phase": "classify", "span_id": s["id"], "category": s["category"],
              "destination": "local-gemma", "preview": redact(s["text"]), "sha256": sha256(s["text"])[:16]})
    print("\nrouting", len(sample), "spans to local endpoint ...")
    result = route_to_local(sample)
    print(json.dumps(result, indent=2))
