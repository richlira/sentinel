"""Local fallback pipeline + self-test harness.

Runs the full Sentinel flow WITHOUT the cloud agent: classify -> route sensitive spans to
the local Gemma in one consolidated call -> render report.pdf + audit-log.json. It emits
the same `SENTINEL_EVENT` stream the cloud agent does, so the FastAPI/SSE layer and the UI
behave identically whether events come from the agent or from here.
"""

from __future__ import annotations

import os
import sys
import json
from datetime import datetime, timezone
from typing import Iterator

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "agent", "tools"))
import sentinel_local as local  # noqa: E402

import classifier  # noqa: E402
import report as report_mod  # noqa: E402


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def run_local_pipeline(text: str, outdir: str, document: str = "input.md") -> Iterator[dict]:
    """Yield events as the run progresses; the final 'done' event carries artifact paths."""
    os.makedirs(outdir, exist_ok=True)
    spans = classifier.classify_document(text)
    yield {"phase": "start", "mode": "local-fallback", "document": document, "spans_total": len(spans)}

    by_id = {s["id"]: s for s in spans}
    for s in spans:
        # Non-sensitive text is public, so show it in clear; sensitive text is masked.
        sensitive = s["destination"] == "local-gemma"
        preview = local.redact(s["text"]) if sensitive else s["text"][:80]
        yield {"phase": "classify", "span_id": s["id"], "category": s["category"],
               "destination": s["destination"], "preview": preview,
               "sha256": local.sha256(s["text"])}

    sensitive = [s for s in spans if s["destination"] == "local-gemma"]
    route_meta = {}
    if sensitive:
        yield {"phase": "route", "status": "sending", "count": len(sensitive)}
        result = local.route_to_local(sensitive)
        route_meta = result
        for d in result.get("derivatives", []):
            if d.get("id") in by_id:
                by_id[d["id"]]["safe_derivative"] = d
        yield {"phase": "route", "status": "received", "latency_ms": result["latency_ms"],
               "model": result["model"], "host": result["endpoint_host"]}

    for s in spans:
        if s["destination"] == "cloud-sandbox":
            yield {"phase": "cloud", "span_id": s["id"], "destination": "cloud-sandbox"}

    # Assemble the report object (the pdf-generator skill contract).
    out_spans = []
    for s in spans:
        local_span = s["destination"] == "local-gemma"
        out_spans.append({
            "id": s["id"], "category": s["category"], "destination": s["destination"],
            "preview": local.redact(s["text"]) if local_span else s["text"][:80],
            "sha256": local.sha256(s["text"]),
            "safe_derivative": s.get("safe_derivative"),
            "latency_ms": route_meta.get("latency_ms") if local_span else None,
        })
    rep = {
        "document": document,
        "generated_at": _now(),
        "summary": {
            "spans_total": len(spans),
            "routed_local": len(sensitive),
            "processed_cloud": len(spans) - len(sensitive),
            "raw_sensitive_bytes_processed_in_cloud": 0,
            "local_model": route_meta.get("model", local._config()["model"]),
            "local_endpoint_host": route_meta.get("endpoint_host", ""),
        },
        "spans": out_spans,
    }

    audit_path = os.path.join(outdir, "audit-log.json")
    pdf_path = os.path.join(outdir, "report.pdf")
    report_mod.write_audit_log(rep, audit_path)
    report_mod.render_pdf(rep, pdf_path)
    yield {"phase": "report", "audit_log": audit_path, "pdf": pdf_path}
    yield {"phase": "done", "summary": rep["summary"], "report": rep}


def main() -> None:
    src = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "data", "synthetic_intake.md")
    outdir = sys.argv[2] if len(sys.argv) > 2 else os.path.join(os.path.dirname(__file__), "runs", "local")
    with open(src) as fh:
        text = fh.read()
    for event in run_local_pipeline(text, outdir, document=os.path.basename(src)):
        if event["phase"] == "done":
            print("\nSUMMARY " + json.dumps(event["summary"], indent=2))
        else:
            local.emit(event)


if __name__ == "__main__":
    main()
