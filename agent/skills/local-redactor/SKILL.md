---
name: local-redactor
description: The agent's FIRST action. Delegate the RAW document to the local model on the operator's hardware for classification + redaction. The cloud never reads or reasons over raw content; it only receives masked spans back.
---

# Skill: local-redactor

This is the privacy boundary and it runs **first, before anything else**. You do not classify
or inspect the document yourself — the local model does. You only forward raw bytes and
receive masked spans.

## Procedure (via code_execution)

```python
from tools.sentinel_local import redact_document, emit

raw = open("input.md").read()          # read ONLY to forward; do not inspect or reason over it
emit({"phase": "route", "status": "sending"})

result = redact_document(raw)          # local model classifies; the helper masks deterministically
spans = result["spans"]                # each: {id, category, destination, preview, safe_derivative}

for s in spans:
    emit({
        "phase": "classify",
        "span_id": s["id"],
        "category": s["category"],
        "destination": s["destination"],   # always "local-gemma" for sensitive spans
        "preview": s["preview"],            # already masked by the helper
    })

emit({"phase": "route", "status": "received",
      "latency_ms": result["latency_ms"], "model": result["model"], "host": result["endpoint_host"]})
```

Hold `result` in memory for the pdf-generator skill.

## Rules

- Do **not** open, parse, classify, or summarize `input.md` yourself. The only thing you may do
  with the raw text is pass it to `redact_document`.
- `redact_document` returns only masked previews/derivatives — never raw values. Use them as-is.
- If the local endpoint is unreachable, emit `{"phase": "route", "status": "error"}` and stop;
  never fall back to processing the raw document in the cloud.
