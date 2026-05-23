---
name: pdf-generator
description: Assemble the final report object and audit log proving which spans were processed locally vs. in the cloud, with raw_sensitive_bytes_to_cloud = 0. Emitted as a file artifact between SENTINEL_AUDIT markers.
---

# Skill: pdf-generator

Produce the evidence. The output must let a judge verify the privacy claim line by line.

## Procedure (via code_execution)

1. Build the report object:

   ```python
   report = {
     "document": "input.md",
     "generated_at": iso_now,
     "summary": {
       "spans_total": N,
       "routed_local": n_local,
       "processed_cloud": n_cloud,
       "raw_sensitive_bytes_to_cloud": 0,   # must be 0
       "local_model": local_result["model"],
       "local_endpoint_host": host,         # the allowlisted domain only
     },
     "spans": [
       {"id", "category", "destination",
        "preview": redact(text), "sha256": sha256(text),
        "safe_derivative": <from local model, for sensitive spans>,
        "latency_ms": <for local spans>}
       , ...
     ],
   }
   ```

2. Emit it as a file artifact, exactly:

   ```python
   import json
   print("SENTINEL_AUDIT_BEGIN")
   print(json.dumps(report))
   print("SENTINEL_AUDIT_END")
   ```

   The orchestrator captures this block, writes `audit-log.json`, and renders `report.pdf`
   from it. Also write `audit-log.json` to `/workspace/` so it exists as a sandbox artifact.

## Rules

- `spans[*].preview` and `sha256` are the only per-span fields derived from raw text.
- Never place a raw sensitive value anywhere in `report`.
- `summary.raw_sensitive_bytes_to_cloud` must be `0`; if you cannot guarantee it, fail loudly.
