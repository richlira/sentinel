---
name: gemma-router
description: Route all sensitive spans in one consolidated request to the operator's local Gemma endpoint, which returns safe redacted derivatives. Raw sensitive data leaves the sandbox only toward the allowlisted local endpoint, with the auth header injected by the egress proxy.
---

# Skill: gemma-router

This is the privacy boundary. Sensitive spans are processed **only** on the operator's
local hardware. The cloud receives Gemma's safe answer, never the raw input.

## Procedure (via code_execution)

1. Collect every span whose `destination == "local-gemma"`.
2. Send them **all at once** (one HTTP request — the local model is a slow reasoning model,
   so minimize round-trips):

   ```python
   from tools.sentinel_local import route_to_local, emit
   emit({"phase": "route", "status": "sending", "count": len(sensitive_spans)})
   local_result = route_to_local(sensitive_spans)   # returns list of safe derivatives
   emit({"phase": "route", "status": "received",
         "latency_ms": local_result["latency_ms"]})
   ```

   `route_to_local` POSTs to the local endpoint defined in `sentinel_config.json`. It does
   **not** add an `Authorization` header — the egress proxy injects it from the network
   allowlist, so the credential never enters this sandbox. The endpoint is the only domain
   the sandbox is allowed to reach.

3. The local model returns, per span, a **safe derivative** only: a redacted display value,
   a validity/format check, and a category confirmation — never the raw value echoed back.
   Example: SSN `524-71-9384` → `{"display": "SSN •••-••-9384", "valid_format": true}`.

4. Process `non_sensitive` spans here in the sandbox (summarize / normalize as needed) and
   emit `{"phase": "cloud", "span_id": ..., "destination": "cloud-sandbox"}` for each.

## Rules

- One consolidated local call. Do not loop per-span over the network.
- Never log the raw request body. After the call, keep only the safe derivatives.
- If the local endpoint is unreachable, emit `{"phase": "route", "status": "error"}` and
  mark those spans `unprocessed_local` — never fall back to processing them in the cloud.
