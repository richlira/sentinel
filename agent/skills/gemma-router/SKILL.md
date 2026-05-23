---
name: gemma-router
description: The contract for talking to the operator's local endpoint. One consolidated call, no credentials in code (the egress proxy injects them), and the only domain the sandbox may reach.
---

# Skill: gemma-router

Defines *how* the sandbox talks to the local model. The local-redactor skill performs the call;
this skill is the contract it must honor.

## The call

- Use `tools.sentinel_local.redact_document(raw)` — a single consolidated request to the local
  endpoint defined in `tools/sentinel_config.json`. Do not loop or make per-span network calls.
- `redact_document` POSTs to the local model with thinking disabled (`think:false`) for speed.
  It sets **no** `Authorization` header — in this sandbox the egress proxy injects it from the
  network allowlist, so the credential never enters your code.
- The endpoint is the **only** domain the sandbox is allowed to reach. Any other outbound
  request will fail by design.

## What comes back

A dict: `{"spans": [...], "model", "endpoint_host", "latency_ms", "document_sha256"}`. Each span
is already a **safe derivative** — `{id, category, destination, preview (masked),
safe_derivative:{display, valid_format, note}}`. The masking is performed deterministically by
the helper, not by the model, so it is reliable even if the model is imperfect.

## Rules

- Never reconstruct, log, or transmit the raw values. Keep only what `redact_document` returns.
- Treat `endpoint_host` and `document_sha256` as the provenance/integrity anchors for the audit.
