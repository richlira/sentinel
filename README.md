# Sentinel — agentic privacy routing

**Sensitive data never leaves your hardware. The cloud trusts the local model's answer
without ever seeing the raw data.**

Sentinel is a privacy-routing system built on Google **Managed Agents**. A cloud agent
ingests a document, classifies which spans are sensitive (PII / financial / medical), and
routes **only the sensitive spans** — in one consolidated call — to a **Gemma model running
locally** on the operator's NVIDIA DGX Spark (Ollama, exposed via an allowlisted tunnel).
Non-sensitive spans are processed in the cloud sandbox. The run produces a **PDF report**
and an **`audit-log.json`** that proves, line by line, what touched cloud vs. local — with
`raw_sensitive_bytes_to_cloud: 0`.

## Why this is a Managed Agents showcase

Built entirely on the new Managed Agents primitives:

| Primitive | How Sentinel uses it |
|---|---|
| `AGENTS.md` | Defines the classifier-router behavior and the hard privacy rules. |
| 3 × `SKILL.md` | `pii-classifier`, `gemma-router`, `pdf-generator`. |
| `code_execution` | The only tool. Classification, the local POST, and reporting all run as sandboxed Python. |
| **Network allowlist + header transform** | The sandbox may reach **only** the operator's local endpoint; the egress proxy injects `Authorization` so the credential never enters the sandbox. |
| Environment `sources` | `AGENTS.md`, the three skills, a stdlib helper, and the input doc are mounted inline. |
| File artifacts | `audit-log.json` is emitted as the run's evidence artifact. |

There is intentionally **no** function-calling or MCP tool: routing to the local model
happens inside a `code_execution` script (a POST to the allowlisted endpoint), which is
exactly what makes the egress-proxy header injection the security boundary.

## Architecture

```
 Next.js UI ──upload──▶ FastAPI (SSE) ──▶ Managed Agent interaction (cloud sandbox)
                                              │  AGENTS.md + 3 skills + code_execution
                                              │
              classify spans (cloud) ─────────┤
                                              │  sensitive spans, ONE consolidated POST
                                              ▼  (egress proxy injects Authorization)
                                   ┌─────────────────────────┐
                                   │  DGX Spark (local)      │
                                   │  auth_proxy → Ollama    │
                                   │  gemma4:31b             │
                                   └─────────────────────────┘
                                              │ safe redacted derivatives only
                                              ▼
                          report.pdf + audit-log.json  (raw_sensitive_bytes_to_cloud: 0)
```

## Layout

- `AGENTS.md` — agent behavior + privacy contract.
- `agent/skills/*` — the three `SKILL.md` procedures.
- `agent/tools/sentinel_local.py` — stdlib helper mounted into the sandbox (redact, hash,
  event emit, one consolidated local call). Runnable standalone for self-tests.
- `backend/` — FastAPI orchestrator driving the interaction and streaming events (SSE).
- `local-gateway/auth_proxy.py` — bearer-token gate the operator runs in front of Ollama.
- `web/` — Next.js demo (upload → live cloud/local routing → download PDF + audit log).

## Status

All code is created during the Google I/O hackathon. Test data is synthetic
(`backend/data/synthetic_intake.md`) — no real personal data.
