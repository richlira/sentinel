"""Managed Agents orchestrator — the cloud path (prize centerpiece).

Runs one interaction with the `antigravity-preview-05-2026` agent. The agent's behavior
is defined by AGENTS.md and three skills, all mounted into the sandbox as inline
environment sources alongside the stdlib helper, its config, and the input document.

Privacy boundary, enforced by the platform:
  * The sandbox network is locked to a single allowlisted domain — the operator's local
    endpoint. Nothing else is reachable.
  * The `Authorization: Bearer` header is injected by the egress proxy from the allowlist
    `transform`, so the credential lives in the request config, never in sandbox code.

Discovered API shape (google-genai 2.6.0):
  client.interactions.create(agent=..., environment={type:"remote", network, sources},
                             tools=[{"type":"code_execution"}], store=True)
The `Api-Revision: 2026-05-20` header is injected automatically by the SDK.

Privacy ordering: the agent's FIRST action delegates the RAW document to the local model
(redact_document); it then operates only on the masked spans returned — never on raw.
"""

from __future__ import annotations

import json
import os
import re
from typing import Iterator
from urllib.parse import urlparse

from google.genai import Client

import envcfg
import report as report_mod

envcfg.load_env()

AGENT = "antigravity-preview-05-2026"
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SKILLS = ["local-redactor", "gemma-router", "pdf-generator"]

_EVENT_RE = re.compile(r"^SENTINEL_EVENT\s+(\{.*\})\s*$", re.M)
_AUDIT_RE = re.compile(r"SENTINEL_AUDIT_BEGIN\s*(\{.*\})\s*SENTINEL_AUDIT_END", re.S)


class AgentUnavailable(RuntimeError):
    """Raised when the cloud agent can't run (e.g. quota) so callers can fall back."""


def _read(path: str) -> str:
    with open(path) as fh:
        return fh.read()


def _local_config() -> dict:
    cfg = {"local_url": "https://4390-12-94-170-82.ngrok-free.app", "model": "gemma4:e4b"}
    path = os.path.join(_ROOT, "agent", "tools", "sentinel_config.json")
    if os.path.exists(path):
        cfg.update(json.load(open(path)))
    cfg["local_url"] = os.environ.get("NGROK_URL") or os.environ.get("SENTINEL_LOCAL_URL") or cfg["local_url"]
    cfg["model"] = os.environ.get("GEMMA_MODEL") or cfg["model"]
    return cfg


def _build_environment(text: str) -> dict:
    """Inline-mount AGENTS.md, the three skills, the helper, its config, and the input."""
    cfg = _local_config()
    sources = [
        {"type": "inline", "target": "AGENTS.md", "content": _read(os.path.join(_ROOT, "AGENTS.md"))},
        {"type": "inline", "target": "tools/__init__.py", "content": ""},
        {"type": "inline", "target": "tools/sentinel_local.py",
         "content": _read(os.path.join(_ROOT, "agent", "tools", "sentinel_local.py"))},
        {"type": "inline", "target": "tools/sentinel_config.json", "content": json.dumps(cfg)},
        {"type": "inline", "target": "input.md", "content": text},
    ]
    for name in _SKILLS:
        sources.append({
            "type": "inline", "target": f"skills/{name}/SKILL.md",
            "content": _read(os.path.join(_ROOT, "agent", "skills", name, "SKILL.md")),
        })

    host = urlparse(cfg["local_url"]).hostname
    rule = {"domain": host}
    token = os.environ.get("SENTINEL_LOCAL_TOKEN")
    if token:
        # Egress proxy injects the bearer token; it never enters sandbox code.
        rule["transform"] = [{"Authorization": f"Bearer {token}"}]
    network = {"allowlist": [rule]}
    return {"type": "remote", "network": network, "sources": sources}


_INPUT_INSTRUCTION = (
    "Follow AGENTS.md exactly. Your FIRST action must be: read input.md as raw text and pass it "
    "to tools.sentinel_local.redact_document() — the local model on the operator's hardware does "
    "the classification. Do NOT read, classify, summarize, or reason over the raw document "
    "yourself. Then operate ONLY on the masked spans it returns: emit one SENTINEL_EVENT per span "
    "and finish with the SENTINEL_AUDIT_BEGIN / SENTINEL_AUDIT_END block exactly as the "
    "pdf-generator skill specifies, with raw_sensitive_bytes_processed_in_cloud = 0."
)


def _collect_stdout(interaction) -> str:
    """Concatenate tool output (stdout) from the interaction steps.

    The antigravity agent runs code via either the `code_execution` tool
    (`code_execution_result`, `.result` is a str) or its built-in shell/python tools
    (`function_result`, `.result` is a list of {text} blocks), so handle both.
    """
    chunks = []
    for step in interaction.steps or []:
        if getattr(step, "type", None) not in ("code_execution_result", "function_result"):
            continue
        res = getattr(step, "result", None)
        if res is None:
            continue
        if isinstance(res, str):
            chunks.append(res)
        elif isinstance(res, list):
            for item in res:
                text = item.get("text") if isinstance(item, dict) else getattr(item, "text", None)
                if text:
                    chunks.append(text)
    return "\n".join(chunks)


def _extract_report(stdout: str):
    """Pull the report JSON from the LAST SENTINEL_AUDIT_BEGIN/END block that parses.

    The concatenated stdout also contains the skills' own text (which includes the literal
    marker strings as code examples), so scan from the last block backward and take the
    first one whose inner JSON object parses.
    """
    starts = [m.start() for m in re.finditer("SENTINEL_AUDIT_BEGIN", stdout)]
    for s in reversed(starts):
        body = s + len("SENTINEL_AUDIT_BEGIN")
        end = stdout.find("SENTINEL_AUDIT_END", body)
        if end == -1:
            continue
        chunk = stdout[body:end]
        b, l = chunk.find("{"), chunk.rfind("}")
        if b == -1 or l <= b:
            continue
        try:
            return json.loads(chunk[b : l + 1])
        except json.JSONDecodeError:
            continue
    return None


def run_agent_pipeline(text: str, outdir: str, document: str = "input.md") -> Iterator[dict]:
    """Run the cloud interaction and yield the parsed SENTINEL events + artifacts.

    Same event shape as pipeline.run_local_pipeline so the SSE layer is mode-agnostic.
    """
    os.makedirs(outdir, exist_ok=True)
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        raise AgentUnavailable("GEMINI_API_KEY not set")
    client = Client(api_key=api_key)

    yield {"phase": "start", "mode": "cloud-agent", "document": document}
    try:
        interaction = client.interactions.create(
            agent=AGENT,
            input=_INPUT_INSTRUCTION,
            environment=_build_environment(text),
            tools=[{"type": "code_execution"}],
            store=True,
            timeout=600,
        )
    except Exception as exc:  # noqa: BLE001 - surface quota/availability cleanly
        raise AgentUnavailable(str(exc)) from exc

    if interaction.status != "completed":
        raise AgentUnavailable(f"interaction status={interaction.status}")

    stdout = _collect_stdout(interaction)
    for match in _EVENT_RE.finditer(stdout):
        try:
            yield json.loads(match.group(1))
        except json.JSONDecodeError:
            continue

    report = _extract_report(stdout)
    if report is None:
        raise AgentUnavailable("no parseable SENTINEL_AUDIT block in agent output")

    audit_path = os.path.join(outdir, "audit-log.json")
    pdf_path = os.path.join(outdir, "report.pdf")
    report_mod.write_audit_log(report, audit_path)
    report_mod.render_pdf(report, pdf_path)
    yield {"phase": "report", "audit_log": audit_path, "pdf": pdf_path}
    yield {"phase": "done", "summary": report.get("summary", {}), "report": report}


if __name__ == "__main__":
    import sys
    src = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "data", "synthetic_intake.md")
    out = os.path.join(os.path.dirname(__file__), "runs", "agent")
    try:
        for ev in run_agent_pipeline(_read(src), out, document=os.path.basename(src)):
            print(json.dumps(ev)[:300])
    except AgentUnavailable as e:
        print(f"AGENT UNAVAILABLE: {e}")
        print("Cloud agent path is wired and ready; run again when agent quota is available.")
