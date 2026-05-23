"""Sentinel — Phase 1 smoke test (the project gate).

Proves the core loop:
  A) a trivial Managed Agent interaction works (auth + model + Api-Revision header), and
  B) the agent runs a `code_execution` script that POSTs to the local Gemma
     (ngrok) endpoint and round-trips the reply back to us.

If B passes, Sentinel's privacy-routing core is proven.

Run:  GEMINI_API_KEY=... python backend/smoke_interaction.py [--trivial|--loop]
The Api-Revision: 2026-05-20 header is injected automatically by the SDK's
interactions client, so we do not set it manually.
"""

from __future__ import annotations

import os
import sys
import textwrap

from google.genai import Client

AGENT = "antigravity-preview-05-2026"
GEMMA_BASE = "https://4390-12-94-170-82.ngrok-free.app/v1"
GEMMA_MODEL = "gemma4:31b"


def _client() -> Client:
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        sys.exit("GEMINI_API_KEY is not set")
    return Client(api_key=api_key)


def _dump_steps(interaction) -> None:
    print(f"\n  status={interaction.status}  steps={len(interaction.steps or [])}")
    for i, step in enumerate(interaction.steps or []):
        stype = getattr(step, "type", type(step).__name__)
        print(f"  [{i}] {stype}")
        # Show code-execution code + result payloads when present.
        for attr in ("arguments", "result", "content", "outcome", "output"):
            val = getattr(step, attr, None)
            if val is None:
                continue
            text = str(val)
            if len(text) > 1200:
                text = text[:1200] + "…[truncated]"
            print(textwrap.indent(f"{attr}: {text}", "        "))


def trivial(client: Client) -> None:
    print("== A) trivial interaction (no tools) ==")
    it = client.interactions.create(
        agent=AGENT,
        input="Reply with exactly: SENTINEL_TRIVIAL_OK",
        environment={"type": "remote"},
        store=True,
        timeout=120,
    )
    _dump_steps(it)
    print("\n  output_text:", repr(it.output_text))


def loop(client: Client) -> None:
    print("== B) code_execution -> local Gemma round-trip ==")
    program = f'''
import json, urllib.request
payload = {{
    "model": "{GEMMA_MODEL}",
    "messages": [{{"role": "user", "content": "Reply with exactly the token SENTINEL_LOOP_OK and nothing else."}}],
    "max_tokens": 512,
    "stream": False,
}}
req = urllib.request.Request(
    "{GEMMA_BASE}/chat/completions",
    data=json.dumps(payload).encode(),
    headers={{"Content-Type": "application/json", "ngrok-skip-browser-warning": "true"}},
    method="POST",
)
with urllib.request.urlopen(req, timeout=120) as r:
    body = json.loads(r.read().decode())
msg = body["choices"][0]["message"]
print("GEMMA_STATUS_OK")
print("CONTENT:", json.dumps(msg.get("content")))
print("REASONING_LEN:", len(msg.get("reasoning") or ""))
'''
    instruction = (
        "Use the code_execution tool to run EXACTLY the following Python program "
        "verbatim (do not modify it), then report the program's stdout in your reply:\n\n"
        f"```python\n{program}\n```"
    )
    it = client.interactions.create(
        agent=AGENT,
        input=instruction,
        tools=[{"type": "code_execution"}],
        environment={"type": "remote"},
        store=True,
        timeout=300,
    )
    _dump_steps(it)
    print("\n  output_text:", repr(it.output_text))


def main() -> None:
    client = _client()
    arg = sys.argv[1] if len(sys.argv) > 1 else "--all"
    if arg in ("--trivial", "--all"):
        trivial(client)
    if arg in ("--loop", "--all"):
        loop(client)


if __name__ == "__main__":
    main()
