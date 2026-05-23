"""Minimal stdlib .env loader (no python-dotenv dependency).

Reads KEY=VALUE lines from the repo-root .env and makes them authoritative for this
process: the project .env wins over inherited shell env (so the agent uses the key that
has antigravity quota, not whatever happens to be exported globally).
"""

from __future__ import annotations

import os

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_env(path: str | None = None) -> None:
    path = path or os.path.join(_ROOT, ".env")
    if not os.path.exists(path):
        return
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            os.environ[key.strip()] = value.strip().strip('"').strip("'")
