"""Minimal stdlib .env loader (no python-dotenv dependency).

Reads KEY=VALUE lines from the repo-root .env and sets them in os.environ WITHOUT
overriding values already present (so a shell-exported GEMINI_API_KEY wins).
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
            os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))
