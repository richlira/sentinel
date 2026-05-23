"""Heuristic span classifier.

The authoritative classification is done by the cloud agent (per the pii-classifier
skill). This module is the local equivalent: it drives the self-test pipeline and is the
fallback path when the cloud agent is unavailable. Same span shape either way:

    {"id": "s3", "category": "financial", "text": "...", "destination": "local-gemma"}
"""

from __future__ import annotations

import re

SENSITIVE = {"pii", "financial", "medical"}

_PATTERNS = [
    # (category, compiled regex) — order matters; first match wins.
    ("financial", re.compile(r"\b(routing|account|balance|income|visa|mastercard|card|iban)\b", re.I)),
    ("financial", re.compile(r"\b\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b")),   # card
    ("financial", re.compile(r"\$\s?\d")),                                    # money
    ("medical", re.compile(r"\b(diagnos|icd-?10|hba1c|mg\b|medication|metformin|sertraline|mellitus|disorder)\b", re.I)),
    ("pii", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),                            # SSN
    ("pii", re.compile(r"\b(ssn|social security|date of birth|dob)\b", re.I)),
    ("pii", re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+")),                          # email
    ("pii", re.compile(r"\(?\d{3}\)?[ .-]?\d{3}[ .-]?\d{4}")),                # phone
    ("pii", re.compile(r"\b\d{3,5}\s+\w+(\s+\w+)*\s+(lane|street|st|ave|avenue|road|rd|blvd)\b", re.I)),
    ("pii", re.compile(r"\b(full name|home address|email|mobile|member id)\b", re.I)),
]


def _classify_line(line: str) -> str:
    for category, pattern in _PATTERNS:
        if pattern.search(line):
            return category
    return "non_sensitive"


def classify_document(text: str) -> list[dict]:
    """Split a markdown document into classifiable spans (one per meaningful line)."""
    spans: list[dict] = []
    n = 0
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ">", "```")):
            continue  # headings / callouts / fences are structure, not data
        # Strip list/bullet markers for cleaner spans, keep the content.
        content = re.sub(r"^[-*]\s+", "", line)
        if len(content) < 3:
            continue
        category = _classify_line(content)
        n += 1
        spans.append({
            "id": f"s{n}",
            "category": category,
            "text": content,
            "destination": "local-gemma" if category in SENSITIVE else "cloud-sandbox",
        })
    return spans
