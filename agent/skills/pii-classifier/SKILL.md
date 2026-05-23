---
name: pii-classifier
description: Split a document into spans and classify each as pii, financial, medical, or non_sensitive. Runs in the cloud sandbox; sees raw text only long enough to label it.
---

# Skill: pii-classifier

Decide **what is sensitive** before anything is routed. This runs in the cloud sandbox,
so it may read raw text to classify it, but it must never *emit* raw sensitive values.

## Procedure (via code_execution)

1. Read `/workspace/input.md`.
2. Split into spans. A span is a line or labeled field (e.g. a `- key: value` bullet, a
   section heading, or a paragraph). Keep spans small enough that a single span maps to a
   single sensitivity decision.
3. Classify each span into exactly one category:
   - `pii` — names, dates of birth, SSNs/tax IDs, home addresses, personal phone/email.
   - `financial` — bank routing/account numbers, card numbers, balances, income.
   - `medical` — diagnoses, ICD codes, medications, lab results.
   - `non_sensitive` — clinic hours, policy boilerplate, public scheduling info.
4. For every span, emit one event:

   ```python
   from tools.sentinel_local import emit, redact, sha256
   emit({
       "phase": "classify",
       "span_id": span_id,            # "s1", "s2", ...
       "category": category,          # pii | financial | medical | non_sensitive
       "destination": "local-gemma" if category != "non_sensitive" else "cloud-sandbox",
       "preview": redact(text),       # NEVER the raw value
       "sha256": sha256(text),
   })
   ```

## Output

Produce a Python list `spans = [{"id", "category", "text", "destination"}, ...]` held in
memory for the next skill. `text` (raw) stays in memory only; it is never emitted.

## Rules

- Default to **more** sensitive when unsure (route to local rather than leak).
- Never print raw `text`. Only `redact(text)` and `sha256(text)` may leave this step.
