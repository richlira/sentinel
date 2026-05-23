"""Sentinel API — FastAPI + SSE.

POST /api/analyze   multipart file (optional) -> Server-Sent Events stream of the run.
GET  /api/synthetic returns the built-in synthetic document.
GET  /api/artifacts/{run_id}/{name}  serves report.pdf / audit-log.json.

The SSE event shape is identical whether the run is driven by the cloud agent
(orchestrator) or the local fallback pipeline, so the UI is mode-agnostic.
"""

from __future__ import annotations

import json
import os
import uuid
from typing import Iterator

from fastapi import FastAPI, File, UploadFile, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse, JSONResponse

import pipeline
import orchestrator

HERE = os.path.dirname(os.path.abspath(__file__))
RUNS_DIR = os.path.join(HERE, "runs")
SYNTHETIC = os.path.join(HERE, "data", "synthetic_intake.md")

app = FastAPI(title="Sentinel", version="1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def _sse(event: dict) -> str:
    return f"data: {json.dumps(event)}\n\n"


def _artifact_urls(run_id: str, event: dict) -> dict:
    """Rewrite local artifact paths to downloadable URLs for the UI."""
    return {
        "phase": "report",
        "audit_log": f"/api/artifacts/{run_id}/audit-log.json",
        "pdf": f"/api/artifacts/{run_id}/report.pdf",
    }


def _run_stream(text: str, document: str, mode: str) -> Iterator[str]:
    run_id = uuid.uuid4().hex[:12]
    outdir = os.path.join(RUNS_DIR, run_id)
    yield _sse({"phase": "run", "run_id": run_id, "mode_requested": mode})

    gen = None
    if mode == "agent":
        try:
            gen = orchestrator.run_agent_pipeline(text, outdir, document=document)
            first = next(gen)            # forces the create() call / quota check
            yield _sse(first)
        except orchestrator.AgentUnavailable as exc:
            yield _sse({"phase": "notice",
                        "message": f"Cloud agent unavailable ({exc}); using local pipeline."})
            gen = None

    if gen is None:
        gen = pipeline.run_local_pipeline(text, outdir, document=document)

    try:
        for event in gen:
            if event.get("phase") == "report":
                event = _artifact_urls(run_id, event)
            elif event.get("phase") == "done":
                event = {"phase": "done", "summary": event.get("summary", {})}
            yield _sse(event)
    except Exception as exc:  # noqa: BLE001 - report failures to the client
        yield _sse({"phase": "error", "message": str(exc)})


@app.get("/api/synthetic")
def synthetic() -> JSONResponse:
    with open(SYNTHETIC) as fh:
        return JSONResponse({"document": "synthetic_intake.md", "text": fh.read()})


@app.post("/api/analyze")
async def analyze(
    file: UploadFile | None = File(default=None),
    mode: str = Query(default="local", pattern="^(local|agent)$"),
) -> StreamingResponse:
    if file is not None:
        text = (await file.read()).decode("utf-8", errors="replace")
        document = file.filename or "upload.md"
    else:
        with open(SYNTHETIC) as fh:
            text = fh.read()
        document = "synthetic_intake.md"
    return StreamingResponse(
        _run_stream(text, document, mode),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/api/artifacts/{run_id}/{name}")
def artifact(run_id: str, name: str):
    safe = os.path.basename(name)
    path = os.path.join(RUNS_DIR, os.path.basename(run_id), safe)
    if not os.path.exists(path):
        return JSONResponse({"error": "not found"}, status_code=404)
    media = "application/pdf" if safe.endswith(".pdf") else "application/json"
    return FileResponse(path, media_type=media, filename=safe)


@app.get("/api/health")
def health() -> dict:
    return {"ok": True}
