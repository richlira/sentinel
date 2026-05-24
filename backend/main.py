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
from contextlib import asynccontextmanager
from typing import Iterator

from fastapi import FastAPI, File, UploadFile, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse, JSONResponse
from starlette.concurrency import run_in_threadpool

import envcfg
import pipeline
import orchestrator
import localfirst
import sentinel_local

envcfg.load_env()

HERE = os.path.dirname(os.path.abspath(__file__))
RUNS_DIR = os.path.join(HERE, "runs")
SYNTHETIC = os.path.join(HERE, "data", "synthetic_intake.md")

@asynccontextmanager
async def lifespan(_app: FastAPI):
    # Warm the local model so the first real request isn't paying cold-start latency.
    try:
        sentinel_local.warm_up()
    except Exception:
        pass
    yield


app = FastAPI(title="Sentinel", version="1.0", lifespan=lifespan)
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
    if mode == "localfirst":
        gen = localfirst.run_localfirst_pipeline(text, outdir, document=document)
    elif mode == "agent":
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
                event = {"phase": "done", "summary": event.get("summary", {}),
                         **({"interaction_id": event["interaction_id"]} if event.get("interaction_id") else {}),
                         **({"session_id": event["session_id"]} if event.get("session_id") else {})}
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
    mode: str = Query(default="localfirst", pattern="^(localfirst|local|agent)$"),
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


@app.post("/api/chat")
async def chat(request: Request) -> JSONResponse:
    body = await request.json()
    interaction_id = body.get("interaction_id")
    message = body.get("message", "")
    if not interaction_id or not message:
        return JSONResponse({"error": "interaction_id and message required"}, status_code=400)
    try:
        # Run the blocking agent call off the event loop so it never freezes the server.
        result = await run_in_threadpool(
            localfirst.continue_interaction, interaction_id, message, body.get("session_id"))
        return JSONResponse(result)
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=500)


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
