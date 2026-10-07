"""Sleuth web app: one page, one streaming endpoint."""

from __future__ import annotations

import json
import time
from collections import defaultdict, deque
from pathlib import Path

from fastapi import FastAPI, Query, Request
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from . import scan

STATIC = Path(__file__).resolve().parent.parent / "static"
app = FastAPI(title="Sleuth", docs_url=None, redoc_url=None)

# Fresh scans hit a dozen public APIs; keep one visitor from burning everyone's quota.
FRESH_PER_10_MIN = 8
_recent: dict[str, deque] = defaultdict(deque)


def _allow(ip: str) -> bool:
    now = time.time()
    q = _recent[ip]
    while q and now - q[0] > 600:
        q.popleft()
    if len(q) >= FRESH_PER_10_MIN:
        return False
    q.append(now)
    return True


def _sse(events):
    async def gen():
        async for e in events:
            yield f"data: {json.dumps(e)}\n\n"
    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.get("/api/scan")
async def api_scan(request: Request, q: str = Query(..., max_length=120), fresh: bool = False):
    t = scan.parse_target(q)
    if not t:
        return JSONResponse({"error": "Enter a domain like example.com, or a username like octocat."}, status_code=400)
    cached = None if fresh else scan.cached_events(t)
    if cached:
        return _sse(scan.replay(cached))
    ip = (request.headers.get("x-forwarded-for") or (request.client.host if request.client else "?")).split(",")[0].strip()
    if not _allow(ip):
        return JSONResponse({"error": "That's a lot of scans. Give it a few minutes, then try again."}, status_code=429)
    return _sse(scan.run(t))


@app.get("/healthz")
async def healthz():
    return {"ok": True}


@app.get("/")
async def index():
    return FileResponse(STATIC / "index.html")


app.mount("/", StaticFiles(directory=STATIC), name="static")
