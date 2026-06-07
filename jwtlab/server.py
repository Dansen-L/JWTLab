"""
JWTLab FastAPI server.

Exposes:
  GET  /api/v1/health
  GET  /api/v1/modules
  POST /api/v1/analyze
  POST /api/v1/crack
  POST /api/v1/attack/{module}/login
  POST /api/v1/attack/{module}/verify
  POST /api/v1/attack/{module}/toggle-patch
  GET  /api/v1/attack/alg-confusion/public-key
  GET  /api/v1/attack/jku-injection/attacker-jwks
  GET  /api/v1/attack/jku-injection/attacker-private-key
  GET  /api/v1/attack/jku-injection/attacker-jwks          (served as public JWKS)

Also serves the pre-built React frontend from jwtlab/static/ on all other paths.
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any, List, Optional

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel


# ─── Request/Response models (module-level for FastAPI introspection) ──────────

class AnalyzeRequest(BaseModel):
    token: str


class CrackRequest(BaseModel):
    token: str
    wordlist: List[str] = []

from jwtlab import __version__
from jwtlab.analyzer import analyze_token, AnalysisError

# ─── Attack module routers ─────────────────────────────────────────────────────
from jwtlab.attacks.alg_none import router as alg_none_router
from jwtlab.attacks.alg_confusion import router as alg_confusion_router
from jwtlab.attacks.weak_secret import router as weak_secret_router
from jwtlab.attacks.kid_sqli import router as kid_sqli_router
from jwtlab.attacks.jku_injection import router as jku_injection_router
from jwtlab.attacks.exp_bypass import router as exp_bypass_router

# ─── Module registry ───────────────────────────────────────────────────────────
# Import the patch-state objects from each module
from jwtlab.attacks.alg_none import state as alg_none_state
from jwtlab.attacks.alg_confusion import state as alg_confusion_state
from jwtlab.attacks.weak_secret import state as weak_secret_state
from jwtlab.attacks.kid_sqli import state as kid_sqli_state
from jwtlab.attacks.jku_injection import state as jku_injection_state
from jwtlab.attacks.exp_bypass import state as exp_bypass_state

MODULE_REGISTRY = [
    {"slug": "alg-none",        "title": "alg=none Bypass",                        "state": alg_none_state},
    {"slug": "alg-confusion",   "title": "Algorithm Confusion (RS256 → HS256)",     "state": alg_confusion_state},
    {"slug": "weak-secret",     "title": "Weak Secret Brute-force",                 "state": weak_secret_state},
    {"slug": "kid-sqli",        "title": "Key ID SQL Injection",                    "state": kid_sqli_state},
    {"slug": "jku-injection",   "title": "jku / jwk Header Injection",              "state": jku_injection_state},
    {"slug": "exp-bypass",      "title": "Expired Token Extension (exp bypass)",    "state": exp_bypass_state},
]

STATIC_DIR = Path(__file__).parent / "static"


def create_app() -> FastAPI:
    application = FastAPI(title="JWTLab API", version=__version__, docs_url="/api/docs")

    # ── CORS (dev: allow 5173; prod: same-origin at 8765) ─────────────────────
    application.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            "http://localhost:8765",
            "http://127.0.0.1:8765",
        ],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── Core routes ───────────────────────────────────────────────────────────
    @application.get("/api/v1/health")
    async def health() -> dict:
        return {"status": "ok", "version": __version__}

    @application.get("/api/v1/modules")
    async def modules() -> list[dict]:
        return [
            {
                "slug": m["slug"],
                "title": m["title"],
                "patched": m["state"].patched,
            }
            for m in MODULE_REGISTRY
        ]

    # ── Analyze ───────────────────────────────────────────────────────────────
    @application.post("/api/v1/analyze")
    async def analyze(req: AnalyzeRequest) -> dict:
        if not req.token:
            return JSONResponse(status_code=400, content={"error": "token is required"})
        try:
            return analyze_token(req.token)
        except AnalysisError as exc:
            return JSONResponse(status_code=400, content={"error": str(exc)})

    # ── Crack ─────────────────────────────────────────────────────────────────
    # Built-in 50-word default; 'secret' is at position ≥ 10 (1-indexed)
    _BUILTIN_WORDLIST = [
        "password", "admin", "123456", "letmein", "qwerty", "dragon",
        "monkey", "welcome", "shadow", "master", "secret", "abc123",
        "football", "superman", "iloveyou", "trustno1", "sunshine",
        "princess", "baseball", "mustang", "access", "696969", "batman",
        "passw0rd", "michael", "000000", "login", "hello", "charlie",
        "donald", "password1", "1234", "cheese", "nintendo", "samsung",
        "hunter", "freedom", "computer", "corvette", "cookie", "joshua",
        "ashley", "jessica", "123abc", "test", "root", "toor", "guest",
        "changeme", "qazwsx",
    ]

    @application.post("/api/v1/crack")
    async def crack(req: CrackRequest) -> dict:
        import hmac
        import hashlib
        import base64

        # Use built-in wordlist when client sends none
        wordlist = req.wordlist if req.wordlist else _BUILTIN_WORDLIST

        # Validate wordlist length (spec: max 10,000 entries)
        if len(wordlist) > 10_000:
            return JSONResponse(
                status_code=422,
                content={"detail": "wordlist exceeds 10,000 entry limit"},
            )

        parts = req.token.split(".")
        if len(parts) != 3:
            return JSONResponse(status_code=400, content={"error": "invalid JWT format"})

        header_payload = f"{parts[0]}.{parts[1]}".encode()
        sig_b64 = parts[2]
        # Restore base64url padding
        padding = 4 - len(sig_b64) % 4
        if padding != 4:
            sig_b64 += "=" * padding
        try:
            expected_sig = base64.urlsafe_b64decode(sig_b64)
        except Exception:
            return JSONResponse(status_code=400, content={"error": "invalid JWT signature encoding"})

        # Determine algorithm from header
        try:
            import json as _json
            hdr_b64 = parts[0]
            hdr_b64 += "=" * (4 - len(hdr_b64) % 4)
            header = _json.loads(base64.urlsafe_b64decode(hdr_b64).decode())
            alg = header.get("alg", "").upper()
        except Exception:
            alg = "HS256"

        alg_map = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
        hash_fn = alg_map.get(alg)
        if hash_fn is None:
            return JSONResponse(
                status_code=400,
                content={"error": f"Algorithm '{alg}' is not supported for cracking. Use HS256/HS384/HS512."},
            )

        start_ms = int(time.time() * 1000)
        for i, candidate in enumerate(wordlist):
            sig = hmac.new(candidate.encode(), header_payload, hash_fn).digest()
            if hmac.compare_digest(sig, expected_sig):
                elapsed = int(time.time() * 1000) - start_ms
                return {
                    "found": True,
                    "secret": candidate,
                    "attempts": i + 1,
                    "elapsed_ms": elapsed,
                }

        elapsed = int(time.time() * 1000) - start_ms
        return {
            "found": False,
            "secret": None,
            "attempts": len(wordlist),
            "elapsed_ms": elapsed,
        }

    # ── Attack module routers ──────────────────────────────────────────────────
    application.include_router(alg_none_router,       prefix="/api/v1/attack/alg-none")
    application.include_router(alg_confusion_router,  prefix="/api/v1/attack/alg-confusion")
    application.include_router(weak_secret_router,    prefix="/api/v1/attack/weak-secret")
    application.include_router(kid_sqli_router,       prefix="/api/v1/attack/kid-sqli")
    application.include_router(jku_injection_router,  prefix="/api/v1/attack/jku-injection")
    application.include_router(exp_bypass_router,     prefix="/api/v1/attack/exp-bypass")

    # ── Serve static frontend (SPA fallback) ──────────────────────────────────
    if STATIC_DIR.exists():
        application.mount("/assets", StaticFiles(directory=str(STATIC_DIR / "assets")), name="assets")

        @application.get("/{full_path:path}", include_in_schema=False)
        async def spa_fallback(full_path: str) -> Any:
            # Return 404 for unrecognised API paths — don't serve the SPA for /api/* misses
            if full_path.startswith("api/"):
                return JSONResponse(
                    status_code=404,
                    content={"error": f"No such API endpoint: /{full_path}"},
                )
            index = STATIC_DIR / "index.html"
            if index.exists():
                return FileResponse(str(index))
            return JSONResponse(
                status_code=404,
                content={"error": "Frontend not found. Run 'npm run build' in frontend/ first."},
            )

    return application
