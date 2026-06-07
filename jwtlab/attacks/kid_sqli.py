"""
Attack Module: kid SQL Injection.

Vulnerable: concatenates `kid` into a SQLite query — UNION SELECT injection possible.
Patched:    uses parameterized query; injection treated as literal kid.

Uses an in-memory SQLite `:memory:` database instantiated at startup.
No files are written to disk.
"""
from __future__ import annotations

import sqlite3
import time
import jwt
from fastapi import APIRouter
from fastapi.responses import JSONResponse

from jwtlab.attacks.models import ModuleState, LoginReq, VerifyReq, TogglePatchResp

router = APIRouter()
state = ModuleState(slug="kid-sqli")

_ALGORITHM = "HS256"
_DEFAULT_KID = "main-key"
_DEFAULT_SECRET = "kid-sqli-main-secret"

# ─── In-memory SQLite key store ────────────────────────────────────────────────
_db: sqlite3.Connection = sqlite3.connect(":memory:", check_same_thread=False)

def _init_db() -> None:
    """Seed the in-memory SQLite with one legitimate key entry."""
    _db.execute(
        "CREATE TABLE IF NOT EXISTS signing_keys (kid TEXT PRIMARY KEY, secret TEXT NOT NULL)"
    )
    _db.execute(
        "INSERT OR IGNORE INTO signing_keys (kid, secret) VALUES (?, ?)",
        (_DEFAULT_KID, _DEFAULT_SECRET),
    )
    _db.commit()

_init_db()


def _lookup_key_vulnerable(kid: str) -> str | None:
    """Vulnerable: kid is concatenated directly into SQL."""
    query = f"SELECT secret FROM signing_keys WHERE kid = '{kid}'"
    try:
        cursor = _db.execute(query)
        row = cursor.fetchone()
        return row[0] if row else None
    except sqlite3.Error:
        return None


def _lookup_key_patched(kid: str) -> str | None:
    """Patched: parameterized query — kid is treated as a literal value."""
    cursor = _db.execute("SELECT secret FROM signing_keys WHERE kid = ?", (kid,))
    row = cursor.fetchone()
    return row[0] if row else None


@router.post("/login")
async def login(req: LoginReq) -> dict:
    payload = {
        "sub": req.username,
        "role": "user",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
    }
    token = jwt.encode(payload, _DEFAULT_SECRET, algorithm=_ALGORITHM,
                       headers={"kid": _DEFAULT_KID})
    return {"token": token}


@router.post("/verify")
async def verify(req: VerifyReq) -> JSONResponse:
    try:
        header_data = jwt.get_unverified_header(req.token)
    except jwt.PyJWTError as exc:
        return JSONResponse(status_code=400,
                            content={"valid": False, "claims": {}, "message": str(exc)})

    kid = header_data.get("kid", _DEFAULT_KID)

    if state.patched:
        secret = _lookup_key_patched(kid)
    else:
        secret = _lookup_key_vulnerable(kid)

    if secret is None:
        return JSONResponse(status_code=401,
                            content={"valid": False, "claims": {},
                                     "message": "No matching key found for kid."})

    try:
        claims = jwt.decode(req.token, secret, algorithms=[_ALGORITHM])
        return JSONResponse({"valid": True, "claims": claims, "message": "Token accepted."})
    except jwt.PyJWTError as exc:
        return JSONResponse(status_code=401,
                            content={"valid": False, "claims": {}, "message": str(exc)})


@router.post("/toggle-patch", response_model=TogglePatchResp)
async def toggle_patch() -> TogglePatchResp:
    state.patched = not state.patched
    return TogglePatchResp(patched=state.patched)
