"""
Attack Module: Expired Token Extension (exp bypass).

Tab 1 (no query param): signature checked, exp NOT checked.
Tab 2 (?mode=nosig):    neither signature nor exp checked.
Patched: verifies signature AND checks exp.

Known secret: 'expsecret' (intentionally disclosed for pedagogy).
"""
from __future__ import annotations

import time
import jwt
from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse

from jwtlab.attacks.models import ModuleState, LoginReq, VerifyReq, TogglePatchResp

router = APIRouter()
state = ModuleState(slug="exp-bypass")

_SECRET = "expsecret"   # intentionally published as part of the lesson
_ALGORITHM = "HS256"


@router.post("/login")
async def login(req: LoginReq) -> dict:
    payload = {
        "sub": req.username,
        "role": "user",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
    }
    return {"token": jwt.encode(payload, _SECRET, algorithm=_ALGORITHM)}


@router.post("/verify")
async def verify(req: VerifyReq, mode: str = Query(default="")) -> JSONResponse:
    if state.patched:
        # Patched: verify signature AND check exp
        try:
            claims = jwt.decode(req.token, _SECRET, algorithms=[_ALGORITHM])
            return JSONResponse({"valid": True, "claims": claims, "message": "Token verified."})
        except jwt.ExpiredSignatureError:
            return JSONResponse(status_code=401,
                                content={"valid": False, "claims": {}, "message": "Token expired."})
        except jwt.InvalidSignatureError:
            return JSONResponse(status_code=401,
                                content={"valid": False, "claims": {},
                                         "message": "Invalid signature."})
        except jwt.PyJWTError as exc:
            return JSONResponse(status_code=401,
                                content={"valid": False, "claims": {}, "message": str(exc)})

    if mode == "nosig":
        # Tab 2: neither signature nor exp checked
        try:
            claims = jwt.decode(
                req.token, options={"verify_signature": False, "verify_exp": False},
                algorithms=["HS256", "HS384", "HS512", "RS256", "none"],
            )
            return JSONResponse(
                {"valid": True, "claims": claims,
                 "message": "Token accepted (no signature or exp check — tab-2 mode)."}
            )
        except jwt.PyJWTError as exc:
            return JSONResponse(status_code=400,
                                content={"valid": False, "claims": {}, "message": str(exc)})
    else:
        # Tab 1 (default): signature checked, exp NOT checked
        try:
            claims = jwt.decode(
                req.token, _SECRET, algorithms=[_ALGORITHM],
                options={"verify_exp": False},
            )
            return JSONResponse(
                {"valid": True, "claims": claims,
                 "message": "Token accepted (signature verified; exp not checked — tab-1 mode)."}
            )
        except jwt.PyJWTError as exc:
            return JSONResponse(status_code=401,
                                content={"valid": False, "claims": {}, "message": str(exc)})


@router.post("/toggle-patch", response_model=TogglePatchResp)
async def toggle_patch() -> TogglePatchResp:
    state.patched = not state.patched
    return TogglePatchResp(patched=state.patched)
