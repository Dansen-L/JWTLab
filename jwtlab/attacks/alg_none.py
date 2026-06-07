"""
Attack Module: alg=none bypass.

Vulnerable: accepts tokens with alg='none' and no signature.
Patched:    rejects any algorithm not in the RS256 allowlist.
"""
from __future__ import annotations

import time
import jwt  # PyJWT
from fastapi import APIRouter
from fastapi.responses import JSONResponse

from jwtlab.attacks.models import ModuleState, LoginReq, VerifyReq, TogglePatchResp

router = APIRouter()
state = ModuleState(slug="alg-none")

_SECRET = "hs256-alg-none-demo-secret"
_ALGORITHM = "HS256"


@router.post("/login")
async def login(req: LoginReq) -> dict:
    payload = {
        "sub": req.username,
        "role": "user",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
    }
    token = jwt.encode(payload, _SECRET, algorithm=_ALGORITHM)
    return {"token": token}


@router.post("/verify")
async def verify(req: VerifyReq) -> JSONResponse:
    if state.patched:
        # Patched: enforce HS256 only via PyJWT (algorithm pinned)
        try:
            claims = jwt.decode(req.token, _SECRET, algorithms=[_ALGORITHM])
            return JSONResponse({"valid": True, "claims": claims, "message": "Token verified."})
        except jwt.exceptions.InvalidAlgorithmError:
            return JSONResponse(status_code=401,
                                content={"valid": False, "claims": {}, "message": "Algorithm not permitted."})
        except jwt.PyJWTError as exc:
            return JSONResponse(status_code=401,
                                content={"valid": False, "claims": {}, "message": str(exc)})
    else:
        # Vulnerable: trust alg header — accept 'none' algorithm
        try:
            header_data = jwt.get_unverified_header(req.token)
            alg = header_data.get("alg", "").lower()
            if alg == "none":
                # Accept without verification
                claims = jwt.decode(req.token, options={"verify_signature": False},
                                    algorithms=["none", "HS256", "RS256"])
                claims["role"] = "admin"  # demonstrate privilege escalation
                return JSONResponse({"valid": True, "claims": claims,
                                     "message": "Token accepted (alg=none — no signature required)."})
            else:
                claims = jwt.decode(req.token, _SECRET, algorithms=[_ALGORITHM])
                return JSONResponse({"valid": True, "claims": claims, "message": "Token verified."})
        except jwt.PyJWTError as exc:
            return JSONResponse(status_code=401,
                                content={"valid": False, "claims": {}, "message": str(exc)})


@router.post("/toggle-patch", response_model=TogglePatchResp)
async def toggle_patch() -> TogglePatchResp:
    state.patched = not state.patched
    return TogglePatchResp(patched=state.patched)
