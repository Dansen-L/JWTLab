"""
Attack Module: Weak Secret Brute-force.

The endpoint is signed with the intentionally weak secret 'secret'.
POST /api/v1/crack brute-forces it from a wordlist.
"""
from __future__ import annotations

import time
import jwt
from fastapi import APIRouter
from fastapi.responses import JSONResponse

from jwtlab.attacks.models import ModuleState, LoginReq, VerifyReq, TogglePatchResp

router = APIRouter()
state = ModuleState(slug="weak-secret")

_SECRET = "secret"   # intentionally weak — this is the educational point
_ALGORITHM = "HS256"

# Patched mode uses a strong secret; tokens signed with the weak 'secret' cannot be verified
_PATCHED_SECRET = "X9kP2mQvR7nL4tWa8bD3hF6jU1sY5cE"  # strong 32-char secret for patched mode


@router.post("/login")
async def login(req: LoginReq) -> dict:
    # In patched mode, issue tokens signed with the strong secret
    signing_key = _PATCHED_SECRET if state.patched else _SECRET
    payload = {
        "sub": req.username,
        "role": "user",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
    }
    return {"token": jwt.encode(payload, signing_key, algorithm=_ALGORITHM)}


@router.post("/verify")
async def verify(req: VerifyReq) -> JSONResponse:
    if state.patched:
        # Patched: uses a strong secret — tokens signed with the weak 'secret' fail verification
        try:
            claims = jwt.decode(req.token, _PATCHED_SECRET, algorithms=[_ALGORITHM])
            return JSONResponse({"valid": True, "claims": claims, "message": "Token verified (strong secret)."})
        except jwt.PyJWTError as exc:
            return JSONResponse(status_code=401,
                                content={"valid": False, "claims": {},
                                         "message": f"Signature verification failed — weak secret tokens rejected."})
    else:
        # Vulnerable: verifies signature but the secret is crackable
        try:
            claims = jwt.decode(req.token, _SECRET, algorithms=[_ALGORITHM])
            return JSONResponse({"valid": True, "claims": claims, "message": "Token accepted."})
        except jwt.PyJWTError as exc:
            return JSONResponse(status_code=401,
                                content={"valid": False, "claims": {}, "message": str(exc)})


@router.post("/toggle-patch", response_model=TogglePatchResp)
async def toggle_patch() -> TogglePatchResp:
    state.patched = not state.patched
    return TogglePatchResp(patched=state.patched)
