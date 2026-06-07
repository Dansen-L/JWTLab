"""
Attack Module: Algorithm Confusion (RS256 → HS256).

Vulnerable: trusts alg header; accepts HS256 token signed with RS256 public key bytes.
Patched:    pins algorithm to RS256 before verification.

RSA key generation: done lazily on first request to ensure /health responds quickly.
"""
from __future__ import annotations

import time
import threading
from typing import Optional

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import APIRouter
from fastapi.responses import JSONResponse

from jwtlab.attacks.models import ModuleState, LoginReq, VerifyReq, TogglePatchResp

router = APIRouter()
state = ModuleState(slug="alg-confusion")

# ─── Lazy RSA key generation ──────────────────────────────────────────────────
_rsa_lock = threading.Lock()
_private_key: Optional[rsa.RSAPrivateKey] = None
_public_key_pem: Optional[bytes] = None


def _get_or_generate_keys():
    global _private_key, _public_key_pem
    if _private_key is not None:
        return _private_key, _public_key_pem
    with _rsa_lock:
        if _private_key is not None:
            return _private_key, _public_key_pem
        _private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        _public_key_pem = _private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    return _private_key, _public_key_pem


# ─── Endpoints ────────────────────────────────────────────────────────────────

@router.post("/login")
async def login(req: LoginReq) -> dict:
    private_key, _ = _get_or_generate_keys()
    payload = {
        "sub": req.username,
        "role": "user",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
    }
    token = jwt.encode(payload, private_key, algorithm="RS256")
    return {"token": token}


@router.post("/verify")
async def verify(req: VerifyReq) -> JSONResponse:
    _, public_key_pem = _get_or_generate_keys()

    if state.patched:
        # Patched: pin algorithm to RS256
        try:
            claims = jwt.decode(req.token, public_key_pem, algorithms=["RS256"])
            return JSONResponse({"valid": True, "claims": claims, "message": "Token verified (RS256)."})
        except jwt.exceptions.InvalidAlgorithmError:
            return JSONResponse(status_code=401,
                                content={"valid": False, "claims": {},
                                         "message": "Algorithm not permitted."})
        except jwt.PyJWTError as exc:
            return JSONResponse(status_code=401,
                                content={"valid": False, "claims": {}, "message": str(exc)})
    else:
        # Vulnerable: trust alg header — if alg is HS256, verify with public key bytes as HMAC secret
        try:
            header_data = jwt.get_unverified_header(req.token)
            alg = header_data.get("alg", "RS256")
            if alg == "HS256":
                # Algorithm confusion: manually verify HS256 using public key PEM bytes as HMAC secret
                # (PyJWT 2.x rejects PEM keys as HMAC secrets, so we verify directly)
                import hmac as _hmac
                import hashlib
                import base64
                parts = req.token.split(".")
                if len(parts) != 3:
                    return JSONResponse(status_code=401,
                                        content={"valid": False, "claims": {},
                                                 "message": "Invalid token format."})
                header_payload = f"{parts[0]}.{parts[1]}".encode()
                sig_b64 = parts[2]
                padding_needed = 4 - len(sig_b64) % 4
                if padding_needed != 4:
                    sig_b64 += "=" * padding_needed
                try:
                    token_sig = base64.urlsafe_b64decode(sig_b64)
                except Exception:
                    return JSONResponse(status_code=401,
                                        content={"valid": False, "claims": {}, "message": "Invalid signature encoding."})
                expected_sig = _hmac.new(public_key_pem, header_payload, hashlib.sha256).digest()
                if not _hmac.compare_digest(token_sig, expected_sig):
                    return JSONResponse(status_code=401,
                                        content={"valid": False, "claims": {}, "message": "Signature verification failed."})
                # Decode payload
                import json as _json
                payload_b64 = parts[1]
                payload_b64 += "=" * (4 - len(payload_b64) % 4)
                claims = _json.loads(base64.urlsafe_b64decode(payload_b64).decode())
                claims["role"] = "admin"
                return JSONResponse({"valid": True, "claims": claims,
                                     "message": "Token accepted (algorithm confusion)."})
            else:
                claims = jwt.decode(req.token, public_key_pem, algorithms=["RS256"])
                return JSONResponse({"valid": True, "claims": claims, "message": "Token verified."})
        except jwt.PyJWTError as exc:
            return JSONResponse(status_code=401,
                                content={"valid": False, "claims": {}, "message": str(exc)})


@router.get("/public-key")
async def public_key() -> dict:
    _, pem = _get_or_generate_keys()
    return {"publicKeyPem": pem.decode()}


@router.post("/toggle-patch", response_model=TogglePatchResp)
async def toggle_patch() -> TogglePatchResp:
    state.patched = not state.patched
    return TogglePatchResp(patched=state.patched)
