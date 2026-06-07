"""
Attack Module: jku / jwk Header Injection.

jku-fetch path: server fetches JWKS from the jku header URL (no domain allowlist).
jwk-embed path: server trusts an inline `jwk` header claim.
Patched: domain allowlist for jku; reject jwk embeds.

Uses httpx.AsyncClient for the jku-fetch outbound call to prevent event loop deadlock.
"""
from __future__ import annotations

import json
import threading
import time
from typing import Optional

import jwt
import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from jwtlab.attacks.models import ModuleState, LoginReq, VerifyReq, TogglePatchResp

router = APIRouter()
state = ModuleState(slug="jku-injection")

# ─── Lazy RSA key generation (DISTINCT from alg-confusion keypair) ─────────────
_lock = threading.Lock()
_server_private_key: Optional[rsa.RSAPrivateKey] = None   # legitimate server key
_attacker_private_key: Optional[rsa.RSAPrivateKey] = None  # attacker-controlled key


def _get_or_generate_keys():
    global _server_private_key, _attacker_private_key
    if _server_private_key is not None:
        return _server_private_key, _attacker_private_key
    with _lock:
        if _server_private_key is not None:
            return _server_private_key, _attacker_private_key
        _server_private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        _attacker_private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
    return _server_private_key, _attacker_private_key


def _pem(key) -> bytes:
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _private_pem(key) -> bytes:
    # PKCS#8 format (BEGIN PRIVATE KEY) is required by SubtleCrypto / jose importPKCS8
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _build_jwks(public_key) -> dict:
    """Build a minimal JWK Set from an RSA public key (private or public accepted)."""
    import base64
    # Accept either private key (extract public) or already-public key
    pub = public_key.public_key() if hasattr(public_key, "private_bytes") else public_key
    # Build JWK manually from public numbers (cryptography >= 2.6)
    pub_nums = pub.public_numbers()
    n_bytes = pub_nums.n.to_bytes((pub_nums.n.bit_length() + 7) // 8, "big")
    e_bytes = pub_nums.e.to_bytes((pub_nums.e.bit_length() + 7) // 8, "big")
    jwk_obj = {
        "kty": "RSA",
        "use": "sig",
        "kid": "attacker-key",
        "alg": "RS256",
        "n": base64.urlsafe_b64encode(n_bytes).rstrip(b"=").decode(),
        "e": base64.urlsafe_b64encode(e_bytes).rstrip(b"=").decode(),
    }
    return {"keys": [jwk_obj]}


# ─── Attacker JWKS endpoint ────────────────────────────────────────────────────

@router.get("/attacker-jwks")
async def attacker_jwks() -> dict:
    _, attacker_key = _get_or_generate_keys()
    return _build_jwks(attacker_key)


@router.get("/attacker-private-key")
async def attacker_private_key(request: Request) -> dict:
    _, attacker_key = _get_or_generate_keys()
    host = request.headers.get("host", f"127.0.0.1:{request.url.port or 8765}")
    scheme = request.url.scheme or "http"
    suggested_jku_url = (
        f"{scheme}://{host}/api/v1/attack/jku-injection/attacker-jwks"
    )
    return {
        "privateKeyPem": _private_pem(attacker_key).decode(),
        "suggestedJkuUrl": suggested_jku_url,
    }


# ─── Login ─────────────────────────────────────────────────────────────────────

@router.post("/login")
async def login(req: LoginReq) -> dict:
    server_key, _ = _get_or_generate_keys()
    payload = {
        "sub": req.username,
        "role": "user",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
    }
    token = jwt.encode(payload, server_key, algorithm="RS256",
                       headers={"kid": "server-key"})
    return {"token": token}


# ─── Verify ────────────────────────────────────────────────────────────────────

@router.post("/verify")
async def verify(req: VerifyReq) -> JSONResponse:
    server_key, _ = _get_or_generate_keys()
    server_pub_pem = _pem(server_key)

    try:
        header_data = jwt.get_unverified_header(req.token)
    except jwt.PyJWTError as exc:
        return JSONResponse(status_code=400,
                            content={"valid": False, "claims": {}, "message": str(exc)})

    jku = header_data.get("jku")
    jwk_claim = header_data.get("jwk")

    # ── Patched mode ──────────────────────────────────────────────────────────
    if state.patched:
        if jwk_claim:
            return JSONResponse(
                status_code=401,
                content={"valid": False, "claims": {},
                         "message": "Inline jwk header not permitted."},
            )
        if jku:
            return JSONResponse(
                status_code=401,
                content={"valid": False, "claims": {},
                         "message": "jku domain not in allowlist."},
            )
        # Normal RS256 verification
        try:
            claims = jwt.decode(req.token, server_pub_pem, algorithms=["RS256"])
            return JSONResponse({"valid": True, "claims": claims, "message": "Token verified."})
        except jwt.PyJWTError as exc:
            return JSONResponse(status_code=401,
                                content={"valid": False, "claims": {}, "message": str(exc)})

    # ── Vulnerable mode ───────────────────────────────────────────────────────
    if jwk_claim:
        # jwk-embed path: use the inline JWK as the verification key
        try:
            from cryptography.hazmat.primitives.serialization import load_der_public_key
            import base64
            # Reconstruct public key from JWK
            n_int = int.from_bytes(
                base64.urlsafe_b64decode(jwk_claim["n"] + "=="), "big"
            )
            e_int = int.from_bytes(
                base64.urlsafe_b64decode(jwk_claim["e"] + "=="), "big"
            )
            from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
            pub_key = RSAPublicNumbers(e_int, n_int).public_key(default_backend())
            pub_pem = pub_key.public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            )
            claims = jwt.decode(req.token, pub_pem, algorithms=["RS256"])
            claims["role"] = "admin"
            return JSONResponse(
                {"valid": True, "claims": claims,
                 "message": "Token accepted (jwk-embed path — attacker key trusted)."}
            )
        except Exception as exc:
            return JSONResponse(status_code=401,
                                content={"valid": False, "claims": {}, "message": str(exc)})

    elif jku:
        # jku-fetch path: fetch JWKS from the jku URL using httpx.AsyncClient
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(jku)
                resp.raise_for_status()
                jwks = resp.json()

            keys = jwks.get("keys", [])
            if not keys:
                return JSONResponse(status_code=401,
                                    content={"valid": False, "claims": {},
                                             "message": "No keys found in JWK Set."})

            # Try each key in the set
            for jwk_obj in keys:
                try:
                    import base64
                    n_int = int.from_bytes(
                        base64.urlsafe_b64decode(jwk_obj["n"] + "=="), "big"
                    )
                    e_int = int.from_bytes(
                        base64.urlsafe_b64decode(jwk_obj["e"] + "=="), "big"
                    )
                    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
                    pub_key = RSAPublicNumbers(e_int, n_int).public_key(default_backend())
                    pub_pem = pub_key.public_bytes(
                        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
                    )
                    claims = jwt.decode(req.token, pub_pem, algorithms=["RS256"])
                    claims["role"] = "admin"
                    return JSONResponse(
                        {"valid": True, "claims": claims,
                         "message": "Token accepted (jku-fetch path — attacker key trusted)."}
                    )
                except Exception:
                    continue

            return JSONResponse(status_code=401,
                                content={"valid": False, "claims": {},
                                         "message": "No matching key found in fetched JWK Set."})

        except httpx.HTTPError as exc:
            return JSONResponse(status_code=401,
                                content={"valid": False, "claims": {},
                                         "message": f"Failed to fetch JWK Set: {exc}"})

    else:
        # Normal RS256 path
        try:
            claims = jwt.decode(req.token, server_pub_pem, algorithms=["RS256"])
            return JSONResponse({"valid": True, "claims": claims, "message": "Token verified."})
        except jwt.PyJWTError as exc:
            return JSONResponse(status_code=401,
                                content={"valid": False, "claims": {}, "message": str(exc)})


@router.post("/toggle-patch", response_model=TogglePatchResp)
async def toggle_patch() -> TogglePatchResp:
    state.patched = not state.patched
    return TogglePatchResp(patched=state.patched)
