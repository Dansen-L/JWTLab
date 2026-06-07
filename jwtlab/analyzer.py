"""
JWT Analyzer — decodes a JWT without verifying the signature.
Used by: POST /api/v1/analyze and `jwtlab analyze` CLI command.
"""
from __future__ import annotations

import base64
import json
import time
from typing import Any

# Header fields with known attack surface returned in dangerousFields by the API.
# alg is always flagged at CLI/UI display layers directly; it is excluded here so
# that the API dangerousFields list stays empty for standard HMAC tokens.
ALWAYS_DANGEROUS = {"kid", "jku", "x5u", "jwk"}


class AnalysisError(Exception):
    """Raised when a token cannot be decoded."""


def _b64url_decode(segment: str) -> bytes:
    """Decode a base64url segment with proper padding."""
    padding = 4 - len(segment) % 4
    if padding != 4:
        segment += "=" * padding
    return base64.urlsafe_b64decode(segment)


def analyze_token(raw_token: str) -> dict[str, Any]:
    """
    Decode a JWT without verifying its signature.

    Returns a dict matching JWTAnalysis (app_spec.txt §data_model):
        {
            algorithm: str,
            expired: bool,
            dangerousFields: list[str],
            header: dict,
            payload: dict,
            signaturePresent: bool,
        }

    Raises AnalysisError if the token is not a valid three-segment JWT.
    """
    parts = raw_token.strip().split(".")
    if len(parts) != 3:
        raise AnalysisError(
            f"Invalid JWT format: expected 3 dot-separated segments, got {len(parts)}."
        )

    header_b64, payload_b64, sig_b64 = parts

    try:
        header: dict = json.loads(_b64url_decode(header_b64).decode("utf-8"))
    except Exception as exc:
        raise AnalysisError(f"Could not decode JWT header: {exc}") from exc

    try:
        payload: dict = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
    except Exception as exc:
        raise AnalysisError(f"Could not decode JWT payload: {exc}") from exc

    algorithm: str = header.get("alg", "")
    signature_present: bool = bool(sig_b64)

    # Detect dangerous header fields present in this token's header
    dangerous: list[str] = [f for f in header if f in ALWAYS_DANGEROUS]

    # Check expiry
    exp = payload.get("exp")
    expired: bool = False
    if exp is not None:
        try:
            expired = float(exp) < time.time()
        except (TypeError, ValueError):
            pass

    return {
        "algorithm": algorithm,
        "expired": expired,
        "dangerousFields": dangerous,
        "header": header,
        "payload": payload,
        "signaturePresent": signature_present,
    }
