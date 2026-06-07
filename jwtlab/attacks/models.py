"""
Shared models for attack module state and request/response schemas.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ModuleState:
    """Ephemeral in-process state for a single attack module."""
    slug: str
    patched: bool = False  # vulnerabilityActive = True means patched = False


class LoginRequest:
    pass


# ─── Pydantic schemas (shared) ────────────────────────────────────────────────
from pydantic import BaseModel


class LoginReq(BaseModel):
    username: str
    password: str


class VerifyReq(BaseModel):
    token: str


class VerifyResp(BaseModel):
    valid: bool
    claims: dict
    message: str


class TogglePatchResp(BaseModel):
    patched: bool
