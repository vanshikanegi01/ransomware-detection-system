"""
Pydantic data models for Authentication and Authorization.
"""
from __future__ import annotations

from typing import Optional
from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, description="Username of the operator/admin")
    password: str = Field(..., min_length=1, description="Plaintext password for verification")


class UserResponse(BaseModel):
    username: str
    full_name: str
    role: str
    created_at: Optional[str] = None
    last_login: Optional[str] = None


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse


class TokenPayload(BaseModel):
    sub: str  # username
    role: str
    exp: int
