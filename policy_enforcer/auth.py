"""
Authentication, Password Hashing, JWT Management, and RBAC Dependencies for TRINETRA.
"""
from __future__ import annotations

import os
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any
from pathlib import Path

import bcrypt
import jwt
from dotenv import load_dotenv
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from . import database
from .auth_models import UserResponse, TokenPayload

logger = logging.getLogger("trinetra.auth")

# Load environment variables from backend/.env if present
_env_path = Path(__file__).resolve().parent.parent / ".env"
if _env_path.exists():
    load_dotenv(dotenv_path=_env_path)
else:
    load_dotenv()

# JWT Settings
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "trinetra-soc-super-secret-jwt-signing-key-change-in-production")
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 12

security_bearer = HTTPBearer(auto_error=False)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# -----------------------------------------------------------------------------
# Password Hashing & Verification (bcrypt)
# -----------------------------------------------------------------------------
def hash_password(password: str) -> str:
    """Hash a plaintext password with bcrypt and automated salt."""
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed.decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify plaintext password against bcrypt hash."""
    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8"),
            hashed_password.encode("utf-8")
        )
    except Exception as e:
        logger.error("Error during password verification: %s", e)
        return False


# -----------------------------------------------------------------------------
# JWT Token Operations
# -----------------------------------------------------------------------------
def create_access_token(username: str, role: str, expires_delta: Optional[timedelta] = None) -> str:
    """Create a signed JWT access token."""
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(hours=JWT_EXPIRATION_HOURS))
    payload = {
        "sub": username,
        "role": role,
        "exp": int(expire.timestamp()),
        "iat": int(datetime.now(timezone.utc).timestamp()),
    }
    encoded_jwt = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return encoded_jwt


def decode_access_token(token: str) -> Dict[str, Any]:
    """Decode and validate a JWT access token."""
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired. Please log in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token.",
            headers={"WWW-Authenticate": "Bearer"},
        )


# -----------------------------------------------------------------------------
# FastAPI Auth & RBAC Dependencies
# -----------------------------------------------------------------------------
async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_bearer),
) -> Dict[str, Any]:
    """
    Extracts Bearer token from header, validates JWT, and fetches user record.
    Permits both 'operator' and 'admin' roles.
    """
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization Bearer header.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials
    payload = decode_access_token(token)
    username: Optional[str] = payload.get("sub")

    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed token payload.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = database.get_user_by_username(username)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account no longer exists.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


async def require_admin(
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Strict dependency for privileged operations (e.g. threshold mutation, enforcer config, event DB clear).
    """
    if current_user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privilege required for this operation.",
        )
    return current_user


# -----------------------------------------------------------------------------
# Initial Admin Seeding (Fail-Fast Rule)
# -----------------------------------------------------------------------------
def seed_initial_admin_if_needed(custom_db_path: Optional[Path] = None) -> None:
    """
    Checks if users table has any records.
    If empty, reads TRINETRA_ADMIN_PASSWORD from environment.
    Fails fast if the environment variable is missing.
    """
    user_count = database.get_user_count(custom_db_path)
    if user_count == 0:
        admin_pass = os.getenv("TRINETRA_ADMIN_PASSWORD")
        if not admin_pass or not admin_pass.strip():
            err_msg = (
                "CRITICAL: TRINETRA_ADMIN_PASSWORD environment variable is required "
                "to initialize the initial admin account. Refusing to start with an insecure default password."
            )
            logger.critical(err_msg)
            raise RuntimeError(err_msg)

        hashed = hash_password(admin_pass.strip())
        database.insert_user(
            username="admin",
            password_hash=hashed,
            full_name="Lead SOC Administrator",
            role="admin",
            created_at=_utc_now_iso(),
            custom_path=custom_db_path,
        )
        logger.info("Successfully seeded initial admin account 'admin' (role: admin).")
