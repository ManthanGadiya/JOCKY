"""
Auth — JWT hardening per SECURITY_MODEL.md §19-20 + ARCHITECTURE §10
Provides: create_token, verify_token, get_current_user dependency
Default policy: AUTH_REQUIRED env = false (host tests bypass), Docker can set true
Uses python-jose + passlib compatible with existing backend/requirements.txt
"""
import os, time, hashlib
from typing import Optional, Dict, Any
from fastapi import HTTPException, Header, Depends

JWT_SECRET = os.getenv("JWT_SECRET", "change-me-in-prod")
JWT_ALG = os.getenv("JWT_ALG", "HS256")
JWT_EXPIRE = int(os.getenv("JWT_EXPIRE_SECONDS", "3600"))
AUTH_REQUIRED = os.getenv("AUTH_REQUIRED", "false").lower() == "true"

# Simple in-memory user store for demo (single analyst per SECURITY_MODEL §7 Investigator)
# In production would be DB-backed; here is synthetic per lab isolation
_USERS = {
    "analyst": hashlib.sha256(b"jocky:analyst:demo").hexdigest()[:16],  # demo password hash placeholder
}
# Allow env USERS_JSON override like {"analyst":"password123"}
try:
    import json as _j
    env_users = os.getenv("USERS_JSON")
    if env_users:
        _USERS.update(_j.loads(env_users))
except Exception:
    pass

def _now() -> int:
    return int(time.time())

def create_token(sub: str = "analyst", role: str = "investigator") -> str:
    """Create JWT (HS256) with sub, role, exp, iat per SECURITY_MODEL §19."""
    try:
        from jose import jwt  # type: ignore
        payload = {"sub": sub, "role": role, "iat": _now(), "exp": _now() + JWT_EXPIRE}
        return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"JWT encode failed: {e}")

def verify_token(token: str) -> Dict[str, Any]:
    try:
        from jose import jwt  # type: ignore
        data = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        if data.get("exp", 0) < _now():
            raise HTTPException(status_code=401, detail="Token expired")
        return data
    except Exception as e:
        # jose raises JWTError
        raise HTTPException(status_code=401, detail=f"Invalid token: {e}")

def get_current_user(authorization: Optional[str] = Header(None), x_api_key: Optional[str] = Header(None)) -> Optional[Dict[str, Any]]:
    """
    Dependency for protected endpoints.
    If AUTH_REQUIRED=false (default host), allows anonymous with role=investigator.
    If true, requires Bearer token or X-API-Key (simple fallback).
    """
    if not AUTH_REQUIRED:
        # permissive for host tests and demo — return synthetic user but still verify if token provided
        if authorization and authorization.startswith("Bearer "):
            try:
                return verify_token(authorization[7:])
            except HTTPException:
                # still allow fallback to anonymous? No — if token provided, must be valid
                raise
        return {"sub": "analyst", "role": "investigator", "auth": "bypass (AUTH_REQUIRED=false)"}
    # strict mode
    if x_api_key and x_api_key == JWT_SECRET:
        return {"sub": "agent", "role": "agent", "auth": "api-key"}
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Authorization: Bearer token required per SECURITY_MODEL §19 (set AUTH_REQUIRED=false to bypass)")
    return verify_token(authorization[7:])

def require_role(role: str):
    def _dep(user: Dict[str, Any] = Depends(get_current_user)):
        if user is None or user.get("role") not in (role, "admin"):
            raise HTTPException(status_code=403, detail=f"Requires role {role}")
        return user
    return _dep
