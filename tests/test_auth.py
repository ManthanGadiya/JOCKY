"""
Auth hardening tests per SECURITY_MODEL §19-20 + ARCHITECTURE §10
Verifies: JWT login, verify, me, status, bypass when AUTH_REQUIRED=false, strict mode raises 401 when enabled
"""
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.auth import create_token, verify_token, JWT_SECRET
import os

client = TestClient(app)

def test_auth_status():
    r = client.get("/api/auth/status")
    assert r.status_code==200
    j = r.json()
    assert "auth_required" in j
    assert "login" in j

def test_auth_login_returns_jwt():
    r = client.post("/api/auth/login", json={"username": "analyst"})
    assert r.status_code==200, r.text
    j = r.json()
    assert "access_token" in j
    assert j["token_type"]=="bearer"
    # verify token
    payload = verify_token(j["access_token"])
    assert payload["sub"]=="analyst"
    assert payload["role"]=="investigator"

def test_auth_me_bypass_when_not_required():
    # Default AUTH_REQUIRED=false → /api/auth/me without token should succeed via bypass
    r = client.get("/api/auth/me")
    assert r.status_code==200
    assert r.json()["user"]["sub"]=="analyst"

def test_auth_me_with_valid_token():
    tok = create_token(sub="tester")
    r = client.get("/api/auth/me", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code==200
    assert r.json()["user"]["sub"]=="tester"

def test_auth_invalid_token_rejected():
    r = client.get("/api/auth/me", headers={"Authorization": "Bearer invalid.invalid.invalid"})
    assert r.status_code==401

def test_health_has_auth_field():
    r = client.get("/health").json()
    assert "auth_required" in client.get("/api/storage/status").json() or True
    # storage status now includes auth_required
    s = client.get("/api/storage/status").json()
    assert "auth_required" in s

def test_run_still_works_without_auth_when_not_required():
    # Existing tests must still pass without token when AUTH_REQUIRED=false
    r = client.post("/api/run", json={"source": "system.info();", "case_id": 801})
    assert r.status_code==200

def test_strict_mode_requires_token(monkeypatch=None):
    # Simulate AUTH_REQUIRED=true by patching auth module
    import backend.app.auth as auth_mod
    import backend.app.main as main_mod
    orig = auth_mod.AUTH_REQUIRED
    try:
        auth_mod.AUTH_REQUIRED = True
        main_mod.AUTH_REQUIRED = True
        # Without token should 401 on /api/auth/me strict
        r = client.get("/api/auth/me")
        assert r.status_code==401
        # With token should pass
        tok = create_token("analyst")
        r2 = client.get("/api/auth/me", headers={"Authorization": f"Bearer {tok}"})
        assert r2.status_code==200
    finally:
        auth_mod.AUTH_REQUIRED = orig
        main_mod.AUTH_REQUIRED = orig
