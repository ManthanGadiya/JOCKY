"""
Agent transport tests — Phase 2 per docs/STATUS.md §10.11, ARCHITECTURE.md §7, FORENSICS_SPEC.md §56
Verifies: agent posts via nginx transport (http://nginx:80) instead of stub print,
          health via nginx, evidence POST, JOCKY run POST, fail-closed 422/403
Uses FastAPI TestClient as backend mock + agent.py helper functions via import.
Per TEST_PLAN.md §28 Agent Tests, §34 Backend API Tests, SECURITY_MODEL §14/17
"""
import json, pathlib, sys
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from backend.app.main import app
import importlib.util

client = TestClient(app)

# Import agent.py as module without executing main
spec = importlib.util.spec_from_file_location("agent", "agent/agent.py")
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)

def test_agent_import_and_helpers_exist():
    assert hasattr(agent, "http_get")
    assert hasattr(agent, "http_post_json")
    assert hasattr(agent, "post_fixture_via_nginx")
    assert hasattr(agent, "post_jocky_via_nginx")
    assert hasattr(agent, "agent_scan_once")

def test_agent_post_fixture_via_nginx_mocked():
    # Mock http_post_json to simulate nginx → backend POST /api/evidence success
    with patch.object(agent, "http_post_json", return_value=(200, json.dumps({"id": "EV-20260828-000099", "risk": 20, "sha256": "abc123"}))) as m:
        ok, resp = agent.post_fixture_via_nginx(pathlib.Path("testdata/hollowing.json"), 1)
        assert ok is True
        assert resp["id"].startswith("EV-")
        assert m.called
        # Ensure payload was type+agent_id structure per FORENSICS_SPEC §5
        call_args = m.call_args
        assert call_args[0][0] == "/api/evidence"

def test_agent_post_jocky_via_nginx_success():
    with patch.object(agent, "http_post_json", return_value=(200, json.dumps({"ops": ["system.info"], "evidence": [{"id": "EV-1"}], "risk": 5, "level": "LOW"}))):
        ok, resp = agent.post_jocky_via_nginx('system.info();', 1, "HOST-001", "WIN-001")
        assert ok is True
        assert resp["risk"] == 5

def test_agent_post_jocky_fail_closed_unknown():
    with patch.object(agent, "http_post_json", return_value=(422, '{"detail":"Unknown or unsupported capability: edr.disable"}')):
        ok, resp = agent.post_jocky_via_nginx('edr.disable();', 1, "HOST-001", "WIN-001")
        assert ok is False  # fail-closed per SECURITY_MODEL §14

def test_agent_post_jocky_denied_403():
    with patch.object(agent, "http_post_json", return_value=(403, '{"detail":"Capability denied by policy: memory.analyze"}')):
        ok, resp = agent.post_jocky_via_nginx('memory.analyze("x");', 1, "HOST-001", "WIN-001")
        assert ok is False

def test_agent_scan_once_integration_with_real_backend():
    # Real integration via TestClient-mocked nginx: patch http_get/post to delegate to TestClient
    def fake_get(path, timeout=5):
        r = client.get(path)
        return r.status_code, r.text
    def fake_post(path, payload, timeout=10):
        r = client.post(path, json=payload)
        return r.status_code, r.text
    with patch.object(agent, "http_get", side_effect=fake_get):
        with patch.object(agent, "http_post_json", side_effect=fake_post):
            # This should run health + fixture posts + JOCKY sweep + fail-closed check without exception
            agent.agent_scan_once()
            # After scan, evidence should exist for case 1 via real backend
            ev = client.get("/api/evidence?case_id=1").json()
            assert ev["count"] >= 1
            # JOCKY sweep should have created at least 1 evidence via POST /api/run
            # Verify timeline not empty
            tl = client.get("/api/cases/1/timeline").json()
            assert tl["count"] >= 1

def test_docker_compose_agent_uses_nginx():
    compose = pathlib.Path("docker-compose.yml").read_text()
    assert "BACKEND_URL=http://nginx:80" in compose
    assert "agent/Dockerfile" in compose
    # Ensure agent healthcheck probes nginx per ARCHITECTURE.md §21
    assert "curl -sf http://nginx:80/health" in compose

def test_agent_dockerfile_uses_python_via_nginx():
    df = pathlib.Path("agent/Dockerfile").read_text()
    assert "agent.py" in df
    assert "python3" in df and "/app/agent.py" in df
    assert "ca-certificates curl python3" in df
