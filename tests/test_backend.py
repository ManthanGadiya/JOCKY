"""
Backend tests — compile/run/timeline/graph/risk + fail-closed
Uses FastAPI TestClient (no Docker needed)
"""
from fastapi.testclient import TestClient
from backend.app.main import app
import json

client = TestClient(app)

def setup_function():
    # TestClient uses same app memory; but each test may add evidence
    # We don't reset between tests — verify cumulative behavior
    pass

def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    j = r.json()
    assert j["status"] == "ok"
    assert j["jocky_ir_version"] == 1

def test_compile_system_info():
    r = client.post("/api/compile", json={"source": "system.info();"})
    assert r.status_code == 200
    j = r.json()
    assert j["ir_version"] == 1
    assert "system.read" in j["capabilities"]
    assert "system.info" in j["ops"]
    assert "JOCKY_DEMO_MARKER" in j["ir"]
    assert j["source_hash"]
    assert j["ir_hash"]

def test_compile_rejects_unknown():
    r = client.post("/api/compile", json={"source": "edr.disable();"})
    assert r.status_code == 422
    assert "Unknown or unsupported capability" in r.json()["detail"]

def test_compile_rejects_security_disable():
    r = client.post("/api/compile", json={"source": "security.disable();"})
    assert r.status_code == 422

def test_run_system_info_creates_evidence():
    # fresh case 10 to avoid collision with earlier runs
    r = client.post("/api/run", json={"source": "system.info();", "agent_id":"TEST-001", "host_id":"TEST-HOST", "case_id": 10})
    assert r.status_code == 200, r.text
    j = r.json()
    assert j["case_id"] == 10
    assert j["ir_version"] == 1
    assert len(j["evidence"]) == 1
    ev = j["evidence"][0]
    assert ev["type"] == "system"
    assert ev["op"] == "system.info"
    assert ev["schema_version"] == 1
    assert ev["integrity"]["verified"] is True
    assert "sha256" in ev["integrity"]
    assert ev["provenance"]["ir_hash"]
    assert j["risk"] >= 0
    assert j["level"] in ("LOW","MEDIUM","HIGH","CRITICAL")

def test_run_memory_denied_403():
    r = client.post("/api/run", json={"source": "memory.analyze(1234);", "case_id": 11})
    assert r.status_code == 403
    assert "Capability denied" in r.json()["detail"]

def test_run_unknown_422():
    r = client.post("/api/run", json={"source": "edr.disable();"})
    assert r.status_code == 422

def test_run_multiple_ops():
    r = client.post("/api/run", json={"source": "system.info();\nprocess.list();\n", "case_id": 12})
    assert r.status_code == 200
    assert len(r.json()["evidence"]) == 2
    ops = {e["op"] for e in r.json()["evidence"]}
    assert "system.info" in ops
    assert "process.list" in ops

def test_timeline_live():
    # case 10 had system.info evidence; timeline must return it
    r = client.get("/api/cases/10/timeline")
    assert r.status_code == 200
    j = r.json()
    assert j["count"] >= 1
    assert any(e["op"] == "system.info" for e in j["timeline"])

def test_graph_live():
    r = client.get("/api/cases/10/graph")
    assert r.status_code == 200
    j = r.json()
    assert "nodes" in j and "edges" in j
    assert len(j["nodes"]) >= 3  # host + evidence + finding
    assert len(j["edges"]) >= 2

def test_risk_low_for_system_info():
    r = client.get("/api/cases/10/risk")
    assert r.status_code == 200
    j = r.json()
    assert j["risk"] == 5
    assert j["level"] == "LOW"

def test_detect_still_works():
    r = client.post("/api/detect", json={"hollowed": True, "memory": {"hollowed": True}})
    assert r.status_code == 200
    assert "hits" in r.json()

def test_evidence_list():
    r = client.get("/api/evidence?case_id=10")
    assert r.status_code == 200
    assert r.json()["count"] >= 1
