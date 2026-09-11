"""
Hardening P2 per SECURITY_MODEL §28,34-36 + DESIGN §53
Verifies: resource limits (source/evidence/IR too large → 413), audit log (capability denied, evidence submit, run execute, hash chain)
"""
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.audit import clear_for_tests, get_events

client = TestClient(app)

def test_source_too_large_413():
    big = "system.info();" * 20000  # ~260KB > 50KB limit
    r = client.post("/api/run", json={"source": big, "case_id": 920})
    assert r.status_code==413
    assert "too large" in r.text.lower()

def test_compile_source_too_large():
    big = "system.info();" * 10000
    r = client.post("/api/compile", json={"source": big})
    assert r.status_code==413

def test_evidence_too_large_413():
    # Create payload ~6MB > 5MB limit
    huge = {"data": "x" * (6*1024*1024)}
    r = client.post("/api/evidence", json={"agent_id":"TST","type":"file","payload": huge})
    assert r.status_code==413

def test_audit_logs_capability_denied():
    clear_for_tests()
    r = client.post("/api/run", json={"source": 'memory.analyze("x");', "case_id": 921})
    assert r.status_code==403
    evs = get_events(action="run.capability_denied")
    assert len(evs) >= 1
    assert evs[-1]["action"]=="run.capability_denied"
    assert "memory.analyze" in str(evs[-1]["metadata"])

def test_audit_logs_evidence_submit():
    clear_for_tests()
    r = client.post("/api/evidence", json={"agent_id":"AUD-001","type":"file","payload":{"sample":"a"}})
    assert r.status_code==200
    evs = get_events(action="evidence.submit")
    assert len(evs) >= 1
    assert evs[-1]["actor"]=="AUD-001"

def test_audit_logs_run_execute():
    clear_for_tests()
    r = client.post("/api/run", json={"source": 'system.info();', "case_id": 922})
    assert r.status_code==200
    evs = get_events(action="run.execute")
    assert len(evs) >= 1
    assert evs[-1]["target"]=="case:922"

def test_audit_hash_chain():
    clear_for_tests()
    client.post("/api/run", json={"source": 'system.info();', "case_id": 923})
    client.post("/api/evidence", json={"agent_id":"A","type":"file","payload":{"x":1}})
    evs = get_events(limit=10)
    assert len(evs) >= 2
    # Each has hash and prev_hash chain
    for e in evs:
        assert "hash" in e and "prev_hash" in e
        assert len(e["hash"])==64
    # Chain: second's prev_hash == first's hash
    assert evs[1]["prev_hash"] == evs[0]["hash"]

def test_audit_endpoint():
    clear_for_tests()
    client.post("/api/run", json={"source": 'process.list();', "case_id": 924})
    r = client.get("/api/audit?limit=5")
    assert r.status_code==200
    j = r.json()
    assert j["count"] >= 1
    assert "events" in j
    # filter by action
    r2 = client.get("/api/audit?action=run.execute")
    assert r2.status_code==200
    assert all(e["action"]=="run.execute" for e in r2.json()["events"])

def test_audit_compile_rejected_logged():
    clear_for_tests()
    r = client.post("/api/run", json={"source": 'edr.disable();', "case_id": 925})
    assert r.status_code==422
    evs = get_events(action="run.compile")
    assert len(evs) >= 1
