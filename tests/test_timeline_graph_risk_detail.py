"""
Timeline / Graph expand / Risk history detail tests per ARCHITECTURE §14-15 + DESIGN §41
"""
from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)

def test_risk_history_endpoint():
    # Create case with evidence
    rc = client.post("/api/cases", json={"title": "risk-history-test"}).json()
    nid = rc["id"]
    client.post("/api/run", json={"source": 'system.info();', "case_id": nid})
    client.post("/api/run", json={"source": 'process.list();', "case_id": nid})
    r = client.get(f"/api/cases/{nid}/risk/history")
    assert r.status_code==200, r.text
    j = r.json()
    assert j["case_id"]==nid
    assert j["count"] >= 2
    assert "history" in j
    for h in j["history"]:
        assert "risk" in h and "cumulative_max" in h and "evidence_id" in h

def test_risk_breakdown_endpoint():
    rc = client.post("/api/cases", json={"title": "breakdown-test"}).json()
    nid = rc["id"]
    client.post("/api/run", json={"source": 'process.list();\nfile.hash("/evidence/sample.exe");', "case_id": nid})
    r = client.get(f"/api/cases/{nid}/risk/breakdown")
    assert r.status_code==200
    j = r.json()
    assert j["case_id"]==nid
    assert "breakdown" in j and len(j["breakdown"])>=1
    for b in j["breakdown"]:
        assert "id" in b and "risk" in b and "behavioral" in b
        # behavioral should have rule/mitre
        if b["behavioral"]:
            assert "rule" in b["behavioral"][0]

def test_graph_expand_node():
    rc = client.post("/api/cases", json={"title": "expand-test"}).json()
    nid = rc["id"]
    rr = client.post("/api/run", json={"source": 'system.info();\nprocess.list();\nfile.hash("/evidence/sample.exe");\nnetwork.connections();', "case_id": nid})
    ev = rr.json()["evidence"][0]["id"]
    r = client.get(f"/api/cases/{nid}/graph/expand?node_id={ev}")
    assert r.status_code==200
    j = r.json()
    assert j["node_id"]==ev
    assert "evidence" in j and "neighbors" in j

def test_graph_expand_without_node():
    rc = client.post("/api/cases", json={"title": "expand-all"}).json()
    nid = rc["id"]
    client.post("/api/run", json={"source": 'system.info();', "case_id": nid})
    r = client.get(f"/api/cases/{nid}/graph/expand")
    assert r.status_code==200
    assert r.json()["expanded"] is True

def test_graph_expand_404():
    r = client.get("/api/cases/99999/graph/expand?node_id=EV-NONEXISTENT")
    assert r.status_code==404

def test_frontend_has_detail_ui():
    import pathlib
    app_txt = pathlib.Path("frontend/src/App.tsx").read_text(encoding="utf-8")
    assert "graph/expand" in app_txt
    assert "risk/breakdown" in app_txt or "RiskGauge" in app_txt
    assert "selectedNode" in app_txt
    timeline = pathlib.Path("frontend/src/components/Timeline.tsx").read_text(encoding="utf-8")
    assert "minRisk" in timeline
    risk = pathlib.Path("frontend/src/components/RiskGauge.tsx").read_text(encoding="utf-8")
    assert "breakdown" in risk or "history" in risk
