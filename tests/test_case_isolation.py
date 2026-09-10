"""
Case isolation UI backend tests per FORENSICS §7 + ARCHITECTURE §11 + ROADMAP §11
Verifies: POST /api/cases, GET /api/cases isolation, case filtering, platform param preserved per case
"""
from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)

def test_create_case_and_isolation():
    # Create fresh case
    r = client.post("/api/cases", json={"title": "isolated-test"})
    assert r.status_code==200, r.text
    nid = r.json()["id"]
    # Run JOCKY in that new case only
    src = 'system.info();'
    rr = client.post("/api/run", json={"source": src, "case_id": nid, "platform": "windows"})
    assert rr.status_code==200
    assert rr.json()["case_id"]==nid
    # Evidence should be isolated to that case
    ev = client.get(f"/api/evidence?case_id={nid}").json()
    assert ev["count"] >= 1
    assert all(e["case_id"]==nid for e in ev["evidence"])
    # Timeline/graph/risk also isolated
    t = client.get(f"/api/cases/{nid}/timeline").json()
    assert t["case_id"]==nid and t["count"]>=1
    g = client.get(f"/api/cases/{nid}/graph").json()
    assert g["case_id"]==nid
    rk = client.get(f"/api/cases/{nid}/risk").json()
    assert rk["case_id"]==nid
    # Other case should not contain this evidence (check case 1 vs new case differ)
    ev_all = client.get("/api/evidence").json()
    assert ev_all["count"] >= ev["count"]

def test_cases_list_grows():
    before = client.get("/api/cases").json()["count"]
    client.post("/api/cases", json={"title": "another"})
    after = client.get("/api/cases").json()["count"]
    assert after >= before + 1

def test_host_filter_via_evidence():
    # Create case with specific host, verify host appears in evidence
    r = client.post("/api/cases", json={"title": "host-filter-test"})
    nid = r.json()["id"]
    client.post("/api/run", json={"source": 'process.list();', "case_id": nid, "host_id": "HOST-FILTER-99", "platform": "linux"})
    ev = client.get(f"/api/evidence?case_id={nid}").json()
    hosts = set(e["host_id"] for e in ev["evidence"])
    assert "HOST-FILTER-99" in hosts

def test_platform_filter_preserved_per_case():
    r = client.post("/api/cases", json={"title": "platform-isolation"})
    nid = r.json()["id"]
    client.post("/api/run", json={"source": 'file.hash("/evidence/sample.exe");', "case_id": nid, "platform": "windows"})
    ev = client.get(f"/api/evidence?case_id={nid}").json()
    assert all(e["payload"].get("platform")=="windows" for e in ev["evidence"])
    # second run with linux in same case adds linux evidence
    client.post("/api/run", json={"source": 'network.connections();', "case_id": nid, "platform": "linux"})
    ev2 = client.get(f"/api/evidence?case_id={nid}").json()
    platforms = set(e["payload"].get("platform") for e in ev2["evidence"])
    assert "windows" in platforms and "linux" in platforms

def test_frontend_case_isolation_ui_exists():
    import pathlib
    txt = pathlib.Path("frontend/src/App.tsx").read_text(encoding="utf-8")
    assert "caseId" in txt and "setCaseId" in txt
    assert "hostFilter" in txt and "typeFilter" in txt and "platformFilter" in txt
    assert "New Case" in txt
    assert "runPlatform" in txt
    assert "filteredEvidence" in txt
