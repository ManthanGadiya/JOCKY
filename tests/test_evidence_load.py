"""
Evidence.load wiring tests per LANGUAGE_SPEC §28 + IR_SPEC §18.1 + FORENSICS §61-62 + SECURITY §26
"""
from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)

def test_evidence_load_hollowing():
    r = client.post("/api/run", json={"source": 'evidence.load("testdata/hollowing.json");', "case_id": 901})
    assert r.status_code==200, r.text
    j = r.json()
    assert "evidence.load" in j["ops"]
    ev = j["evidence"][0]
    # payload should contain hollowing fixture fields per testdata/hollowing.json
    assert ev["payload"]["type"]=="memory" or ev["payload"].get("memory",{}).get("hollowed") is True
    assert ev["payload"]["source"]=="evidence.load"
    assert "hollowing.json" in ev["payload"].get("source_file","")
    # integrity preserved per FORENSICS §26
    assert ev["integrity"]["verified"] is True
    assert ev["payload"]["platform"] in ("linux","windows")

def test_evidence_load_byovd():
    r = client.post("/api/run", json={"source": 'evidence.load("testdata/byovd_driver.json");', "case_id": 902})
    assert r.status_code==200
    ev = r.json()["evidence"][0]
    assert ev["payload"]["type"]=="driver"
    assert "RTCore64" in str(ev["payload"])

def test_evidence_load_platform_agnostic():
    # Same fixture, different platform param → same content but platform field differs per LANGUAGE §27
    r1 = client.post("/api/run", json={"source": 'evidence.load("testdata/hollowing.json");', "case_id": 903, "platform": "windows"})
    r2 = client.post("/api/run", json={"source": 'evidence.load("testdata/hollowing.json");', "case_id": 904, "platform": "linux"})
    assert r1.json()["evidence"][0]["payload"]["platform"]=="windows"
    assert r2.json()["evidence"][0]["payload"]["platform"]=="linux"
    # core hollowing signal preserved across platforms
    assert r1.json()["evidence"][0]["payload"]["memory"]["hollowed"] is True
    assert r2.json()["evidence"][0]["payload"]["memory"]["hollowed"] is True

def test_evidence_load_traversal_rejected():
    r = client.post("/api/run", json={"source": 'evidence.load("../../etc/passwd");', "case_id": 905})
    assert r.status_code==400
    assert "traversal" in r.text.lower() or "rejected" in r.text.lower()

def test_evidence_load_missing_arg_rejected():
    r = client.post("/api/run", json={"source": 'evidence.load();', "case_id": 906})
    assert r.status_code in (400,422)
    assert "evidence.load" in r.text.lower() or "requires path" in r.text.lower()

def test_evidence_load_not_found():
    r = client.post("/api/run", json={"source": 'evidence.load("testdata/not_exist.json");', "case_id": 907})
    assert r.status_code==400
    assert "not found" in r.text.lower()

def test_evidence_load_timeline_graph():
    r = client.post("/api/run", json={"source": 'evidence.load("testdata/hollowing.json");', "case_id": 908})
    nid = r.json()["case_id"]
    # Should appear in timeline and graph
    t = client.get(f"/api/cases/{nid}/timeline").json()
    assert t["count"] >= 1
    g = client.get(f"/api/cases/{nid}/graph").json()
    assert len(g["nodes"]) >= 2
    # Risk should be at least behavioral hollowing weight
    rk = client.get(f"/api/cases/{nid}/risk").json()
    assert rk["risk"] >= 30

def test_combine_evidence_load_with_other_ops():
    src = 'evidence.load("testdata/hollowing.json");\nprocess.list();\nfile.hash("/evidence/sample.exe");'
    r = client.post("/api/run", json={"source": src, "case_id": 909})
    assert r.status_code==200
    assert len(r.json()["evidence"]) == 3
    # Graph should have correlations
    g = client.get("/api/cases/909/graph").json()
    assert g["correlation_count"] >= 1

def test_lexer_handles_evidence_load():
    from backend.app.main import validate_and_collect
    ops, caps, errs = validate_and_collect('evidence.load("testdata/hollowing.json");')
    assert errs == []
    assert ops == ["evidence.load"]
    assert caps == ["evidence.read"]
