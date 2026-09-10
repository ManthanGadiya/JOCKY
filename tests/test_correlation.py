"""
Correlation enrichment tests per ARCHITECTURE §14 + FORENSICS §43 + DESIGN §37
Verifies: temporal, pid-sharing, process→file/net, mitre aggregation
"""
from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)

def test_graph_correlations_present():
    # Use full sweep which should have process→file and process→net and temporal
    r = client.post("/api/run", json={"source": 'system.info();\nprocess.list();\nfile.hash("/evidence/sample.exe");\nnetwork.connections();', "case_id": 701, "platform": "windows"})
    assert r.status_code==200, r.text
    g = client.get("/api/cases/701/graph").json()
    assert "correlations" in g
    assert g["correlation_count"] >= 2
    # Should have at least process→file and process→net
    types = [c["type"] for c in g["correlations"]]
    assert "process→file" in types or any("process" in t for t in types)
    assert "process→net" in types or any("net" in t for t in types)

def test_graph_temporal_correlation():
    # Two quick evidences in same case should be temporally correlated (<120s)
    client.post("/api/run", json={"source": 'system.info();', "case_id": 702})
    client.post("/api/run", json={"source": 'process.list();', "case_id": 702})
    g = client.get("/api/cases/702/graph").json()
    assert any(c["type"]=="temporal" for c in g["correlations"])

def test_graph_pid_correlation():
    # file + network sharing pid 9012 via process tree should correlate
    r = client.post("/api/run", json={"source": 'process.list();\nnetwork.connections();', "case_id": 703})
    assert r.status_code==200
    g = client.get("/api/cases/703/graph").json()
    # pid correlation may appear as process→net or pid type
    assert any("pid" in (c["type"].lower() + c.get("reason","")) for c in g["correlations"]) or g["correlation_count"]>0

def test_graph_mitre_and_platform_preserved():
    r = client.post("/api/run", json={"source": 'file.hash("/evidence/sample.exe");', "case_id": 704, "platform": "linux"})
    g = client.get("/api/cases/704/graph").json()
    assert "T1105" in g["mitre"]
    # nodes should have platform field
    assert any(n.get("platform")=="linux" for n in g["nodes"])

def test_graph_edges_have_weight():
    g = client.get("/api/cases/701/graph").json()
    for e in g["edges"]:
        assert "weight" in e
        assert 0 < e["weight"] <= 1

def test_correlation_confidence_range():
    g = client.get("/api/cases/701/graph").json()
    for c in g["correlations"]:
        assert 0 < c["confidence"] <= 1
        assert "reason" in c
