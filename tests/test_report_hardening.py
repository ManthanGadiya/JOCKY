"""
Report hardening tests per FORENSICS §64 + ARCHITECTURE §11 + DESIGN §41
Verifies: put_report versioned, list_reports history, get versioned, storage persists via MinIO mem fallback
"""
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app import storage as stor

client = TestClient(app)

def test_report_history_list():
    cases = client.get("/api/cases").json()["cases"]
    # use a fresh high id via POST /cases
    rc = client.post("/api/cases", json={"title": "report-history"})
    nid = rc.json()["id"]
    # Ensure clean
    try:
        stor.delete_reports_for_case(nid)
    except Exception:
        pass
    client.post("/api/run", json={"source": 'system.info();', "case_id": nid})
    r1 = client.get(f"/api/cases/{nid}/report")
    assert r1.status_code in (200,)
    client.post("/api/run", json={"source": 'file.hash("/evidence/sample.exe");', "case_id": nid})
    import time; time.sleep(1)
    r2 = client.get(f"/api/cases/{nid}/report")
    assert r2.status_code in (200,)
    # On host without pango deps report is HTML fallback (no MinIO put), so directly seed versioned history via storage
    # to verify list/get versioned endpoints work per FORENSICS §64 (host fallback still testable via direct put)
    stor.put_report(nid, b"%PDF-history-seed-1")
    time.sleep(1)
    stor.put_report(nid, b"%PDF-history-seed-2")
    lst = client.get(f"/api/cases/{nid}/reports").json()
    assert lst["case_id"]==nid
    assert lst["count"] >= 2
    assert all("JOCKY_case_" in x["key"] for x in lst["reports"])
    first_key = lst["reports"][0]["key"].split("/")[-1]
    rv = client.get(f"/api/cases/{nid}/reports/{first_key}")
    assert rv.status_code==200

def test_storage_list_reports_direct():
    # Direct storage API
    data = b"%PDF-versioned-test"
    stor.put_report(9991, data)
    import time; time.sleep(1)
    stor.put_report(9991, data + b"2")
    lst = stor.list_reports(9991)
    assert len(lst) >= 2
    # cleanup
    stor.delete_reports_for_case(9991)
    assert len(stor.list_reports(9991))==0

def test_health_includes_storage_history():
    r = client.get("/health").json()
    assert "storage" in r
    # storage status has bucket_reports
    assert r["storage"]["bucket_reports"] == "jocky-reports"
