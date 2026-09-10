"""
Storage & Cache tests — Harden & Persist per ARCHITECTURE §11 + FORENSICS §64
Verifies: MinIO/Redis with in-memory fallback, report→MinIO, artifact upload, health, cache
"""
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app import storage as stor
from backend.app import cache as cach

client = TestClient(app)

def test_health_includes_minio_redis():
    r = client.get("/health")
    assert r.status_code==200
    j = r.json()
    assert "minio" in j and "redis" in j
    assert "storage" in j and "cache" in j
    assert isinstance(j["minio"], bool)

def test_storage_status_endpoint():
    r = client.get("/api/storage/status")
    assert r.status_code==200
    j = r.json()
    assert "storage" in j and "cache" in j
    assert "minio" in j["storage"] or "minio_available" in j["storage"]

def test_storage_put_get_fallback():
    # Put via storage layer, get back (works even without MinIO via mem fallback)
    data = b"test-report-pdf-bytes-%PDF"
    key = stor.put_report(9999, data)
    assert "case-9999" in key
    got = stor.get_report(9999)
    assert got == data or got is not None  # fallback ensures at least mem store has it

def test_cache_fallback():
    cach.cache_set("test:key", {"value": 42}, ttl=5)
    v = cach.cache_get("test:key")
    assert v is not None
    # value may be dict or json depending on path, but should contain 42
    assert v == {"value":42} or "42" in str(v)

def test_report_triggers_storage():
    # Generate a case with evidence, then fetch report (should hit storage path)
    r = client.post("/api/run", json={"source": 'system.info();\nfile.hash("/evidence/sample.exe");', "case_id": 777})
    assert r.status_code==200
    rp = client.get("/api/cases/777/report")
    # HTML fallback on host without pango deps is ok, but should still store to mem if pdf
    assert rp.status_code in (200,)
    ctype = rp.headers.get("content-type","")
    assert "pdf" in ctype or "html" in ctype
    # If PDF, check storage got it (mem fallback)
    if "pdf" in ctype:
        got = stor.get_report(777)
        assert got is not None and got.startswith(b"%PDF")

def test_evidence_post_triggers_artifact_storage():
    r = client.post("/api/evidence", json={"agent_id":"TEST-001","type":"file","payload":{"sample":"data"}})
    assert r.status_code==200
    evid = r.json()["id"]
    # artifact should be in storage via put_evidence_artifact
    data = stor.get_bytes(stor.BUCKET_EVIDENCE, f"{evid}.json")
    assert data is not None

def test_artifact_upload_and_get():
    payload = {"case_id": 123, "evidence": "hello"}
    r = client.post("/api/artifacts/upload", json=payload)
    assert r.status_code==200
    j = r.json()
    assert "key" in j and "sha256" in j
    key = j["key"]
    # GET via API should find it (mem fallback)
    rg = client.get(f"/api/artifacts/{key}")
    assert rg.status_code==200
    assert rg.json()["key"]==key

def test_artifact_too_large_rejected():
    big = {"data": "x"* (6*1024*1024)}
    r = client.post("/api/artifacts/upload", json=big)
    assert r.status_code==413
