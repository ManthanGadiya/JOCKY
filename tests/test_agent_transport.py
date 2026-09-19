from fastapi.testclient import TestClient
from backend.app.main import app
import pathlib, json, base64

client = TestClient(app)

def test_daemon_mode_exists():
    txt = pathlib.Path("agent/agent.py").read_text(encoding="utf-8")
    assert "def daemon_loop" in txt
    assert "--daemon" in txt
    assert "DAEMON_INTERVAL" in txt
    assert "ENCRYPT_ALERTS" in txt
    assert "encrypt_payload_lab" in txt

def test_encrypted_alert_via_api():
    # lab encrypt then POST /api/evidence/encrypted
    import json, base64
    payload = {"type": "file", "path": "/tmp/enc_test.exe", "note": "lab encrypted"}
    key = "jocky-lab-key"
    raw = json.dumps(payload, sort_keys=True).encode()
    kb = key.encode()
    enc = bytes(b ^ kb[i % len(kb)] for i, b in enumerate(raw))
    token = base64.b64encode(enc).decode()
    r = client.post("/api/evidence/encrypted", json={"agent_id": "WIN-001", "type": "file", "payload_encrypted": token})
    assert r.status_code == 200
    j = r.json()
    assert j["payload"]["path"] == "/tmp/enc_test.exe"
    # verify endpoint also works
    r2 = client.get(f"/api/evidence/verify-encrypted?token={token}")
    assert r2.status_code == 200 and r2.json().get("verified") is True

def test_encrypted_invalid_rejected():
    r = client.post("/api/evidence/encrypted", json={"payload_encrypted": "!!!invalid!!!"})
    assert r.status_code == 400

def test_resource_limits_413_under_hardened_ir():
    # Hardened IR load should still respect MAX limits (413)
    # Oversized source -> 413 per SECURITY 28
    big = "system.info();" * 20000  # ~280k > 50k MAX_SOURCE_SIZE
    r = client.post("/api/run", json={"source": big, "platform": "windows"})
    assert r.status_code == 413
    # Oversized evidence -> 413
    big_payload = {"x": "A"* (6*1024*1024)}
    r2 = client.post("/api/evidence", json={"agent_id": "WIN-001", "type": "file", "payload": big_payload})
    assert r2.status_code == 413
    # Hardened IR normal size still succeeds (under limit)
    import tools.jockyc as jc
    src = "system.info(); process.list(); file.hash(\"/evidence/sample.exe\");"
    ir = jc.generate_ir(src, 1, True)
    assert len(ir) < 100*1024
    r3 = client.post("/api/run", json={"source": src, "platform": "windows"})
    assert r3.status_code == 200

def test_audit_hash_chain_under_hardened_load():
    # Run several hardened IRs and check audit hash chain is intact
    for i in range(3):
        client.post("/api/run", json={"source": f"system.info(); process.list(); // hardened {i}", "platform": "windows"})
    r = client.get("/api/audit?limit=10")
    assert r.status_code == 200
    evs = r.json().get("events", r.json() if isinstance(r.json(), list) else [])
    # Check chain: each prev_hash == prior hash
    if isinstance(evs, dict) and "events" in evs:
        evs = evs["events"]
    for i in range(1, len(evs)):
        assert evs[i]["prev_hash"] == evs[i-1]["hash"], "audit hash chain must be intact under hardened IR load"
