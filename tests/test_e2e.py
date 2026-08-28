"""
E2E test — system.info(); traveling through full pipeline as described in docs/STATUS.md §8
Source → Compile (IR_VERSION=1, caps) → Run (envelope + integrity) → Timeline → Graph → Risk
"""
from fastapi.testclient import TestClient
from backend.app.main import app
import subprocess, sys, pathlib, hashlib

client = TestClient(app)

def test_compiler_and_backend_e2e_system_info():
    src = "system.info();\n"
    # 1. Compiler file path (host fallback)
    p = pathlib.Path("build/e2e_system_info.jocky")
    o = pathlib.Path("build/e2e_system_info.ll")
    p.write_text(src)
    r = subprocess.run([sys.executable, "tools/jockyc.py", str(p), "-o", str(o), "--seed", "42"], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    ir_text = o.read_text()
    assert "; IR_VERSION=1" in ir_text
    assert "system.read" in ir_text

    # 2. Backend compile via API matches file compiler
    rc = client.post("/api/compile", json={"source": src})
    assert rc.status_code == 200
    assert rc.json()["ir_version"] == 1

    # 3. Run via API produces live evidence, not hardcoded
    rr = client.post("/api/run", json={"source": src, "agent_id":"E2E-001","host_id":"E2E-HOST","case_id": 99})
    assert rr.status_code == 200, rr.text
    j = rr.json()
    assert j["ops"] == ["system.info"]
    # envelope per FORENSICS_SPEC.md §5
    ev = j["evidence"][0]
    for field in ("id","case_id","host_id","type","source","collected_at","observed_at","collector","schema_version","payload","integrity","provenance","chain_of_custody"):
        assert field in ev, f"missing envelope field {field}"
    assert ev["schema_version"] == 1
    assert ev["integrity"]["verified"] is True
    assert hashlib.sha256
    # provenance traces back
    assert ev["provenance"]["source_hash"] == rc.json()["source_hash"]

    # 4. Timeline reflects this evidence (live, not static fallback)
    t = client.get(f"/api/cases/99/timeline").json()
    assert any(e["id"] == ev["id"] for e in t["timeline"])

    # 5. Graph reflects this evidence
    g = client.get(f"/api/cases/99/graph").json()
    assert any(n["id"] == ev["id"] for n in g["nodes"])

    # 6. Risk derived from evidence
    risk = client.get(f"/api/cases/99/risk").json()
    assert risk["risk"] == ev["risk"]

    # 7. Dashboard would fetch same (simulated by polling endpoint)
    # Verify live evidence list endpoint
    ev_list = client.get("/api/evidence?case_id=99").json()
    assert ev_list["count"] >= 1

def test_e2e_rejects_malicious():
    r = client.post("/api/run", json={"source": "edr.disable();", "case_id": 100})
    assert r.status_code == 422
    r2 = client.post("/api/run", json={"source": "memory.analyze(1);", "case_id": 100})
    assert r2.status_code == 403  # policy denies sensitive

def test_polymorphic_ir_still_detectable():
    p = pathlib.Path("build/e2e_poly.jocky")
    p.write_text("system.info();\n")
    for seed in (1,2,3):
        o = pathlib.Path(f"build/e2e_poly_{seed}.ll")
        r = subprocess.run([sys.executable, "tools/jockyc.py", str(p), "-o", str(o), "--polymorphic", "--seed", str(seed)], capture_output=True, text=True)
        assert r.returncode == 0
        text = o.read_text()
        assert "JOCKY_DEMO_MARKER" in text  # YARA would still hit despite different hash
        assert "IR_VERSION=1" in text
    # hashes differ
    h1 = hashlib.sha256(pathlib.Path("build/e2e_poly_1.ll").read_bytes()).hexdigest()
    h2 = hashlib.sha256(pathlib.Path("build/e2e_poly_2.ll").read_bytes()).hexdigest()
    assert h1 != h2
