import hashlib, pathlib, subprocess, sys
from fastapi.testclient import TestClient
from backend.app.main import app
import tempfile, os

client = TestClient(app)

def _ir(src, seed, poly):
    from tools.jocky_lexer import build_ir_json
    import tools.jockyc as jc
    return jc.generate_ir(src, seed, poly)

SRC = "system.info();\nprocess.list();\nfile.hash(\"/evidence/sample.exe\");\n"

def test_three_hashes_distinct_same_yara_cluster():
    ir1 = _ir(SRC, 1, True)
    ir2 = _ir(SRC, 2, True)
    ir3 = _ir(SRC, 3, True)
    h1 = hashlib.sha256(ir1.encode()).hexdigest()
    h2 = hashlib.sha256(ir2.encode()).hexdigest()
    h3 = hashlib.sha256(ir3.encode()).hexdigest()
    assert len({h1,h2,h3})==3, "3 seeds must give 3 distinct hashes (hash != detection)"
    for ir in [ir1,ir2,ir3]:
        assert "JOCKY_DEMO_MARKER" in ir
        assert "LAB / SIMULATED" in ir
    # YARA cluster via API
    r = client.post("/api/yara/polymorphic-demo", json={"source": SRC, "seeds": [1,2,3], "polymorphic": True})
    assert r.status_code==200
    j=r.json()
    assert j.get("same_yara_cluster") is True
    assert j.get("distinct_hashes") is True or len(set(j.get("hashes",[])))==3

def test_deterministic_same_seed_same_ir():
    ir_a = _ir(SRC, 42, True)
    ir_b = _ir(SRC, 42, True)
    assert ir_a == ir_b, "same source+seed must give same IR (deterministic)"
    ir_c = _ir(SRC, 43, True)
    assert ir_a != ir_c

def test_lab_markers_present_and_reversible():
    ir = _ir(SRC, 7, True)
    assert "@LAB transform=import_shuffle" in ir
    assert "@LAB transform=string_encrypt" in ir
    assert "@LAB transform=cfg_flatten" in ir
    assert "LAB reversible" in ir
    assert "cfg-flatten:states=" in ir
    assert "string-encrypt:xor(key=" in ir
    assert "import-obfuscate:shuffled" in ir

def test_plain_ir_has_no_lab_markers():
    ir = _ir(SRC, 1, False)
    assert "LAB / SIMULATED" not in ir
    assert "@LAB transform" not in ir

def test_fail_closed_still_with_poly():
    r = client.post("/api/compile", json={"source": "edr.disable();", "seed": 1, "polymorphic": True})
    assert r.status_code==422
    r2 = client.post("/api/run", json={"source": "memory.analyze(1234);", "seed": 2, "polymorphic": True})
    assert r2.status_code==403
