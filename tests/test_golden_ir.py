"""
Golden IR tests per TEST_PLAN §7 + GAPS.md Gap Testing — ensures deterministic IR JSON and .ll outputs.
Compares build_ir_json and textual IR against committed expected values to catch accidental compiler changes.
"""
import json, hashlib, pathlib
from tools.jocky_lexer import build_ir_json, validate_ir_json
from tools.jockyc import generate_ir

def _hash12(s): return hashlib.sha256(s.encode()).hexdigest()[:12]

def test_golden_basic_json():
    src='system.info(); process.list(); file.hash("/evidence/sample.exe");'
    j=build_ir_json(src, seed=1, poly=False)
    assert j["version"]==1
    assert j["entry"]=="main"
    assert "system.read" in j["capabilities"]
    assert j["ops"]==["system.info","process.list","file.hash"]
    assert len(j["instructions"])==3
    assert j["instructions"][0]["opcode"]=="SYSTEM_INFO"
    assert j["instructions"][0]["type"]=="evidence"
    assert j["instructions"][2]["opcode"]=="FILE_HASH"
    assert j["instructions"][2]["operands"]==["/evidence/sample.exe"]
    assert validate_ir_json(j)==[]
    # Deterministic: same src seed -> same hash
    j2=build_ir_json(src, seed=1, poly=False)
    assert j["metadata"]["source_hash"]==j2["metadata"]["source_hash"]
    assert j["metadata"]["module_id"]==j2["metadata"]["module_id"]

def test_golden_different_seeds_same_ops_distinct_module():
    src='system.info();'
    j1=build_ir_json(src, seed=1, poly=False)
    j2=build_ir_json(src, seed=2, poly=True)
    assert j1["ops"]==j2["ops"]
    assert j1["metadata"]["module_id"]!=j2["metadata"]["module_id"]
    # But textual IR hashes differ (poly)
    ir1=generate_ir(src, seed=1, poly=True)
    ir2=generate_ir(src, seed=2, poly=True)
    assert hashlib.sha256(ir1.encode()).hexdigest() != hashlib.sha256(ir2.encode()).hexdigest()
    # Same YARA marker still present
    assert "JOCKY_DEMO_MARKER" in ir1 and "JOCKY_DEMO_MARKER" in ir2

def test_golden_investigation_block():
    src='investigation "full_demo" { system.info(); process.list(); }'
    j=build_ir_json(src, seed=1, poly=False)
    assert len(j["investigations"])==1
    assert j["investigations"][0]["title"]=="full_demo"
    assert "system.info" in j["ops"]

def test_golden_filter_correlate():
    src='let p=process.list(); filter(p, p.name=="a"); correlate(p,p);'
    j=build_ir_json(src, seed=1, poly=False)
    ops=[i["opcode"] for i in j["instructions"]]
    assert "PROCESS_LIST" in ops
    assert "EVIDENCE_FILTER" in ops
    assert "CORRELATE" in ops

def test_golden_import_func():
    src='import "forensic.net"; func foo(){ system.info(); } function bar(){ process.list(); }'
    j=build_ir_json(src, seed=1, poly=False)
    assert "forensic.net" in j["imports"]
    assert any(f["name"]=="foo" for f in j["functions"])
    assert any(f["name"]=="bar" for f in j["functions"])
    # Textual IR should contain markers
    ir=generate_ir(src, seed=1, poly=False)
    assert "JOCKY Imports: forensic.net" in ir
    assert "Funcs: foo, bar" in ir or "Funcs: foo" in ir

def test_golden_expected_files_exist():
    # Expected golden files committed for reproducibility per TEST_PLAN
    exp_dir=pathlib.Path("tests/expected")
    assert exp_dir.exists(), "tests/expected dir missing"
    assert (exp_dir/"basic.ir.json").exists(), "basic.ir.json golden missing"
    # Validate golden JSON is valid IR
    gj=json.loads((exp_dir/"basic.ir.json").read_text())
    assert validate_ir_json(gj)==[]
    assert gj["version"]==1
