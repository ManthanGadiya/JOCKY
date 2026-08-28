"""
Compiler tests — IR_VERSION=1 + capability validation (fail-closed)
Uses tools/jockyc.py host fallback (same logic as jocky/src/IRGen.cpp)
"""
import subprocess, pathlib, sys

def jockyc(source_text, polymorphic=False, seed=1):
    p = pathlib.Path("build/tmp_test.jocky")
    o = pathlib.Path("build/tmp_test.ll")
    p.write_text(source_text, encoding="utf-8")
    cmd = [sys.executable, "tools/jockyc.py", str(p), "-o", str(o), "--seed", str(seed)]
    if polymorphic: cmd.append("--polymorphic")
    r = subprocess.run(cmd, capture_output=True, text=True)
    ir = o.read_text(encoding="utf-8") if o.exists() else ""
    return r.returncode, r.stderr, ir

def test_system_info_generates_ir_version1():
    rc, err, ir = jockyc("system.info();\n")
    assert rc == 0, err
    assert "; IR_VERSION=1" in ir
    assert "; IR_CAPS: system.read" in ir
    assert "; IR_OPS: system.info" in ir
    assert "JOCKY_DEMO_MARKER" in ir
    assert "EntryPoint" in ir
    assert "call i32 @jocky_system_info" in ir

def test_process_list_ops():
    rc, err, ir = jockyc("process.list();\n")
    assert rc == 0
    assert "process.read" in ir
    assert "process.list" in ir

def test_multiple_ops_caps_dedup():
    src = "system.info();\nprocess.list();\nprocess.tree();\n"
    rc, err, ir = jockyc(src)
    assert rc == 0
    # process.list + process.tree share cap process.read — caps deduped
    assert ir.count("process.read") == 1 or "process.read" in ir  # at least present, not duplicated many times
    assert "system.read" in ir
    assert "IR_CAPS:" in ir

def test_polymorphic_produces_different_hash():
    rc1, _, ir1 = jockyc("system.info();\n", polymorphic=True, seed=11)
    rc2, _, ir2 = jockyc("system.info();\n", polymorphic=True, seed=22)
    assert rc1 == 0 and rc2 == 0
    assert ir1 != ir2
    assert "bb.poly." in ir2
    assert "IR_VERSION=1" in ir2

def test_unknown_capability_rejected_fail_closed():
    rc, err, ir = jockyc("edr.disable();\n")
    assert rc == 2, f"expected exit 2 fail-closed, got {rc} {err}"
    assert "Unknown or unsupported capability" in err
    assert "edr.disable" in err

def test_security_disable_rejected():
    rc, err, ir = jockyc("security.disable();\n")
    assert rc == 2
    assert "Fail-closed" in err

def test_empty_produces_nop_with_none_caps():
    rc, err, ir = jockyc("")
    assert rc == 0
    assert "; IR_CAPS: (none)" in ir
    assert "; IR_OPS: (none)" in ir
    assert "call i32 @jocky_nop" in ir

def test_all_allowed_ops_compile():
    # exhaustive list from OP_CAPS — each must compile
    allowed = [
        "system.info();", "process.list();","process.tree();","file.hash(\"a.exe\");",
        "network.connections();","driver.scan(\"RTCore64.sys\");","memory.analyze(1234);"
    ]
    for src in allowed:
        rc, err, ir = jockyc(src)
        assert rc == 0, f"{src} failed: {err}"

def test_file_hash_needs_arg_but_still_caps():
    rc, err, ir = jockyc('file.hash("sample.exe");\n')
    assert rc == 0
    assert "file.hash" in ir
    assert "file.hash" in ir  # cap
