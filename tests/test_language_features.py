"""
Language features P1 per LANGUAGE_SPEC §7, §11, §12, §15 + IR_SPEC §18
"""
from fastapi.testclient import TestClient
from backend.app.main import app
from tools.jocky_lexer import validate_and_collect

client = TestClient(app)

def test_variable_assignment():
    src = 'processes = process.list();'
    ops, caps, errs, toks, calls = validate_and_collect(src)
    assert errs == [], errs
    assert ops == ["process.list"]

def test_let_assignment():
    src = 'let procs = process.list();'
    ops, caps, errs, toks, calls = validate_and_collect(src)
    assert errs == []
    assert "process.list" in ops

def test_investigation_block_extracts_title_and_ops():
    src = 'investigation "host_scan" {\n  system.info();\n  process.list();\n}'
    ops, caps, errs, toks, calls = validate_and_collect(src)
    assert errs == [], errs
    assert "system.info" in ops and "process.list" in ops
    # via API, should create case with title
    r = client.post("/api/run", json={"source": src, "case_id": 910})
    assert r.status_code==200, r.text
    # case should have title host_scan
    cases = client.get("/api/cases").json()["cases"]
    c = next((x for x in cases if x["id"]==910), None)
    assert c is not None and "host_scan" in c["title"]

def test_investigation_block_with_filter():
    src = 'investigation "filter_test" {\n  processes = process.list();\n  filtered = filter(processes, process.name == "explorer.exe");\n  file.hash("/evidence/sample.exe");\n}'
    ops, caps, errs, toks, calls = validate_and_collect(src)
    assert errs == [], errs
    assert "process.list" in ops and "file.hash" in ops
    # filter is not an op, but should not error
    r = client.post("/api/run", json={"source": src, "case_id": 911})
    assert r.status_code==200
    assert len(r.json()["evidence"]) >= 2

def test_filter_requires_two_args():
    src = 'filter(processes);'
    ops, caps, errs, toks, calls = validate_and_collect(src)
    assert any("filter" in e.lower() for e in errs)

def test_correlate_requires_two_args():
    src = 'correlate(a);'
    ops, caps, errs, toks, calls = validate_and_collect(src)
    assert any("correlate" in e.lower() for e in errs)
    src2 = 'correlate(a, b);'
    ops2, caps2, errs2, toks2, calls2 = validate_and_collect(src2)
    assert errs2 == []

def test_combined_investigation_filter_correlate():
    src = '''
    investigation "combined" {
      procs = process.list();
      conns = network.connections();
      correlate(procs, conns);
      file.hash("/evidence/sample.exe");
    }
    '''
    ops, caps, errs, toks, calls = validate_and_collect(src)
    assert errs == [], errs
    assert "process.list" in ops
    # via API
    r = client.post("/api/run", json={"source": src, "case_id": 912})
    assert r.status_code==200
    assert r.json()["case_id"]==912

def test_unknown_op_still_fail_closed_in_investigation():
    src = 'investigation "bad" { edr.disable(); }'
    ops, caps, errs, toks, calls = validate_and_collect(src)
    assert any("edr.disable" in e for e in errs)
    r = client.post("/api/run", json={"source": src, "case_id": 913})
    assert r.status_code==422

def test_variable_assignment_with_evidence_load():
    src = 'ev = evidence.load("testdata/hollowing.json");'
    ops, caps, errs, toks, calls = validate_and_collect(src)
    assert errs == []
    assert ops == ["evidence.load"]
    r = client.post("/api/run", json={"source": src, "case_id": 914})
    assert r.status_code==200
    assert r.json()["evidence"][0]["payload"]["source"]=="evidence.load"
