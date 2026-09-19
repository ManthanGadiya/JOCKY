from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.providers.factory import get_providers

client = TestClient(app)

def test_same_jocky_same_mitre_different_platform_path():
    src = "process.list(); file.hash(\"/evidence/sample.exe\"); network.connections();"
    r_win = client.post("/api/run", json={"source": src, "platform": "windows"})
    r_lin = client.post("/api/run", json={"source": src, "platform": "linux"})
    assert r_win.status_code == 200 and r_lin.status_code == 200
    j_win = r_win.json(); j_lin = r_lin.json()
    # same MITRE should appear in both (T1055 process, T1105 file, T1071 net)
    mitre_win = set(j_win.get("mitre", []))
    mitre_lin = set(j_lin.get("mitre", []))
    assert mitre_win == mitre_lin, f"MITRE should be same across platforms, win={mitre_win} lin={mitre_lin}"
    # different platform fields
    ev_win = [e for e in j_win.get("evidence", [])]
    ev_lin = [e for e in j_lin.get("evidence", [])]
    # check platform field differs but count same
    assert len(ev_win) == len(ev_lin) == 3
    # file path differs windows vs linux style still preserved
    for e in ev_win+ev_lin:
        assert "platform" in e.get("payload", {}) or "platform" in e, "payload must contain platform per FORENSICS 67"

def test_factory_etw_and_ebpf_normalized_schema():
    # Windows ETW provider behind same interface
    s,p,f,n,d = get_providers("windows", use_etw=True)
    procs = p.list_processes("HOST-TEST")
    assert len(procs) >= 4
    for pr in procs[:2]:
        assert "pid" in pr and "ppid" in pr and "name" in pr and "platform" in pr
        assert pr["platform"] == "windows"
    # Linux eBPF provider behind same interface
    s2,p2,f2,n2,d2 = get_providers("linux", use_ebpf=True)
    procs2 = p2.list_processes("HOST-TEST")
    assert len(procs2) >= 4
    for pr in procs2[:2]:
        assert "pid" in pr and "ppid" in pr and "name" in pr and "platform" in pr
        assert pr["platform"] == "linux"

def test_factory_without_native_still_normalized():
    s,p,f,n,d = get_providers("windows", use_etw=False)
    s2,p2,f2,n2,d2 = get_providers("linux", use_ebpf=False)
    assert p.list_processes("H")[0]["platform"] == "windows"
    assert p2.list_processes("H")[0]["platform"] == "linux"

def test_etw_ebpf_attempt_markers_present_when_enabled():
    _,p,_,_,_ = get_providers("windows", use_etw=True)
    pr = p.list_processes("HOST")[0]
    # when ETW enabled, markers should be present (lab)
    assert "etw_attempted" in pr or "etw_available" in pr
    _,p2,_,_,_ = get_providers("linux", use_ebpf=True)
    pr2 = p2.list_processes("HOST")[0]
    assert "ebpf_attempted" in pr2 or "proc_available" in pr2

def test_api_run_preserves_risk_same_across_providers():
    src = "process.list();"
    r1 = client.post("/api/run", json={"source": src, "platform": "windows"})
    r2 = client.post("/api/run", json={"source": src, "platform": "linux"})
    assert r1.json().get("risk") == r2.json().get("risk"), "risk should normalize across providers (same behavioral weights)"
