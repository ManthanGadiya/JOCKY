"""
Platform provider contract tests per ARCHITECTURE.md §8 + DESIGN.md §22-23 + TEST_PLAN.md §55-57
Verifies: same JOCKY op → different adapters → common normalized schema (FORENSICS_SPEC §67)
Covers: IProcessProvider/IFileProvider/INetworkProvider contract + factory + /api/run platform param
"""
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.providers.factory import get_providers, detect_platform, platform_from_request
from backend.app.providers.base import IProcessProvider, IFileProvider

client = TestClient(app)

def test_factory_returns_correct_platform():
    win = get_providers("windows")
    lin = get_providers("linux")
    assert win[0].__class__.__name__ == "WindowsSystemProvider"
    assert lin[0].__class__.__name__ == "LinuxSystemProvider"

def test_process_provider_contract_windows_vs_linux():
    _, win_proc, _, _, _ = get_providers("windows")
    _, lin_proc, _, _, _ = get_providers("linux")
    for prov in (win_proc, lin_proc):
        procs = prov.list_processes("HOST-001")
        assert len(procs) >= 4
        # Common contract per FORENSICS_SPEC §11 + TEST_PLAN §57: required fields
        for p in procs:
            for field in ("pid","ppid","name","path"):
                assert field in p, f"missing {field} in {p}"
            assert isinstance(p["pid"], int)
            assert isinstance(p["name"], str)
        # Platform-specific field preserved but not breaking schema
        assert any(p.get("platform")=="windows" for p in win_proc.list_processes("X"))
        assert any(p.get("platform")=="linux" for p in lin_proc.list_processes("X"))
        # Sigma correlation same T1055 preserved across platforms (FORENSICS_SPEC §43)
        assert any(p.get("sigma_hit") for p in procs)

def test_file_provider_contract():
    _, _, win_file, _, _ = get_providers("windows")
    _, _, lin_file, _, _ = get_providers("linux")
    for prov, plat in ((win_file,"windows"),(lin_file,"linux")):
        data = prov.hash_file("/evidence/sample.exe" if plat=="linux" else "C:\\Evidence\\sample.exe","HOST-001")
        assert data["platform"]==plat
        assert "hashes" in data and "sha256" in data["hashes"]
        assert data["yara_hit"]=="JOCKY_DEMO_MARKER"
        assert data["type"]=="file"

def test_network_provider_contract():
    _, _, _, win_net, _ = get_providers("windows")
    _, _, _, lin_net, _ = get_providers("linux")
    for prov in (win_net, lin_net):
        conns = prov.list_connections("HOST-001")
        for c in conns:
            for field in ("local_address","remote_address","protocol","state"):
                assert field in c

def test_platform_from_request_priority():
    assert platform_from_request("windows", None)=="windows"
    assert platform_from_request(None, "linux")=="linux"
    # env fallback returns one of them (not error)
    assert platform_from_request(None, None) in ("windows","linux")

def test_api_run_platform_param_windows():
    r = client.post("/api/run", json={"source": "system.info();\nprocess.list();", "case_id": 501, "platform": "windows"})
    assert r.status_code==200, r.text
    j = r.json()
    # payload platform should be windows for each evidence
    for ev in j["evidence"]:
        assert ev["payload"].get("platform")=="windows"
        # process evidence should have Windows path C:
        if ev["type"]=="process":
            assert any("C:\\" in p.get("path","") for p in ev["payload"].get("processes",[]))

def test_api_run_platform_param_linux():
    r = client.post("/api/run", json={"source": "system.info();\nprocess.list();", "case_id": 502, "platform": "linux"})
    assert r.status_code==200, r.text
    for ev in r.json()["evidence"]:
        assert ev["payload"].get("platform")=="linux"
        if ev["type"]=="process":
            # Linux processes have /usr or /tmp paths and uid field
            procs = ev["payload"].get("processes",[])
            assert any(p.get("uid") is not None for p in procs)

def test_api_run_platform_invalid_rejected():
    r = client.post("/api/run", json={"source": "system.info();", "case_id": 503, "platform": "macos"})
    assert r.status_code==400

def test_api_run_same_jocky_different_platform_same_findings():
    # Same JOCKY, different adapters → same MITRE findings but different payload platform (ARCHITECTURE §8)
    src = 'file.hash("/evidence/sample.exe");'
    rw = client.post("/api/run", json={"source": src, "case_id": 504, "platform": "windows"}).json()
    rl = client.post("/api/run", json={"source": src, "case_id": 505, "platform": "linux"}).json()
    assert len(rw["evidence"])==1 and len(rl["evidence"])==1
    assert rw["evidence"][0]["payload"]["mitre"]==rl["evidence"][0]["payload"]["mitre"]=="T1105"
    assert rw["evidence"][0]["payload"]["platform"]=="windows"
    assert rl["evidence"][0]["payload"]["platform"]=="linux"
    # risk same (same YARA hit) even though platform differs — demonstrates normalization
    assert rw["evidence"][0]["risk"]==rl["evidence"][0]["risk"]

def test_jocky_language_platform_agnostic():
    # LANGUAGE_SPEC §27: same JOCKY source should be valid on either platform
    for plat in ("windows","linux"):
        r = client.post("/api/compile", json={"source": "process.list();"})
        assert r.status_code==200
        # compile always succeeds (platform chosen at run time, not compile time per IR_SPEC §28)
        assert r.json()["ops"]==["process.list"]
