from fastapi.testclient import TestClient
from backend.app.main import app
c = TestClient(app)

def test_file_hash_synthetic():
    r = c.post('/api/run', json={'source':'file.hash("/evidence/sample.exe");','case_id':30})
    assert r.status_code == 200, r.text
    ev = r.json()['evidence'][0]
    assert ev['payload']['path'] == "/evidence/sample.exe"
    assert 'hashes' in ev['payload']
    assert ev['payload']['yara_hit'] == "JOCKY_DEMO_MARKER"
    assert r.json()['risk'] >= 35

def test_file_hash_traversal_rejected():
    r = c.post('/api/run', json={'source':'file.hash("../../etc/passwd");','case_id':31})
    assert r.status_code == 400
    assert "traversal" in r.json()['detail'].lower() or "rejected" in r.json()['detail'].lower()

def test_process_list_rich():
    r = c.post('/api/run', json={'source':'process.list();','case_id':32})
    assert r.status_code == 200
    payload = r.json()['evidence'][0]['payload']
    # Phase 15 real: Windows returns >50 live + synthetic injected, Linux synthetic 4 — both satisfy contract ≥4
    assert len(payload['processes']) >= 4
    assert any(p.get('ppid_anomaly') for p in payload['processes'])
    assert r.json()['risk'] >= 30
    # Platform contract per FORENSICS §67: each proc has required fields
    for p in payload['processes'][:5]:
        assert "pid" in p and "ppid" in p and "name" in p and "path" in p

def test_network_connections():
    r = c.post('/api/run', json={'source':'network.connections();','case_id':33})
    assert r.status_code == 200
    conns = r.json()['evidence'][0]['payload']['connections']
    assert len(conns) >= 2
    assert any(cc['remote_address']=="192.0.2.20" for cc in conns)

def test_combined_investigation():
    src = 'system.info();\nprocess.list();\nfile.hash("/tmp/malware.exe");\nnetwork.connections();'
    r = c.post('/api/run', json={'source':src,'case_id':34})
    assert r.status_code == 200
    assert len(r.json()['evidence']) == 4
    assert r.json()['risk'] >= 30  # max across evidence types, file/process push risk
    g = c.get('/api/cases/34/graph').json()
    assert len(g['nodes']) >= 5  # host + 4 evidence + finding
    assert len(g['edges']) >= 4
    t = c.get('/api/cases/34/timeline').json()
    assert t['count'] == 4

def test_file_hash_without_arg_defaults():
    r = c.post('/api/run', json={'source':'file.hash("sample.exe");','case_id':35})
    assert r.status_code == 200
    assert r.json()['evidence'][0]['payload']['path'] == "sample.exe"
