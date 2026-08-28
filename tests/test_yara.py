from fastapi.testclient import TestClient
from backend.app.main import app
import hashlib

c = TestClient(app)

def test_yara_status():
    r = c.get('/api/yara/status')
    assert r.status_code == 200
    j = r.json()
    assert 'yara_rules' in j
    # host fallback: yara not necessarily available, but test_hits should contain marker
    assert 'JOCKY_DEMO_MARKER' in j['test_hits']

def test_yara_scan_string_fallback():
    r = c.post('/api/yara/scan', json={'content': 'JOCKY_DEMO_MARKER hello', 'filename': 'a.ll'})
    assert r.status_code == 200
    j = r.json()
    assert 'JOCKY_DEMO_MARKER' in j['hits']
    assert 'sha256' in j
    assert j['sha256'] == hashlib.sha256('JOCKY_DEMO_MARKER hello'.encode()).hexdigest()

def test_yara_scan_byovd():
    r = c.post('/api/yara/scan', json={'content': 'RTCore64.sys vulnerable', 'filename': 'drv.txt'})
    assert r.status_code == 200
    assert 'BYOVD_RTCore64' in r.json()['hits']

def test_yara_polymorphic_demo_hash_not_equal_but_yara_same():
    src = "system.info();\nprocess.list();"
    r = c.post('/api/yara/polymorphic-demo', json={'source': src, 'seeds': [1,2,3], 'polymorphic': True})
    assert r.status_code == 200
    j = r.json()
    assert j['distinct_hashes'] is True, "polymorphic should give distinct hashes"
    assert j['same_yara_cluster'] is True, "same yara hits despite different hash"
    # each should hit JOCKY_DEMO_MARKER
    for res in j['results']:
        assert 'JOCKY_DEMO_MARKER' in res['hits']
        assert len(res['sha256']) == 64

def test_detect_uses_yara():
    # payload containing marker should trigger via yara
    r = c.post('/api/detect', json={'JOCKY_DEMO_MARKER': True, 'hollowed': True})
    assert r.status_code == 200
    j = r.json()
    assert any(h['rule'] == 'JOCKY_DEMO_MARKER' for h in j['hits'])
    assert 'yara_used' in j

def test_compile_ir_yara_hit():
    # compile then yara scan IR should hit
    r = c.post('/api/compile', json={'source': 'system.info();'})
    assert r.status_code == 200
    ir = r.json()['ir']
    rr = c.post('/api/yara/scan', json={'content': ir, 'filename': 'test.ll'})
    assert 'JOCKY_DEMO_MARKER' in rr.json()['hits']
