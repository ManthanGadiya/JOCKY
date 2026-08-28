from fastapi.testclient import TestClient
from backend.app.main import app
import pathlib

c = TestClient(app)

def test_gibberish_rejected_422_compile():
    r = c.post('/api/compile', json={'source': 'system.i.lisidence/saons();'})
    assert r.status_code == 422
    assert 'Syntax error' in r.json()['detail'] or 'no valid' in r.json()['detail'].lower()

def test_gibberish_rejected_422_run():
    r = c.post('/api/run', json={'source': 'system.i.lisidence/saons();'})
    assert r.status_code == 422

def test_empty_still_nop():
    # empty should still succeed with nop (not rejected) - bug 2 fix should not break empty
    r = c.post('/api/compile', json={'source': ''})
    assert r.status_code == 200
    assert r.json()['ops'] == []

def test_reset_case():
    # create case 400
    c.post('/api/run', json={'source': 'system.info();', 'case_id': 400})
    assert c.get('/api/evidence?case_id=400').json()['count'] == 1
    # run again -> stacked to 2 (bug 1 before fix would stack)
    c.post('/api/run', json={'source': 'system.info();', 'case_id': 400})
    assert c.get('/api/evidence?case_id=400').json()['count'] == 2
    # reset should clear
    r = c.post('/api/reset', json={'case_id': 400})
    assert r.status_code == 200
    assert c.get('/api/evidence?case_id=400').json()['count'] == 0

def test_reset_all():
    c.post('/api/run', json={'source': 'system.info();', 'case_id': 401})
    c.post('/api/run', json={'source': 'process.list();', 'case_id': 402})
    assert c.get('/api/evidence').json()['count'] >= 2
    r = c.post('/api/reset', json={})
    assert r.status_code == 200
    assert c.get('/api/evidence').json()['count'] == 0

def test_examples_list():
    r = c.get('/api/examples')
    assert r.status_code == 200
    assert r.json()['count'] >= 7
    names = [e['name'] for e in r.json()['examples']]
    assert '01_system_info.jocky' in names
    assert '05_full_sweep.jocky' in names

def test_examples_fetch_content():
    r = c.get('/api/examples/01_system_info.jocky')
    assert r.status_code == 200
    assert 'system.info()' in r.json()['content']

def test_examples_traversal_blocked():
    r = c.get('/api/examples/..%2Fbackend%2Fapp%2Fmain.py')
    # FastAPI will 404 for path with slash, but we also explicitly block .. -> 400 if it reaches handler; accept either
    assert r.status_code in (400, 404)

def test_different_examples_different_evidence():
    # run 01 vs 02 should give different types (ids will be same after reset -> both 000001, so check type not id)
    c.post('/api/reset', json={})
    c.post('/api/run', json={'source': 'system.info();', 'case_id': 410})
    sys_ev = c.get('/api/evidence?case_id=410').json()['evidence'][0]
    c.post('/api/reset', json={'case_id': 410})
    c.post('/api/run', json={'source': 'process.list();', 'case_id': 410})
    proc_ev = c.get('/api/evidence?case_id=410').json()['evidence'][0]
    assert sys_ev['type'] == 'system'
    assert proc_ev['type'] == 'process'
    # ids are reset to 000001 after clear, so not necessarily different; check payload distinction
    assert sys_ev['payload']['type'] != proc_ev['payload']['type']

def test_file_hash_example_produces_different_payload():
    c.post('/api/reset', json={})
    # load example content via API
    content = c.get('/api/examples/03_file_hash.jocky').json()['content']
    r = c.post('/api/run', json={'source': content, 'case_id': 411})
    assert r.status_code == 200
    assert any(e['type'] == 'file' for e in r.json()['evidence'])
