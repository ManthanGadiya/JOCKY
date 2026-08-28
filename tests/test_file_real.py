from fastapi.testclient import TestClient
from backend.app.main import app
import hashlib
c=TestClient(app)

def test_file_real_sample_vs_clean():
    c.post('/api/reset', json={})
    r=c.post('/api/run', json={'source':'file.hash("/evidence/sample.exe");','case_id':500})
    assert r.status_code==200
    ev=r.json()['evidence'][0]['payload']
    assert ev['yara_hit']=="JOCKY_DEMO_MARKER"
    assert 'real_path' in ev
    # hash should be of file content, not path string
    assert ev['hashes']['sha256'] != hashlib.sha256(b'/evidence/sample.exe').hexdigest()
    c.post('/api/reset', json={'case_id':500})
    r2=c.post('/api/run', json={'source':'file.hash("/evidence/clean.txt");','case_id':501})
    ev2=r2.json()['evidence'][0]['payload']
    assert ev2['yara_hit'] is None
    assert ev['hashes']['sha256'] != ev2['hashes']['sha256']

def test_malware_variants_different_hash():
    c.post('/api/reset', json={})
    r3=c.post('/api/run', json={'source':'file.hash("/evidence/malware_1.bin");','case_id':502})
    r4=c.post('/api/run', json={'source':'file.hash("/evidence/malware_2.bin");','case_id':503})
    assert r3.json()['evidence'][0]['payload']['hashes']['sha256'] != r4.json()['evidence'][0]['payload']['hashes']['sha256']
    assert r3.json()['evidence'][0]['payload']['yara_hit']=="JOCKY_DEMO_MARKER"
    assert r4.json()['evidence'][0]['payload']['yara_hit']=="JOCKY_DEMO_MARKER"
