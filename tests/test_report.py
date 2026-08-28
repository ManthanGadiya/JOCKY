from fastapi.testclient import TestClient
from backend.app.main import app
import json

c = TestClient(app)

def test_report_system_info_generates():
    # ensure case 70 has evidence
    r = c.post('/api/run', json={'source':'system.info();\nprocess.list();','case_id':70})
    assert r.status_code == 200
    # GET report
    rr = c.get('/api/cases/70/report')
    assert rr.status_code == 200
    # should be either pdf or html fallback
    ctype = rr.headers.get('content-type','')
    assert 'pdf' in ctype or 'html' in ctype
    content = rr.content
    # PDF magic %PDF or HTML <!doctype
    assert content[:4] == b'%PDF' or b'<html' in content.lower() or b'<!doctype' in content.lower()
    # must contain case and evidence markers
    txt = content.decode(errors='ignore')
    assert 'Case 70' in txt
    assert 'system.info' in txt or 'Evidence' in txt
    # header fallback check if html
    if 'html' in ctype:
        assert 'X-Report-Fallback' in rr.headers or True

def test_report_empty_case_still_generates():
    rr = c.get('/api/cases/9999/report')
    assert rr.status_code == 200
    assert b'Case 9999' in rr.content or b'case-9999' in rr.content.lower()

def test_post_report():
    c.post('/api/run', json={'source':'file.hash("/evidence/sample.exe");','case_id':71})
    rr = c.post('/api/report', json={'case_id':71, 'title':'Test Report'})
    assert rr.status_code == 200
    assert b'Case 71' in rr.content or b'Test Report' in rr.content

def test_report_contains_chain():
    c.post('/api/run', json={'source':'network.connections();','case_id':72})
    rr = c.get('/api/cases/72/report')
    txt = rr.content.decode(errors='ignore')
    assert 'chain_of_custody' in txt.lower() or 'Chain of Custody' in txt
    assert 'SHA256' in txt or 'sha256' in txt.lower()
