import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))
from fastapi.testclient import TestClient
from backend.app.main import app
import json, time, hashlib

c=TestClient(app)
from backend.app.detection_engine import detect

pos_cases = [
    ('hollowing', 'evidence.load("testdata/hollowing.json");'),
    ('byovd', 'evidence.load("testdata/byovd_driver.json");'),
    ('file', 'file.hash("/evidence/sample.exe");'),
    ('process', 'process.list();'),
    ('network', 'network.connections();'),
]

pos_hits = 0
for name, src in pos_cases:
    r = c.post('/api/run', json={'source': src, 'case_id': 9000})
    j = r.json()
    ev = j['evidence'][0] if j.get('evidence') else {}
    payload = ev.get('payload',{}) if ev else {}
    hits = detect(payload)
    has_hit = len(hits) > 0
    print(f'{name}: hits={len(hits)} risk={ev.get("risk",0)} -> {[h["rule"] for h in hits]}')
    if has_hit:
        pos_hits+=1

benign_payloads = [
    {'type':'process','processes':[{'pid':1,'name':'explorer.exe','ppid_anomaly':False}]},
    {'type':'file','path':'/evidence/benign.txt','yara_hit':None},
    {'type':'system','hostname':'PC-01'},
]
neg_fp=0
for p in benign_payloads:
    hits = detect(p)
    if hits:
        neg_fp+=1
    print(f'benign {p["type"]}: hits={len(hits)} -> {hits}')

print(f'positive hit rate: {pos_hits}/{len(pos_cases)}')
print(f'false positives: {neg_fp}/{len(benign_payloads)}')

from backend.app.main import yara_scan_content
from tools.jockyc import generate_ir
src='system.info(); process.list(); file.hash("/evidence/sample.exe");'
for seed in [1,2,3]:
    ir = generate_ir(src, seed, True)
    hits, used = yara_scan_content(ir)
    print(f'seed {seed} sha12 {hashlib.sha256(ir.encode()).hexdigest()[:12]} hits={hits} yara_used={used}')

times=[]
src2='process.list(); file.hash("/evidence/sample.exe"); network.connections();'
for i in range(100):
    t0=time.perf_counter()
    c.post('/api/run', json={'source': src2, 'case_id': 8000+i, 'platform':'linux'})
    times.append((time.perf_counter()-t0)*1000)
times=sorted(times)
print(f'latency p50={times[50]:.2f} p95={times[95]:.2f} avg={sum(times)/len(times):.2f} min={times[0]:.2f} max={times[-1]:.2f}ms')
