# JOCKY DEMO SCRIPT (2 min - for judges)

## Terminal Demo (Point 1+2) - 40 sec
# In D:\SIH
python tools/jockyc.py examples/test.jocky -o build/a.ll --seed 1
python tools/jockyc.py examples/test.jocky --polymorphic -o build/b.ll --seed 2
python tools/jockyc.py examples/test.jocky --polymorphic -o build/c.ll --seed 3
certutil -hashfile build\a.ll SHA256
certutil -hashfile build\b.ll SHA256
certutil -hashfile build\c.ll SHA256
# SHOW: 3 different hashes
findstr JOCKY_DEMO_MARKER build\*.ll
# SHOW: all 3 hit same YARA -> 1 cluster

# Docker version (same, inside container):
docker compose run --rm jocky bash -c "jockyc examples/test.jocky -o /tmp/a.ll --seed 1 && jockyc examples/test.jocky --polymorphic -o /tmp/b.ll --seed 2 && sha256sum /tmp/*.ll && grep JOCKY_DEMO_MARKER /tmp/*.ll"

## Backend Demo (L6+L7) - 20 sec
cd backend; python -m uvicorn app.main:app --port 8000 &
curl http://localhost:8000/health
curl -X POST http://localhost:8000/api/evidence -d @../testdata/hollowing.json -H "Content-Type: application/json"
curl http://localhost:8000/api/cases/1/risk  # -> 90 CRITICAL

## Frontend Demo (L8) - 40 sec
docker compose up  # or npm run dev in frontend
open http://localhost:3000
# SHOW: Graph (User->Process->File->Network->Driver->Finding), Timeline 10:30-10:33, Risk 90 CRITICAL, MITRE T1055/T1068, AI explainer, Download PDF

## PPT Line
Adversary emulation on synthetic data - detection only, no kernel exploitation, all Docker.
