# JOCKY DEMO SCRIPT (2 min — Ship P3, 152 tests, main ffbd33c → P1/P2 + Ship)

## 0. Pre-check (host, no Docker — 20s)
python tools/jockyc.py examples/test.jocky -o build/a.ll --seed 1
python tools/jockyc.py examples/test.jocky --polymorphic -o build/b.ll --seed 2
python tools/jockyc.py examples/test.jocky --polymorphic -o build/c.ll --seed 3
certutil -hashfile build\a.ll SHA256 & certutil -hashfile build\b.ll SHA256 & certutil -hashfile build\c.ll SHA256
REM 3 hashes differ
findstr JOCKY_DEMO_MARKER build\*.ll
REM all 3 hit same YARA → 1 cluster (Point 1+2)
python -m pytest -q
REM → 152 passed (compiler 9 + backend 13 + e2e 3 + forensic 6 + report 4 + yara 6 + agent 8 + grammar 12 + platform 10 + detection 11 + storage 8 + isolation 5 + report-harden 3 + correlation 6 + auth 8 + timeline 6 + sigma-tune 6 + evidence-load 9 + frontend-report 1 + language 9 + hardening 9)

## 1. Full stack via Docker (40s)
docker compose build
docker compose up
# In another terminal:
docker compose ps
REM → 9 Up: jocky, agent (python via nginx), backend :8000, frontend :3000, db healthy, redis, minio, nginx 8082, detector
curl http://localhost:8000/health
REM → {"status":"ok","jocky_ir_version":1,"db":true,"yara":true,"yara_rules":"/app/yara/rules.yar","minio":true,"redis":true,"auth_required":false}
curl http://localhost:8000/api/sigma/rules
REM → 2 rules jocky-001 T1055, jocky-002 T1068
curl http://localhost:8000/api/cases
REM → [] or existing cases

## 2. JOCKY via API (30s)
curl -X POST http://localhost:8000/api/compile -H "Content-Type: application/json" -d "{\"source\":\"system.info();\\nprocess.list();\\nfile.hash(\\\"/evidence/sample.exe\\\");\"}"
REM → ir_version 1, IR_CAPS, 422 on edr.disable, 403 on memory.analyze (fail-closed at 1:1)

curl -X POST http://localhost:8000/api/run -H "Content-Type: application/json" -d "{\"source\":\"system.info();\\nprocess.list();\\nfile.hash(\\\"/evidence/sample.exe\\\");\\nnetwork.connections();\\nevidence.load(\\\"testdata/hollowing.json\\\");\",\"case_id\":1,\"platform\":\"windows\"}"
REM → 5 evidences, risk 60+ (process Sigma + file YARA + hollowing), star host→evidence + process→file/net + temporal/pid correlations

curl http://localhost:8000/api/cases/1/graph | python -m json.tool
REM → nodes 6+, edges with weight, correlations [{process→file 0.85, process→net 0.9, temporal 0.6}] + mitre T1055/T1105/T1071

curl http://localhost:8000/api/cases/1/risk/history | python -m json.tool
REM → history [{evidence_id, risk, cumulative_max}] + breakdown via /risk/breakdown

curl -X POST http://localhost:8000/api/auth/login -H "Content-Type: application/json" -d "{\"username\":\"analyst\"}"
REM → {access_token: "eyJ...HS256", token_type:"bearer"}

## 3. Frontend (50s)
open http://localhost:3000
# SHOW:
# - Top bar: 9 services, IR v1, YARA ✅ binary 5 rules, Postgres ✅, MinIO+Redis ✅
# - Case bar: dropdown case-1 + New Case, host/type/platform filters, filtered count
# - YARA panel: Run YARA Poly Demo → 3 hashes distinct but same cluster
# - JOCKY Editor: Compile (IR v1) + Run (linux|windows) + full sweep / evidence.load / investigation "demo" { } / traversal fail
# - Graph: ReactFlow live, click node → Selected chip + expand (GET /graph/expand?node_id=)
# - Timeline: search + minRisk filter (all/≥30/≥60/≥80) + click
# - RiskGauge: bar + sparkline history (last 20) + detail breakdown (per-evidence behavioral/sigma) + links /risk/history /risk/breakdown
# - Findings: severity colors, Mitre T1055/T1068/T1105
# - Reports History + Sigma panels: list versioned reports + dl, sigma rules + tune + Auto-Tune
# - Download Report PDF button → JOCKY_case_1_report.pdf (20KB %PDF, X-Report-Cached on second fetch, stored MinIO jocky-reports)

## PPT line
Defensive forensics: synthetic evidence + controlled fixtures + hash≠detection (3 IRs → 1 YARA cluster) — no kernel exploitation, no EDR bypass, all Docker reproducible.
