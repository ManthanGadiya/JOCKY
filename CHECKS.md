# CHECKS FOR TEAMMATE LAPTOP (Docker-only) — Ship P3 + Phase 15 Real (157 tests)

Already done: Windows 11 + WSL2 Ubuntu-24.04 + Docker Desktop (WSL Integration ON) — see `docs/STATUS.md §7`

Run:
wsl --list -v
docker --version
docker compose version
docker ps
docker run hello-world

Need: Free C: >10GB, D:\SIH 110GB free (psutil + yara + pango layers)
No host LLVM/CMake/Java - all inside Dockerfile (clang/llvm + antlr4 + yara 4.5.2 + psutil)

Verify (no Docker needed — 157 host):
python tools/jockyc.py examples/test.jocky -o build/a.ll --seed 1
python tools/jockyc.py examples/test.jocky --polymorphic -o build/b.ll --seed 2
certutil -hashfile build\a.ll SHA256
certutil -hashfile build\b.ll SHA256
# hashes differ + both contain JOCKY_DEMO_MARKER/EntryPoint/bb.poly.* = Point 1+2 pass
python -m pytest -q
# → 157 passed (compiler 9 + backend 13 + e2e 3 + forensic 6 + report 4 + yara 6 + agent 8 + grammar 12 + platform 10 + detection 11 + storage 8 + isolation 5 + report-harden 3 + correlation 6 + auth 8 + timeline 6 + sigma-tune 6 + evidence-load 9 + frontend-report 1 + language 9 + hardening 9 + phase15 5)

# Evidence.load + platform wiring (P0 + Phase 15) — host fallback, no Docker:
python -c "from fastapi.testclient import TestClient; from backend.app.main import app; c=TestClient(app); print(c.post('/api/run', json={'source': 'evidence.load(\"testdata/hollowing.json\");', 'case_id': 1}).json()['evidence'][0]['payload']['source'])"
curl -X POST http://localhost:8000/api/run -H "Content-Type: application/json" -d "{\"source\":\"process.list();\",\"case_id\":1,\"platform\":\"windows\"}"  | python -m json.tool | findstr platform
curl -X POST http://localhost:8000/api/run -H "Content-Type: application/json" -d "{\"source\":\"process.list();\",\"case_id\":1,\"platform\":\"linux\"}"  | python -m json.tool | findstr platform
# → windows vs linux same MITRE T1055 but different platform + path/uid per FORENSICS §67; Windows live psutil 50+ on Windows host, Linux synthetic fallback

With Docker (full stack — 9 services):
# If auth.docker.io flakes for node:20-alpine, retry: docker compose build agent backend --no-cache
docker compose build          # ~10 min first time (pulls ubuntu:22.04 + python:3.11-slim + node:20-alpine + yara + pango + psutil)
docker compose run --rm jocky bash -c "jockyc examples/test.jocky -o /tmp/a.ll --seed 1 && jockyc examples/test.jocky --polymorphic -o /tmp/b.ll --seed 2 && sha256sum /tmp/*.ll"
docker compose up  # frontend 3000, backend 8000/docs, nginx 8082 (was 80, now 8082 per docker-compose.yml), db 5432 (pg_isready -d jockydb), redis 6379, minio 9000/9001
# Check: docker compose ps → 9 Up (jocky, agent real POST via nginx:80, backend health python urllib, frontend, db healthy, redis, minio, nginx, detector)
# Health: curl http://localhost:8000/health → {"db":true,"yara":true,"minio":true,"redis":true,"auth_required":false}
# Agent: docker logs jocky-agent-1 → Found 6 fixtures → all POST 200 (no more 422/list crash) → POST /api/run via nginx risk 60 → Fail-closed 422
# Dashboard: open http://localhost:3000 → case dropdown + New Case, host/type/platform filters, YARA poly demo 3 hashes → 1 cluster, timeline search/minRisk, risk sparkline/history, graph expand, reports history + sigma tune
