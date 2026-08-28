# SUMMARY FOR TEAMMATE'S OPENCODE - ENTIRE PROJECT (Not Just Demo)

## Title
Creation of scripts/functions with new programming language to commence Computer & Network forensic analysis without triggering security solutions - DOCKER ONLY in D:\SIH

## Objective (Detection, Not Weapon)
Build JOCKY: proprietary DSL + LLVM + agent + central dashboard that DETECTS adversaries described in PS. Points 1,2,3A,3B + Central all as detection on synthetic data inside Docker.

## Already Done in D:\SIH (verify)
- All 8 layers scaffolded. Host fallback python tools/jockyc.py works without Docker/LLVM (tested: 3 hashes differ, YARA hits all 3 -> Point 1+2 proven, backend risk 90 CRITICAL).
- No host LLVM needed. All heavy tools inside Dockerfile.

## What Opencode Must Build/Verify in D:\SIH

### L1 Language (Point1)
grammar/jocky.g4 (ANTLR4), jocky/src/IRGen.cpp, jocky/src/main.cpp -> generateIRText -> .ll with EntryPoint, Imports, JOCKY_DEMO_MARKER, bb.poly.* blocks when --polymorphic.

### L2 Runtime
runtime/include/runtime.h, runtime/src/runtime.cpp (synthetic adapter, real WinAPI/Linux later).

### L3 Polymorphism (Point2)
jocky/transform/* + tools/jockyc.py --polymorphic --seed -> unique SHA256. Dockerfile FROM ubuntu:22.04 apt install clang-17 llvm-17-dev cmake ninja openjdk-17 wget. docker-compose service jocky.

### L4 Agent (3A+3B collector, synthetic)
agent/src/agent.cpp, agent/Dockerfile, testdata/hollowing.json, byovd_driver.json, reflective_dll.json, timeline.json. Agent reads JSON via Nginx proxy.

### L5 Transport/Central
nginx/nginx.conf (cdn.jocky.local -> backend:8000), docker-compose jocky-net.

### L6 Backend Store
backend/app/main.py (FastAPI), models.py, detector.py, requirements.txt, Dockerfile. Postgres 15, Redis 7, MinIO.

### L7 Detection
yara/rules.yar (JOCKY_DEMO_MARKER, BYOVD_RTCore64, Process_Hollowing), sigma/rules.yml, backend/app/detector.py Risk 0-100.

### L8 Correlation
frontend/* (React 18 TS Vite Tailwind ReactFlow Recharts), Graph, Timeline, RiskGauge, MITRE T1055/T1068, Ollama stub, WeasyPrint PDF.

### DevOps
Dockerfile, docker-compose.yml (6 services + volumes + jocky-net), .github/workflows/build.yml, tools/jockyc.py fallback, examples/test.jocky.

## Checks on his laptop
wsl --list -v, docker --version, docker compose version, docker ps, docker run hello-world, free >10GB. No host cmake/llvm/java.

## Verify (host, no Docker)
python tools/jockyc.py examples/test.jocky -o build/a.ll --seed 1
python tools/jockyc.py examples/test.jocky --polymorphic -o build/b.ll --seed 2
certutil -hashfile build\a.ll SHA256 vs build\b.ll -> differ
Backend: cd backend; python -c "from app.main import app; ..." -> risk 90

## Verify (Docker)
docker compose build
docker compose run --rm jocky bash -c "jockyc examples/test.jocky -o /tmp/a.ll --seed 1 && jockyc examples/test.jocky --polymorphic -o /tmp/b.ll --seed 2 && sha256sum /tmp/*.ll"
docker compose up -> localhost:3000, 8000/docs, 80

## What NOT to do
Do NOT apt install llvm on host, do NOT run real hollowing/driver, do NOT create native host build. Keep Docker.

## Project path
D:\SIH (not D:\Foram_TP\JOCKEY). All .:/app bind mount.
