# JOCKY — Forensic Language & Framework (Docker-Only, Entire PS)

**Entire Problem Statement, not just demo.** Points 1,2,3A,3B + Central Management, implemented as **detection of synthetic adversary emulation** inside Docker — ethical, no weaponization on host.

## 8 Layers (Bottom → Top)

- **L1 Language (Point 1):** `grammar/jocky.g4` (ANTLR4 4.13.1) + C++20 + LLVM 17 IR — `process.list()`, `file.hash()`, `memory.analyze()`, `driver.scan()` — alters CFG/tokens/binary per Point 1.
- **L2 Stdlib:** `jocky_runtime` cross-platform adapters (WinAPI/ETW vs /proc) — same `process.list()` on Win + Ubuntu.
- **L3 Polymorphism (Point 2):** LLVM passes `libCfgFlatten.so`, `libStringEncrypt.so`, `libImportObfuscate.so` + `rename.py`/`encrypt.py` + `jockyc --polymorphic --seed` → unique SHA256/entry/import per build. CI in `.github/workflows/build.yml` (Docker).
- **L4 Agent (Point 3A + 3B collector):** `jocky-agent` C++ — reads `testdata/hollowing.json`, `byovd_driver.json` (synthetic, no real hollowing/driver load) → streams via TLS WSS.
- **L5 Transport/Central:** Nginx 1.25 (CDN/domain-fronting simulation) → `agent -> https://cdn.jocky.local (Nginx:80) -> backend:8000` via `jocky-net`.
- **L6 Backend Store:** FastAPI + PostgreSQL 15 + Redis 7 + MinIO + JWT — `POST /api/evidence` → chain-of-custody SHA256+timestamp.
- **L7 Detection:** YARA 4.5 (`JOCKY_DEMO_MARKER`), Sigma, Behavioral Risk 0–100 (`ppid*30 + hollowed*40 + driver*30`).
- **L8 Correlation:** React 18 + TS + Vite + Tailwind + React Flow (Evidence Knowledge Graph) + Recharts + Timeline + MITRE T1055/T1068 + AI Explainer (Ollama stub) + WeasyPrint PDF at `http://localhost:3000`.

**Ethical line:** All 3A/3B is *detection* on `testdata/*.json` + `yara/rules.yar` inside containers. No real `NtUnmapViewOfSection`, reflective DLL, or `RTCore64.sys` load on host. PPT: *“Adversary emulation on controlled synthetic data — detection only, no kernel exploitation.”*

## Host Prerequisite (Already Done)

Windows 11 + WSL2 Ubuntu-24.04 + Docker Desktop (WSL Integration ON). **No host LLVM/CMake/Java.**

Checks on teammate laptop:
```bash
wsl --list -v          # Ubuntu-24.04 Version 2
docker --version       # >=24.0
docker compose version # >=2.20
docker ps              # daemon running (if not: Docker Desktop → Settings → Resources → WSL Integration → enable Ubuntu)
docker run hello-world # Hello from Docker!
# Free C: >10GB, D:\SIH has 110GB+ free
```

## Quick Start (Docker-Only)

```bash
# 1. Build all 6 services (first ~10m, pulls LLVM/CMake/Java inside image)
docker compose build

# 2. Point 1+2 proof: 3 different hashes from same .jocky
docker compose run --rm jocky bash -c "jockyc examples/test.jocky -o /tmp/a.ll --seed 1 && jockyc examples/test.jocky --polymorphic -o /tmp/b.ll --seed 2 && jockyc examples/test.jocky --polymorphic -o /tmp/c.ll --seed 3 && sha256sum /tmp/a.ll /tmp/b.ll /tmp/c.ll && echo '--- CFG diff a vs b ---' && diff /tmp/a.ll /tmp/b.ll | head -20"
# Must show 3 different SHA256 → Point 1+2 proven

# 3. Full stack
docker compose up
# frontend http://localhost:3000  backend http://localhost:8000/docs  nginx http://localhost:80

# 4. Detection demo (inside containers)
docker compose exec agent ./agent --scan
curl -X POST http://localhost:8000/api/evidence -H "Content-Type: application/json" -d @testdata/hollowing.json
curl http://localhost:8000/api/cases/1/risk   # → {"risk":85,"level":"CRITICAL"}
# Frontend Graph shows hollowed node + Timeline + Risk 85 + MITRE + PDF download
```

## Host-Free Fallback (No Docker or No WSL)

If Docker not running, run the Python fallback compiler (same IR logic, no LLVM needed):
```bash
python tools/jockyc.py examples/test.jocky -o build/a.ll
python tools/jockyc.py examples/test.jocky --polymorphic --seed 2 -o build/b.ll
sha256sum build/*.ll   # 3 different hashes, same detection
```

## Project Tree (Entire PS)

```
D:\SIH/
 Dockerfile, docker-compose.yml, CMakeLists.txt, .env
 grammar/jocky.g4
 jocky/ include/jocky/ src/ transform/
 runtime/ agent/ examples/ testdata/ yara/ sigma/
 backend/ frontend/ nginx/ .github/workflows/build.yml
 tools/jockyc.py  # host fallback without Docker
```

## Novelty (1+3+5)

- **Portable DSL:** One `investigate.jocky` runs on Win + Ubuntu via adapters.
- **Evidence Knowledge Graph + Risk Propagation:** React Flow User→Process→File→Network→Driver→Finding with propagated risk.
- **Explainable AI + MITRE:** “Why HIGH?” from evidence only + T1055/T1068 mapping.

## What NOT To Do

- Do NOT `apt install llvm` on host — all inside Dockerfile.
- Do NOT run real hollowing/BYOVD outside VM — use `testdata/*.json` only.
- Do NOT create native host build — keep `docker compose build` path.

## Verification (Entire Project)

- `docker compose config` → 6 services
- `docker compose build` → jockyc compiles inside
- 3 hashes differ → Point 1+2
- `curl localhost:8000/api/cases` → JSON → L6
- `curl localhost:80/api/cases` via Nginx → L5 proxy proven
- Frontend Graph/Timeline/Risk → L8
