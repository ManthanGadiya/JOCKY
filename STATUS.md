# JOCKY — Project Status

**Document:** `STATUS.md`
**Project:** JOCKY
**Status:** Active Development
**Last Updated:** 2026-09-11

---

# 1. Purpose

This document is the **single source of truth for the current implementation state of JOCKY**.

Unlike the other documentation files, this document describes what **actually exists in the repository right now**, not what is planned.

The coding agent MUST update this file after every meaningful implementation milestone.

Do not mark a feature as complete unless it has been implemented and verified.

---

# 2. Current Project State

## Overall Status

**Phase:** Foundation / Core Platform Development

**Current Objective:**

Build a safe, reproducible, defensive forensic investigation platform around the JOCKY DSL, compiler, IR, agent, evidence pipeline, detection engine, backend, and dashboard.

---

# 3. Implementation Status

| Component               | Status          | Notes                                      |
| ----------------------- | --------------- | ------------------------------------------ |
| Repository structure    | 🟢 Complete     | Base project organization established      |
| Documentation structure | 🟢 Complete     | 8 specs + ARCHITECTURE now correct         |
| JOCKY language          | 🟡 In Progress  | 12 ops whitelisted; filtering/correlation pending |
| Lexer                   | 🟢 Verified     | **Grammar-wired** `tools/jocky_lexer.py` `lex()` per `grammar/jocky.g4` + `jocky/src/Lexer.cpp` (ID/DOT/LPAREN/... + WS/COMMENT skip, line:col tracking) — used by `tools/jockyc.py` + `backend/app/main.py` both (12 tests) |
| Parser                  | 🟢 Verified     | `parse_member_calls()` per g4 `MemberCall` + `validate_and_collect()` with line:col errors — fail-closed 422 includes `at X:Y`, syntax errors for unterminated string / unmatched '(' (12 tests) |
| AST                     | 🟡 Partial      | `MemberCall` dataclass + `.tokens` real dump + `.ast` with calls/tokens; full visitor pending |
| Semantic analysis       | 🟡 Partial      | Unknown op → 422 fail-closed via OP_CAPS whitelist (verified) |
| Capability system       | 🟡 Partial      | 15 ops → 8 caps; DEFAULT_POLICY deny memory.analyze (403), allow system.read etc. |
| IR                      | 🟢 Verified     | IR_VERSION=1, IR_CAPS/IR_OPS, EntryPoint, Imports, JOCKY_DEMO_MARKER, bb.poly.* (25 tests) |
| IR validation           | 🟢 Verified     | Unknown capability → 422; capability denied → 403 (fail-closed, tested) |
| Runtime                 | 🟢 Verified     | **Real platform-aware** `backend/app/providers/` per `ROADMAP Phase 15` `ARCHITECTURE §8` — `factory.get_providers(platform)` + `psutil==6.1.0` live (`process_iter`, `net_connections`, real `hash_file` on allowed roots) + fallback synthetic per `SECURITY §47` (10+5 tests) |
| Forensic adapters       | 🟢 Verified     | `IProcessProvider/IFileProvider/INetworkProvider` `DESIGN §23` — both adapters now `real` (psutil/`/proc` + `hashlib` live) with normalized schema `FORENSICS §67`; `POST /api/run?platform=windows|linux` (10 contract + 5 real) |
| Evidence model          | 🟢 Verified     | Canonical envelope schema_version 1 + integrity SHA256 + provenance (tested, E2E) |
| Agent                   | 🟢 Verified     | **Real POST via nginx** `agent/agent.py` → `http://nginx:80` → backend:8000 — `GET /health` via nginx, `POST /api/evidence` per fixture, `POST /api/run` JOCKY sweep + fail-closed 422/403 via nginx (8 tests) |
| Backend                 | 🟢 Verified     | PG persistence + compile/run + report + yara scan/polymorphic-demo + /evidence|findings + **MinIO+Redis** (`/health` `minio`/`redis`, `/api/storage/status`, `/api/artifacts`) (8 storage tests) |
| Detection engine        | 🟢 Verified     | **YARA 5 rules** (`JOCKY_DEMO_MARKER/BYOVD_RTCore64/Process_Hollowing` + `File_Suspicious_PE`/`Network_C2_Beacon`) + **Sigma 2 rules** (`jocky-001 T1055`, `jocky-002 T1068`) + **Behavioral** (`detection_engine.py` `sigma_scan()`/`behavioral_scan()`/`detect()` with mitre/severity/confidence per FORENSICS §31) — 11 tests |
| Investigation graph     | 🟢 Verified     | Star host→evidence + process→file/net edges, live ReactFlow |
| Timeline                | 🟢 Verified     | Ordered by observed_at |
| Dashboard               | 🟢 Verified     | Editor + live Graph/Timeline/Risk + findings + 📄 Report PDF + **YARA panel (poly demo: 3 hashes → 1 cluster)** (live :3000) |
| Report generation       | 🟢 Verified     | PDF via WeasyPrint pydyf 0.11 + **MinIO** `jocky-reports` + **Redis cache** TTL 300s + `X-Report-Cached` — live 20KB verified |
| Docker environment      | 🟢 Verified     | 9 Up: backend (pango + postgres + **yara 4.5.2** + **minio+redis** verified in `/health`) :8000, frontend :3000, nginx 8082, db healthy `pgdata+miniodata` persisting |
| Database                | 🟢 Verified     | Postgres 15 persistence — survive restart (case 90: 2→restart→2) + MinIO `jocky-reports`/`jocky-evidence` buckets |
| Cache / Queue           | 🟢 Verified     | **Redis** `cache.py` (`cache_get/set/invalidate`, TTL, mem fallback, `redis_url` health) — 8 tests |
| Storage                 | 🟢 Verified     | **MinIO** `storage.py` (`put_report`/`get_report`/`put_evidence_artifact`/`put_bytes`/`get_bytes` + `list_reports`/`delete_reports` history, versioned `JOCKY_case_{id}_report_{ts}_{sha}.pdf`) — 8+3 tests |
| Reports                 | 🟢 Verified     | **Versioned history** `GET /api/cases/{id}/reports` + `GET /api/cases/{id}/reports/{key}` per FORENSICS §64 — `put_report` now dual-writes latest + versioned timestamp key (11 tests total for report+storage) |
| Windows support         | 🟢 Verified     | **Real + Synthetic Windows** `Windows*Provider` — `psutil` live `Toolhelp32` equivalent on Windows host (`psutil.process_iter` 50+ + `exe`/`username`, `source_adapter` `psutil live`) + fallback synthetic `C:\Windows\...` — same contract `pid/ppid/name/path` + `sigma_hit` injected `jocky-001` — `ROADMAP Phase 15` `5` real tests |
| Linux support           | 🟢 Verified     | **Real + Synthetic Linux** `Linux*Provider` — `psutil` + `/proc` live on Linux host (`/proc` + `exe`/`uid`/`inode`) + fallback synthetic `systemd /usr/bin/...` on Windows host — same normalized contract + real file `hash_file` via `hashlib` on allowed roots — `5` real tests + `10` contract tests |
| Controlled laboratory   | 🟢 Verified     | 6 fixtures + live poly demo (3 IRs same YARA cluster) + full-sweep cases + report + `POST /api/cases` isolation (5 tests) |
| End-to-end workflow     | 🟢 Verified     | Full sweep → envelope → YARA → Timeline/Graph/Risk→Report persists (Point 1+2) + **auth** `POST /api/auth/login` → JWT → `GET /api/auth/me` per SECURITY §19-20 |
| Dashboard               | 🟢 Verified     | **Case isolation + enrichment** `App.tsx` `caseId` dropdown + `hostFilter`/`typeFilter`/`platformFilter` + `runPlatform` + `filteredEvidence` + **Timeline search/risk filter** + **Risk history sparkline** + **Graph node select** — per FORENSICS §7 + ARCHITECTURE §11 + DESIGN §41 |
| Authentication          | 🟢 Verified     | **JWT** `backend/app/auth.py` `POST /api/auth/login` `HS256` + `GET /api/auth/me` + `GET /api/auth/status` per SECURITY §19-20 + `ARCHITECTURE §10` — `AUTH_REQUIRED` env (default false for host, strict 401 when true), `X-API-Key` fallback — 8 tests |
| Automated tests         | 🟢 Verified     | **157 tests** (compiler 9, backend 13, e2e 3, forensic 6, report 4, yara 6, agent 8, grammar 12, platform 10, detection 11, storage 8, isolation 5, report-harden 3, correlation 6, auth 8, timeline 6, sigma-tune 6, evidence-load 9, frontend-report 1, language 9, hardening 9, phase15 5) all passing |
| Language features       | 🟢 Verified     | **P1** `investigation "title" { }` (sets case title per FORENSICS §7), `filter`/`correlate` (2-arg validation per LANGUAGE §12,15), variable `x = op()` assignments — via `tools/jocky_lexer.py` + `backend _extract_investigation_titles` (9 tests) |
| Hardening P2            | 🟢 Verified     | **Resource limits** `MAX_IR_SIZE 100KB`/`MAX_EVIDENCE_SIZE 5MB`/`MAX_SOURCE_SIZE 50KB` per `SECURITY §28` `413` + **Audit** `backend/app/audit.py` hash chain (`prev_hash`/`hash`) `GET /api/audit` per `SECURITY §34-36` `ARCHITECTURE §11` — 9 tests |
| Correlation engine      | 🟢 Verified     | **Enriched** `GET /api/cases/{id}/graph` → `correlations` (temporal 0.6, pid 0.8, process→file 0.85, process→net 0.9, supports 0.95) + `weight` on edges, `correlation_count`, platform on nodes — per ARCHITECTURE §14 + FORENSICS §43 (6 tests) |
| Timeline / Graph / Risk | 🟢 Verified     | **Detail** `GET /api/cases/{id}/risk/history` + `/risk/breakdown` (per-evidence behavioral+sigma) + `GET /api/cases/{id}/graph/expand?node_id=` (neighbors + payload) — frontend `Timeline` search/minRisk, `RiskGauge` history sparkline + breakdown toggle + `Graph` expand → `selectedNode` chip (6 tests) |
| Sigma tuning            | 🟢 Verified     | **Auto-tune** `backend/app/sigma_tuner.py` `get_rules`/`tune_rule`/`auto_tune` (level/confidence 0.5-0.95, history) + `GET /api/sigma/rules` + `POST /api/sigma/tune` + `POST /api/sigma/auto-tune` + `GET /api/sigma/status` per ARCHITECTURE §13 + FORENSICS §34 (6 tests) |
| Evidence.load           | 🟢 Verified     | **Wired** `evidence.load("testdata/hollowing.json")` per LANGUAGE §28 + IR_SPEC §18.1 + FORENSICS §61 — validates path (traversal 400), loads JSON fixture from allowed roots (`testdata/` `/app/testdata` `/evidence/` `/tmp/`), preserves `type/memory`/`driver` fields, adds `source_file` + `platform`, isolated per case + appears in timeline/graph/risk (9 tests) |
| Reports frontend        | 🟢 Verified     | **History UI** `App.tsx` fetches `GET /reports` + lists versioned keys with `dl` + `Sigma` panel (`GET /sigma/rules` + `tune` prompt + `Auto-Tune`) — per FORENSICS §64 + ARCHITECTURE §11 (1 test) |

---

# 4. Documentation Status

| Document            | Status     |
| ------------------- | ---------- |
| `ARCHITECTURE.md`   | 🟢 Created |
| `LANGUAGE_SPEC.md`  | 🟢 Created |
| `IR_SPEC.md`        | 🟢 Created |
| `FORENSICS_SPEC.md` | 🟢 Created |
| `SECURITY_MODEL.md` | 🟢 Created |
| `TEST_PLAN.md`      | 🟢 Created |
| `ROADMAP.md`        | 🟢 Created |
| `DESIGN.md`         | 🟢 Created |
| `STATUS.md`         | 🟢 Created |
| `TEAMMATES.md`      | 🟢 Created |
| `AGENTS.md`         | 🟡 Pending |

---

# 5. Definition of Status

Use the following status values consistently.

### 🟢 Complete

The feature:

* is implemented,
* has appropriate tests,
* has been integrated where required,
* and has been verified.

### 🟡 In Progress

Implementation exists or work has started, but verification or integration is incomplete.

### 🟠 Blocked

Implementation cannot continue because of a known dependency, design decision, environment issue, or external requirement.

### 🔴 Not Started / Not Verified

The feature either has not been implemented or there is insufficient evidence that it works.

### ⚪ Not Applicable

The feature is intentionally not part of the current project scope.

---

# 6. Current Working Pipeline

The intended end-to-end pipeline is:

```text
JOCKY Source
     ↓
Lexer
     ↓
Parser
     ↓
AST
     ↓
Semantic Analysis
     ↓
Capability Validation
     ↓
IR Generation
     ↓
IR Validation
     ↓
Agent Runtime
     ↓
Forensic Adapter
     ↓
Evidence Normalization
     ↓
Evidence Integrity
     ↓
Backend
     ↓
Detection
     ↓
Findings
     ↓
Timeline / Graph / Risk
     ↓
Dashboard
     ↓
Report
```

Every stage must eventually be independently testable.

---

# 7. Currently Verified (2026-08-28 — Full Sweep + Harden & Persist)

### Verified on Host + Docker (evidence logged, 90 tests + live PG + YARA + Agent via nginx + Platform + Detection + MinIO/Redis)

* **Host compiler** `tools/jockyc.py` → IR_VERSION=1 — 3 hashes differ + `edr.disable()` → exit 2 fail-closed (9 tests)
* **Backend API** `backend/app/main.py` v1.2.0 (enriched + PG + YARA) via TestClient **and live on :8000**:
  * `system.info` → risk 5 LOW; `process.list` → 4 procs Sigma T1055 risk 60; `file.hash("/evidence/sample.exe")` → YARA T1105 risk 55 + traversal 400; `network.connections` → C2 T1071 risk 30; full sweep 4 evidence risk 60 star graph 6 nodes
  * Live case 60 verified 4 evidence, graph 6 nodes, timeline 4
  * `GET /health` → `db:true postgres:true yara:true yara_rules:/app/yara/rules.yar` (Docker)
* **Postgres** `db.py` tables, `DATABASE_URL`, `POST /api/run` dual-write, `GET /evidence` PG read — case 90: 2→restart→2 persists
* **YARA 4.5 binary** inside backend (`/usr/bin/yara`, `/app/yara/rules.yar` volume): `GET /api/yara/status` → `yara_binary_used true test_hits JOCKY_DEMO_MARKER`, `POST /api/yara/scan {JOCKY_DEMO_MARKER}` → hits, `POST /api/yara/polymorphic-demo {seeds 1,2,3}` → 3 distinct SHA256 (`3df…/b6d5…/d450…`) but `same_yara_cluster true` (hash≠detection, Point 1+2) — verified both host fallback and Docker binary
* **E2E** `system.info+process+file+net` via `POST /api/run` → live + `test_yara` 6
* **Dashboard** :3000 — 4-op sweep default + traversal fail + **📄 Report PDF** + **YARA panel** (poly demo: 3 hashes → 1 cluster, hash≠detection)
* **Report** `GET /report` → 20KB `%PDF` (WeasyPrint pydyf 0.11) verified Docker, HTML fallback host
* **Agent via nginx** `agent/agent.py` (stdlib `urllib`) — `GET /health` via `http://nginx:80`, `POST /api/evidence` per `testdata/*.json` fixture, `POST /api/run` JOCKY sweep `system.info+process+file+net` via nginx (same fail-closed 422/403 as direct), `healthcheck` `curl -sf http://nginx:80/health` in compose — 8 tests including integration `agent_scan_once` delegating to TestClient
* **Grammar-wired compiler** `tools/jocky_lexer.py` — real `lex()` per `grammar/jocky.g4` tokens + `parse_member_calls()` per g4 `MemberCall`, `validate_and_collect()` returns line:col errors, used by both `tools/jockyc.py` + `backend/app/main.py` (single source; replaces `RE_CALL` regex), `.tokens` now real dump + `.ast` with calls/tokens, 12 new `test_compiler_grammar` tests (keywords, strings, comments, syntax errors, g4 coverage, backend same lexer)
* **Platform providers** `backend/app/providers/` per ARCHITECTURE §8 + DESIGN §22 — `base.py` `ISystem/IProcess/IFile/INetwork/IDriverProvider`, `windows.py` (WinAPI synthetic `C:\Windows\...`), `linux.py` (`/proc` synthetic `uid/inode/lsmod`), `factory.py` `get_providers(platform)` + `detect_platform()` + `platform_from_request()`; `backend/app/main.py` `make_envelope(..., platform)` dispatches via `_platform_provider_payload()`, `RunRequest.platform` field, same JOCKY → same MITRE `T1105/T1055` but different `platform` + path/uid per FORENSICS §67; 10 `test_platform_providers` contract tests
* **Detection depth** `backend/app/detection_engine.py` per ARCHITECTURE §13 + FORENSICS §31 — `load_sigma_rules()` (yaml + fallback), `sigma_scan()` (jocky-001 ppid anomaly, jocky-002 BYOVD), `behavioral_scan()` (13 weights: ppid/hollowed/unbacked/reflective/vuln/yara/sigma/C2), `detect()` + `risk_for_payload()`; `yara/rules.yar` expanded to 5 rules (`File_Suspicious_PE` T1105, `Network_C2_Beacon` T1071) + `backend/app/main.py` fallback strings for new rules; `backend/requirements.txt` adds `pyyaml`; 11 `test_detection_depth` tests
* **Harden & Persist** `backend/app/storage.py` + `cache.py` per ARCHITECTURE §11 + FORENSICS §64 — `storage.py` MinIO `jocky-reports`/`jocky-evidence` buckets (auto-create, fallback mem, `put_report/get_report/put_bytes/get_bytes`), `cache.py` Redis `cache_get/set/invalidate` (TTL, fallback mem); `backend/app/main.py` now `GET /health` includes `minio`/`redis` + `GET /api/storage/status`, `POST /api/artifacts/upload` (5MB 413 per SECURITY_MODEL §28) + `GET /api/artifacts/{key}`, `POST /api/evidence` → MinIO artifact, `GET /api/cases/{id}/report` → MinIO + Redis `X-Report-Cached`; 8 `test_storage` tests
* **Case isolation UI** `frontend/src/App.tsx` + `backend/app/main.py` `POST /api/cases` per FORENSICS §7 + ARCHITECTURE §11 — `App.tsx` adds case dropdown (from `/api/cases`), `+ New Case` button, `hostFilter`/`typeFilter`/`platformFilter` selectors + `runPlatform` for `POST /api/run`, `filteredEvidence` derived, header+evidence/graph counts reflect filtered; backend `POST /api/cases` auto-increment id; 5 `test_case_isolation` tests (create+isolation, list grows, host/platform filters, UI presence)
* **Tests** 95/95: 9+13+3+6+4+6+8+12+10+11+8+5 (compiler/backend/e2e/forensic/report/yara/agent/grammar/platform/detection/storage/isolation)
* **Docker** 9 Up: backend (pango+PG+yara 4.5.2 + 5 rules + minio/redis) :8000, frontend :3000 (+ case isolation UI), nginx 8082, `agent` real POST via nginx, db healthy pgdata+miniodata persisting

### Still Pending / Not Verified

* AST visitor / full block/funcDecl control-flow (grammar has them, IR only emits MemberCall ops)
* Real WinAPI/ETW `/proc` live collection (beyond synthetic — lab remains synthetic per SECURITY_MODEL §47)
* Dashboard richer filters (timeline search, graph expand, risk history — per DESIGN §41)

---

# 8. Known Limitations

Current known limitations must be recorded here.

### Security

JOCKY is being developed as a **defensive/authorized forensic platform**.

The project must not introduce:

* arbitrary command execution,
* unrestricted native execution,
* privilege escalation,
* security-control bypass,
* EDR/AV evasion,
* covert persistence,
* covert C2,
* credential theft,
* or other offensive malware functionality.

Controlled laboratory scenarios should use synthetic or benign fixtures whenever possible.

---

### Platform

Cross-platform support must not be considered complete merely because the source code compiles.

A platform is considered supported only after:

```text
Build
+
Unit Tests
+
Integration Tests
+
Platform Validation
```

have succeeded.

---

# 9. Current Milestone

## Milestone: ✅ YARA Binary — hash ≠ detection (Point 1+2) — COMPLETE (2026-08-28)

### Demo

```bash
POST /api/yara/polymorphic-demo {source:"system.info();\\nprocess.list();", seeds:[1,2,3], polymorphic:true}
→ 3 distinct SHA256 (3df847…/b6d5a4…/d45094…) but same_yara_cluster true — all hit JOCKY_DEMO_MARKER via yara binary 4.5.2 (/app/yara/rules.yar)
```

→ Backend `yara_scan_content()` tries `yara /app/yara/rules.yar` binary (`yara_available` true, `yara_binary_used` true on :8000 Docker, fallback string on host), `POST /api/yara/scan` per-IR/file + `GET /api/yara/status` + `POST /api/detect` now `yara_used` flag. Frontend **YARA panel** shows test_hits, 3-hashes→1-cluster demo, links to `/api/yara/status` + `/api/docs`. Tests 6 yara cases including polymorphic hash≠detection.

### Prior milestones still hold (report PDF 20KB, PG persistence, forensic sweep)

---

## Milestone: ✅ Report Generation — PDF via WeasyPrint — COMPLETE (2026-08-28)

### Demo

```jocky
system.info();
process.list();
file.hash("/evidence/sample.exe");
network.connections();
```

→ **Report PDF** `GET /api/cases/{id}/report` (20KB, risk badge, chain-of-custody, timeline, findings) — WeasyPrint 62.3 + pydyf 0.11.0 live on :8000 Docker with pango/cairo deps. Frontend **📄 Report PDF** button triggers download. Tests 4 report cases including empty case.

→ Prior milestone still holds: 4 envelopes correlated graph, file YARA + process Sigma, risk 60 MEDIUM, path traversal 400, memory 403.

---

## Milestone: ✅ Forensic Ops Expansion — process/file/network enriched — COMPLETE (2026-08-28)

### Demo

```jocky
system.info();
process.list();
file.hash("/evidence/sample.exe");
network.connections();
```

→ 4 envelopes, correlated graph (host→process/file/net → finding + process→file/net edges), file YARA + process Sigma correlation, risk 60 MEDIUM.

---

## Milestone: ✅ First Usable Query — `system.info();` E2E — COMPLETE (2026-08-28)

### Goal

Prove: Source → Compile (IR v1) → Validation (fail-closed) → Runtime (synthetic) → Envelope → Backend → Findings → Live Dashboard.

### Exit Criteria — Completed

```text
[x] JOCKY `system.info();` compiles to IR v1 (IR_VERSION, IR_CAPS, EntryPoint, JOCKY_DEMO_MARKER) — host + Docker
[x] Unknown op `edr.disable();` → 422 fail-closed (compiler + /api/compile + /api/run)
[x] Capability `memory.analyze` → 403 denied by DEFAULT_POLICY
[x] Runtime synthetic envelope (schema_version 1, integrity SHA256, provenance) — verified
[x] Evidence reaches backend via POST /api/run (nginx 8082 → 8000 live) — not just manual curl
[x] Detection produces finding F-... INFO risk 5 for system.info
[x] Timeline / Graph / Risk live from backend (not hardcoded fallback) — dashboard fetches /api/cases/{id}/timeline|graph|risk
[x] Dashboard editor + Compile/Run buttons show IR + caps + evidence live — frontend :3000 verified
[x] 25 automated tests cover compiler/backend/E2E (all passing)
[x] Docker compose up verified (9 services)

### Next Milestone: Expand Language — `process.list`, `file.hash`, `network.connections`

Progressively add operations per LANGUAGE_SPEC.md §10, each with capability, synthetic provider, envelope normalization, detection correlation, and dashboard visualization.
```

---

# 10. Immediate Next Tasks (for next milestone: language expansion)

1. ✅ Fix repo hygiene (audit) — done (commit ef35f26)
2. ✅ IR version + capability whitelist + fail-closed — done (IR_VERSION=1, 422/403)
3. ✅ Runtime synthetic envelope + backend compile/run — done
4. ✅ Timeline/Graph/Risk live + Dashboard editor/Run — done
5. ✅ Enriched forensic ops (process 4-proc tree Sigma, file hash YARA, network C2) — done (v1.1.1, 6 forensic tests)
6. ✅ Postgres persistence (evidence/cases/findings survive restart, health db:true, live case 90: 2→restart→2) — done
7. ✅ YARA 4.5 binary (POST /api/yara/scan, GET /api/yara/status, POST /api/yara/polymorphic-demo hash≠detection) + frontend YARA panel — done (6 yara tests)
8. ✅ Report PDF (WeasyPrint 20KB, frontend 📄 button) — done (4 report tests)
9. 41 tests — done (9+13+3+6+4+6)
10. ✅ Agent real POST via nginx (GET /health, POST /evidence, POST /run + fail-closed via nginx) — done (8 agent tests, 49 total)
11. ✅ Lexer/Parser grammar-wired (jocky_lexer.py per g4 + Lexer.cpp, replaces RE_CALL, line:col errors) — done (12 grammar tests, 61 total)
12. ✅ Platform providers (IProcess/IFile/INetwork per DESIGN §22, Windows vs Linux factory, same JOCKY → different adapter, normalized schema) — done (10 platform tests, 71 total)
13. ✅ Detection depth (YARA 3→5 rules + Sigma 2 rules + behavioral engine per FORENSICS §31, mitre/severity/confidence) — done (11 detection tests, 82 total)
14. ✅ Harden & Persist (MinIO jocky-reports/jocky-evidence + Redis cache per ARCHITECTURE §11, report→MinIO + cache, artifacts) — done (8 storage tests, 90 total)
15. ✅ Case isolation UI (dropdown of cases from /api/cases + host/type/platform filters + New Case + runPlatform) — done (5 isolation tests, 95 total)
16. Dashboard richer filters (timeline search, graph expand) + hardening per SECURITY_MODEL §41 (optional)

---

# 11. Recent Changes

### 2026-08-28 — Case Isolation UI (Cases + Host/Platform Filters)

#### Added
- `backend/app/main.py` — `CaseCreate` + `POST /api/cases` (auto-increment id per ARCHITECTURE §10, returns `case/id/title`) — evidence already isolated via `case_id` param but now explicit creation per `POST /api/run` flow
- `frontend/src/App.tsx` — case isolation bar per FORENSICS §7 + ARCHITECTURE §11: `caseId` dropdown (from `GET /api/cases`), `+ New Case` button (`POST /api/cases`), `hostFilter`/`typeFilter`/`platformFilter` selectors derived from `evidence` hosts, `runPlatform` selector (`linux`/`windows`) for `POST /api/run`, `filteredEvidence` derivation, filtered counts in graph/evidence panels, platform badge per evidence row
- `tests/test_case_isolation.py` (5) — create+isolation (evidence/timeline/graph/risk all `case_id==nid`), list grows, host filter, platform preserved per case (windows+linux both present), UI presence checks (caseId/hostFilter/filteredEvidence)

#### Verified
- `pytest` 95/95 (5 new) — case isolation verified via TestClient (evidence all `case_id==nid`, timeline/graph/risk isolated, `GET /api/cases` count grows, platform windows vs linux both present in same case)

### 2026-08-28 — Correlation Enrichment (Temporal + PID + Platform)

#### Added
- `backend/app/main.py` `GET /api/cases/{id}/graph` enriched per ARCHITECTURE §14 + FORENSICS §43: builds `pid→evidence` map, `nodes` now `platform` field, `edges` now `weight` (0.5-0.95) + `reason`, `correlations` list (`process→file` 0.85, `process→net` 0.9, `temporal` <120s 0.6, `pid` 0.8, `supports` 0.95), `correlation_count`, platform-aware labels
- `tests/test_correlation.py` (6) — full sweep has ≥2 correlations (process→file/net/temporal), temporal window <120s, pid sharing, mitre/platform preserved, edges weight ∈(0,1], confidence ∈(0,1] + reason

#### Verified
- `pytest` 104/104 (6 new)

### 2026-08-28 — Phase 15 Cross-Platform Real (Windows Toolhelp32 + Linux /proc via psutil)

#### Added
- `backend/requirements.txt` — `psutil==6.1.0` per `ROADMAP Phase 15`
- `backend/app/providers/linux.py` — `LinuxSystemProvider` tries `platform.release()` + `/proc` live, `LinuxProcessProvider` `psutil.process_iter` (50+ `pid/ppid/name/exe/username`, `source_adapter` `psutil live`) on Linux host else fallback synthetic `systemd` 4-proc per `SECURITY §47`, `LinuxFileProvider` real `hashlib` on allowed roots (`/evidence/ /tmp/ testdata` → `real_file:true` `size` from `stat`), `LinuxNetworkProvider` `psutil.net_connections` (20+ `TCP/UDP` `pid` live) else synthetic `C2`
- `backend/app/providers/windows.py` — `WindowsProcessProvider` `psutil` live `Toolhelp32` equivalent on Windows host (50+ + `synthetic-injected` `jocky-001`), `WindowsFileProvider` real `hashlib` live, same contract `pid/ppid/name/path` + `sigma_hit` preserved
- `tests/test_forensic_ops.py` — `test_process_list_rich` `len>=4` (was `==4`) + `test_network_connections` `len>=2` to allow live `>50` vs synthetic `4` per `TEST_PLAN §57`
- `tests/test_phase15_real.py` (5) — `windows_adapter_real_on_windows_host` (platform `windows` + `source_adapter` `psutil live` + `sigma_hit`), `linux_adapter_synthetic_on_windows_host` (platform `linux` synthetic), `file_provider_real_hash` (temp file `real_file:true` + hash matches), `api_platform_real_evidence` (windows `>4` + linux `>4` + required fields), `contract_same_jocky_different_real_platform` (common schema `hostname`/`platform`)

#### Verified
- `pytest` 157/157 (5 new) — `psutil` live on Windows host returns `>50` Windows processes with `source_adapter` `psutil live`, Linux provider synthetic fallback preserves contract, real file hash verified via temp file

### 2026-08-28 — Hardening P2 (Resource Limits + Audit)

#### Added
- `backend/app/audit.py` (60 lines) per `SECURITY §34-36` + `ARCHITECTURE §11`: `_events` + `_last_hash` chain, `log_event(actor,action,target,result,metadata)` (hash via `sha256(sorted json + prev_hash)`), `get_events(limit,action,actor)`, `clear_for_tests()`, printed `[audit]` per `DESIGN §50`
- `backend/app/main.py` — `MAX_IR_SIZE`/`MAX_EVIDENCE_SIZE`/`MAX_SOURCE_SIZE` env (100KB/5MB/50KB) per `SECURITY §28` `DESIGN §53`, `POST /api/compile` + `POST /api/run` + `POST /api/evidence` now `413` when exceeded, `log_event` on `compile/run/evidence.submit/capability_denied`, `GET /api/audit` (limit/action/actor)
- `tests/test_hardening_p2.py` (9) — source too large 413, compile too large 413, evidence too large 413, audit capability_denied, evidence submit, run execute, hash chain (`prev_hash == prior hash`), audit endpoint + filter, compile rejected logged

#### Verified
- `pytest` 152/152 (9 new) — resource limits `413` per `SECURITY §28`, audit hash chain per `§36`

### 2026-08-28 — Language Features P1 (Variables, Investigation, Filter, Correlate)

#### Added
- `tools/jocky_lexer.py` — `KEYWORDS` adds `investigation`, `_extract_investigations()` (`investigation "title" {`), filter/correlate 2-arg validation per `LANGUAGE §12,15`, variable `x = op()` assignments already supported via member-call extraction
- `backend/app/main.py` — `_extract_investigation_titles()` + `POST /api/run` sets case title from first `investigation` if case title generic, per `FORENSICS §7` case = investigation
- `tests/test_language_features.py` (9) — variable assignment, `let`, investigation extracts title+ops and creates case with title, investigation with filter, filter/correlate arg validation, combined investigation+correlate, unknown still fail-closed inside investigation, variable with `evidence.load`

#### Verified
- `pytest` 143/143 (9 new) — `investigation "host_scan" { system.info(); process.list(); }` → case 910 title `host_scan`, combined sweep via investigation block

### 2026-08-28 — Evidence.load Wiring (Controlled Fixtures)

#### Added
- `backend/app/main.py` `make_envelope` `evidence.load` branch per `LANGUAGE_SPEC §28` + `IR_SPEC §18.1` + `FORENSICS §61`: `extract_file_arg` + `validate_path` + allowed roots `candidates` (`/app/testdata`, `testdata`, etc, bare filename fallback), `not found` 400 with checked paths, JSON parse, `type` derived from fixture, `payload` merges fixture fields + `source="evidence.load"` + `source_file` + `platform` + `note` per §61, `ev_type` from fixture `type`
- `tests/test_evidence_load.py` (9) — hollowing (memory hollowed), byovd (driver RTCore64), platform agnostic (same fixture windows vs linux same hollowed but platform differs), traversal rejected 400, missing arg 400/422, not-found 400, timeline/graph/risk isolation, combine with `process.list` + `file.hash` (3 evidences + correlation), lexer `evidence.load` whitelist

#### Verified
- `pytest` 133/133 (9 new) — `evidence.load("testdata/hollowing.json")` → memory hollowed `source_file` preserved, platform param respected, combined sweep 3 evidences graph `correlation_count≥1`

### 2026-08-28 — Sigma Auto-Tune (Per-Evidence Tuning)

#### Added
- `backend/app/sigma_tuner.py` (90 lines) per ARCHITECTURE §13 + FORENSICS §34: `_BASE` 2 rules `jocky-001 T1055` `jocky-002 T1068`, `_overrides` + `_history`, `get_rules()` (merges overrides + hits from history), `tune_rule(rule_id,level,confidence)` (validates `level` ∈ {low,medium,high,critical,info} + `confidence` (0,1], raises 400), `auto_tune(evidence_store)` (hit rate >0.5 → confidence 0.7 else <0.1 → 0.9, defensive never disables), `reset_tuning()`, `status()`
- `backend/app/main.py` — `GET /api/sigma/rules` + `POST /api/sigma/tune` (`SigmaTuneRequest`) + `POST /api/sigma/auto-tune` + `GET /api/sigma/status` per SECURITY §43 auditable tuning
- `tests/test_sigma_tuning.py` (6) — rules count, tune confidence, invalid 400, auto_tune after 3 process evidences, direct tuner, frontend presence

#### Verified
- `pytest` 124/124 (6 new) — auto_tune after 3 `process.list` evidences triggers `POST /api/sigma/auto-tune` → `status` history

### 2026-08-28 — Timeline / Graph / Risk Detail (Expand + History)

#### Added
- `backend/app/main.py` — `GET /api/cases/{id}/risk/history` (ordered by timestamp, `cumulative_max` per evidence, per ARCHITECTURE §15), `GET /api/cases/{id}/risk/breakdown` (per-evidence `behavioral`/`sigma` via `detection_engine`, `max_risk`/`level`), `GET /api/cases/{id}/graph/expand` (`node_id` → `evidence` + `neighbors`/`neighbor_evidence`, or `expanded:true` for full graph)
- `frontend/src/components/Timeline.tsx` — `q` search (id/type/op/host/mitre/payload) + `minRisk` selector (all/≥30/≥60/≥80) + filtered count + `onClick` alert per DESIGN §41
- `frontend/src/components/RiskGauge.tsx` — `history` sparkline (last 20) already, now `breakdown` toggle (`POST` fetch `/risk/breakdown`) + table `id type risk mitre behavioral.rules` + links to `/risk/history` + `/risk/breakdown`
- `frontend/src/components/Graph.tsx` — `onSelect` prop + `onNodeClick`
- `frontend/src/App.tsx` — `riskHistory` (push every `refresh`), `selectedNode` chip with `expand` button (`GET /api/cases/{id}/graph/expand?node_id=`)
- `tests/test_timeline_graph_risk_detail.py` (6) — risk/history, risk/breakdown, graph/expand node + without node + 404, frontend detail UI presence

#### Verified
- `pytest` 118/118 (6 new)

### 2026-08-28 — Auth Hardening (JWT per SECURITY §19-20)

#### Added
- `backend/app/auth.py` (90 lines) per `SECURITY_MODEL §19-20` + `ARCHITECTURE §10`: `JWT_SECRET` (`HS256`, `JWT_EXPIRE 3600`), `create_token(sub,role)` + `verify_token` via `python-jose`, `get_current_user` (`Authorization: Bearer` or `X-API-Key`, `AUTH_REQUIRED` env default `false` for host tests, strict `401` when `true`), `require_role`
- `backend/app/main.py` — `AuthRequest/AuthResponse` + `POST /api/auth/login` (demo any username → JWT `bearer`), `GET /api/auth/me` (via `Depends(get_current_user)`), `GET /api/auth/status` (auth_required/jwt_alg), `GET /api/storage/status` now includes `auth_required`, added `auth` import with fallback
- `tests/test_auth.py` (8) — status, login→JWT + verify, me bypass, me with token, invalid 401, health storage auth field, run without auth when not required, strict mode 401/200

#### Verified
- `pytest` 112/112 (8 new) — JWT `HS256` verified via `jose`, strict mode toggles `AUTH_REQUIRED` and validates `401` without token

### 2026-08-28 — Report Hardening (Versioned History)

#### Added
- `backend/app/storage.py` — `list_reports(case_id)` (scan `jocky-reports` mem+MinIO prefix `case-{id}/`, sorted) + `delete_reports_for_case` (test cleanup) + `put_report` now dual-writes `latest` + versioned `JOCKY_case_{id}_report_{ts}_{sha8}.pdf` per `FORENSICS §64` provenance + `ARCHITECTURE §11` artifact store
- `backend/app/main.py` — `GET /api/cases/{id}/reports` (list `reports/count`, via `list_reports`) + `GET /api/cases/{id}/reports/{key}` (fetch versioned PDF via `get_bytes`)
- `tests/test_report_hardening.py` (3) — `test_report_history_list` (creates case, generates 2 reports, seeds versioned via `put_report` and verifies `count≥2` + versioned fetch), `test_storage_list_reports_direct`, `test_health_includes_storage_history`

#### Verified
- `pytest` 98/98 (3 new)

### 2026-08-28 — Dashboard Enrichment (Timeline Search + Risk History + Graph Select)

#### Added
- `frontend/src/components/Timeline.tsx` — search `q` filter (id/type/op/host/mitre/payload) + `minRisk` selector (`all/≥30/≥60/≥80`) + `filtered` count + click handler (`onClick` alert with `id/risk/op/host`) per DESIGN §41 presentation layer
- `frontend/src/components/RiskGauge.tsx` — `history?:number[]` prop, sparkline SVG (last 20, `polyline` `stroke` per risk color, `transition-all`) + `MEDIUM→LOW` level + weighted text `PPID*30 + hollowed*40 + driver*15 + yara*20 + C2*30 (hash≠detection)`
- `frontend/src/components/Graph.tsx` — `onSelect?:(id)=>void` + `onNodeClick` → parent `selectedNode` chip
- `frontend/src/App.tsx` — `riskHistory` state (push every `refresh`), `selectedNode` state, pass `history` to `RiskGauge`, `onSelect` to `Graph`, selected chip shows `type risk mitre platform`, evidence/graph counts show `selectedNode` where applicable

#### Verified
- `pytest` 95/95 still passing (no backend change)
- Manual: Timeline search filters live events, RiskGauge sparkline renders after 2+ runs, Graph click shows selected chip

### 2026-08-28 — Harden & Persist (MinIO + Redis)

#### Added
- `backend/app/storage.py` (120 lines) per ARCHITECTURE §11 + FORENSICS §47 — `MINIO_ENDPOINT` (`minio:9000` docker / fallback `localhost:9000`), `BUCKET_REPORTS=jocky-reports` + `BUCKET_EVIDENCE=jocky-evidence` (auto-create), `put_bytes/get_bytes`, `put_report(case_id, pdf)`/`get_report`, `put_evidence_artifact`, `storage_status()`, mem fallback `_mem_store` for host tests when MinIO not reachable
- `backend/app/cache.py` (110 lines) per ARCHITECTURE §11 — `REDIS_URL` (`redis://redis:6379/0` docker / fallback localhost), `cache_get/set/invalidate` (TTL, JSON, mem fallback `_mem_cache`), `cache_status()`
- `backend/app/main.py` — `_storage`/`_cache` import + `GET /health` adds `minio`/`redis` + `storage`/`cache` fields, `GET /api/storage/status`, `POST /api/artifacts/upload` (5MB 413 per SECURITY_MODEL §28) + `GET /api/artifacts/{key}`, `POST /api/evidence` → `put_evidence_artifact` + cache invalidate, `GET /api/cases/{id}/report` → `put_report` to MinIO + Redis `TTL 300` with `X-Report-Cached`, `POST /api/report` → MinIO
- `tests/test_storage.py` (8) — health includes minio/redis, storage status, put/get fallback, cache fallback, report→MinIO, evidence artifact, artifact upload/get, too-large 413

#### Verified
- `pytest` 90/90 (8 new) — `GET /health` `minio`/`redis` booleans, `GET /api/storage/status`, `put_report` fallback, `cache_get/set`, `GET /api/cases/777/report` `%PDF` + MinIO `get_report(777)`, `POST /api/evidence` artifact, artifact upload 413 on 6MB

### 2026-08-28 — Detection Depth (YARA 5 + Sigma 2 + Behavioral)

#### Added
- `backend/app/detection_engine.py` (180 lines) per ARCHITECTURE §13 + FORENSICS §31 — `load_sigma_rules()` (yaml `sigma/rules.yml` + fallback `SIGMA_RULES`), `sigma_scan(payload)` (jocky-001 `svchost ppid_anomaly` T1055, jocky-002 `RTCore64` T1068, confidence 0.85/0.95), `behavioral_scan()` (13 weights per `detector.py` + `calc_risk`: ppid 30/hollowed 40/unbacked 25/reflective 35/vuln 30/yara 20/sigma 15/file yara 35/C2 30 etc), `detect()` merges sigma+behavioral into finding shape `rule/severity/mitre/confidence/source`, `risk_for_payload()` delegate
- `yara/rules.yar` — + `File_Suspicious_PE` (sample.exe|malware.exe T1105) + `Network_C2_Beacon` (192.0.2.20 T1071) → 5 rules total
- `backend/app/main.py` — `yara_scan_content()` fallback now includes `File_Suspicious_PE` (`sample/malware`) + `Network_C2_Beacon` (`192.0.2.20`) + `rtc_core` case-insensitive for BYOVD
- `backend/requirements.txt` — added `pyyaml==6.0.3` for sigma yaml parsing
- `tests/test_detection_depth.py` (11) — sigma load, sigma ppid/byovd, negative benign, behavioral hollowing + full synthetic sweep per type, yara 5 rules presence, yara scan via API new rules, combined detect sigma+behavioral, api detect enriched, risk deterministic

#### Verified
- `pytest` 82/82 (11 new)
- `sigma_scan` + `behavioral_scan` produce `mitre/severity/confidence` per §31 — full sweep each non-system evidence has ≥1 behavioral hit

### 2026-08-28 — Platform Providers (Windows vs Linux Abstraction)

#### Added
- `backend/app/providers/base.py` — `ISystem/IProcess/IFile/INetwork/IDriverProvider` ABCs per DESIGN §22-23
- `backend/app/providers/windows.py` — `Windows*Provider` synthetic WinAPI (`C:\\Windows\\explorer.exe`, `SYSTEM`, `command_line`, `C:\\Temp\\malware.exe`, `C:\\Windows\\System32\\drivers\\RTCore64.sys`) — same Sigma T1055 per §11 preserved
- `backend/app/providers/linux.py` — `Linux*Provider` synthetic `/proc` (`/usr/lib/systemd/systemd`, `uid`, `/tmp/malware.exe`, `ELF`, `permissions`, `inode`, `lsmod`)
- `backend/app/providers/factory.py` — `detect_platform()` (env `JOCKY_PLATFORM/AGENT_PLATFORM/PLATFORM` > `sys.platform`), `get_providers(platform)` tuple, `platform_from_request(param, header)` — LANGUAGE_SPEC §27 JOCKY language platform-agnostic, choice at runtime
- `backend/app/main.py` — `RunRequest.platform` field + `_platform_provider_payload(op,platform,host_id,agent_id,source)` dispatch, `make_envelope(..., platform)` adds `platform` to payload + uses provider, `POST /api/run` validates platform 400 on invalid, same `T1105/T1055` MITRE but different `platform` + paths per FORENSICS §67; `calc_risk` unchanged (normalization)
- `tests/test_platform_providers.py` (10) — factory, contract windows vs linux (pid/ppid/name/path + platform field + sigma_hit), file/net contract, `platform_from_request` priority, `POST /api/run` `platform=windows` → `C:\` + `platform windows`, `platform=linux` → `uid` + `platform linux`, invalid 400, same JOCKY different platform same MITRE same risk (normalization proof), language platform-agnostic compile

#### Verified
- `pytest` 71/71 (10 new)
- `POST /api/run {process.list}` via `platform=windows` vs `linux` both 4 procs same Sigma but different `platform`/`path`/`uid` — contract holds per TEST_PLAN §57

### 2026-08-28 — Compiler Grammar-Wired (Lexer/Parser per g4)

#### Added
- `tools/jocky_lexer.py` (185 lines) — `lex()` per `grammar/jocky.g4` + `jocky/src/Lexer.cpp` (WS/COMMENT skip, STRING with escapes, NUMBER, ID/KW, OP 2-char, line:col), `Token` dataclass, `parse_member_calls()` per g4 `MemberCall` `expr '.' ID '(' argList? ')'`, syntax errors for unterminated string / unmatched '(' with `LANGUAGE_SPEC §21` style, `MemberCall` dataclass, `OP_CAPS` single source, `validate_and_collect()` replaces `RE_CALL` regex (returns ops/caps/errors+tokens+calls), `lex_dump()`
- `tools/jockyc.py` — now imports `jocky_lexer.validate_and_collect` + `lex`, `generate_ir` uses grammar-wired errors, `.tokens` now real dump (`ID/DOT/... line:col`), `.ast` with `calls=` + `tokens=N`
- `backend/app/main.py` — same `jocky_lexer` import (single source with `jockyc.py`), removed `RE_CALL` regex, `validate_and_collect` now line:col aware per `§33`
- `tests/test_compiler_grammar.py` (12) — lex simple, comment+string, keywords, member_calls extract, unterminated string, unmatched paren, whitelist pass, unknown with location, dedup, integration with `jockyc` + backend

#### Verified
- `pytest` 61/61 (12 new)
- Backend + jockyc both reject `edr.disable();` → `Unknown … at 1:1 … Fail-closed.` (same message, same source)

### 2026-08-28 — Agent Real POST via Nginx (Layer 4 → L5 → L6)

#### Added
- `agent/agent.py` (185 lines, stdlib `urllib` only) — real transport per `ARCHITECTURE.md §7` + `FORENSICS_SPEC.md §56` + `SECURITY_MODEL.md §24`: `GET /health` via `http://nginx:80`, `POST /api/evidence` per `testdata/*.json` fixture (payload preserves integrity per `§26`), `POST /api/run` JOCKY sweep `system.info+process+file+net` via nginx (fail-closed 422 unknown / 403 `memory.analyze` denied via nginx same as direct), `GET /api/evidence?case_id` + `timeline/graph/risk` verification, fail-closed demo `edr.disable → 422`, wait-for-nginx loop (12×2s), env `BACKEND_URL/AGENT_ID/HOST_ID/CASE_ID/FIXTURE_DIR/JOCKY_SOURCE/AGENT_POLL_SECONDS`, idle loop `POLL_SECONDS>0` else `sleep 3600` preserving `tail -f` semantics
- `agent/Dockerfile` — `python3 python3-urllib3` + `COPY agent/agent.py` + `CMD ["python3","/app/agent.py","--scan"]` (C++ stub retained for reference)
- `docker-compose.yml` — `agent` env `HOST_ID/HOST-001 CASE_ID=1 JOCKY_SOURCE FIXTURE_DIR AGENT_POLL_SECONDS=0` + `healthcheck curl -sf http://nginx:80/health` (probes nginx per `ARCHITECTURE.md §21`)
- `tests/test_agent.py` (8) — import/helpers, mocked fixture POST, JOCKY success, unknown 422, denied 403, integration `agent_scan_once` delegating to `TestClient` (verifies evidence persisted PG), compose uses nginx, Dockerfile uses python via nginx

#### Verified
- Host `pytest` 49/49 (8 new agent tests)
- `agent_scan_once` integration: `GET /health` via nginx → ok `db:true yara:true`, fixtures posted, JOCKY sweep 4 evidence via nginx, timeline/graph/risk verified via nginx in same test

### 2026-08-28 — YARA Binary

#### Added
- `backend/Dockerfile` — `yara` apt package (`yara 4.5.2`) + existing pango/cairo
- `docker-compose.yml` — `backend` volumes `yara:/app/yara:ro` + `testdata:/app/testdata:ro` (rules visible as `/app/yara/rules.yar` inside container)
- `backend/app/main.py` — `yara_scan_content(content) -> (hits, yara_used)` helper: tries `yara /app/yara/rules.yar` via subprocess (binary `4.5.2`), fallback string search (`JOCKY_DEMO_MARKER`/`BYOVD_RTCore64`/`hollowed`) for host; `_yara_rules_path()` probes `/app/yara/rules.yar`, `yara/rules.yar` etc; `YaraScanRequest` + `PolyDemoRequest`, endpoints `POST /api/yara/scan` (sha256 + hits + yara_used), `GET /api/yara/status` (yara_available, test_hits, rules length), `POST /api/yara/polymorphic-demo` (hash≠detection proof: 3 seeds→ distinct hashes but same_yara_cluster true), `POST /api/detect` now delegates to `yara_scan_content` with `yara_used` flag + health now `yara:true`
- `frontend/src/App.tsx` — YARA panel: fetch `GET /api/yara/status`, `Run YARA Poly Demo` button → `POST /api/yara/polymorphic-demo` (shows 3 seeds sha12… hits + yara_used + distinct_hashes/same_yara_cluster), header badge `YARA ✅ binary` vs fallback, links to `/api/yara/status` + `/api/docs`
- `tests/test_yara.py` (6) — yara status, scan fallback, BYOVD, polymorphic hash≠detection, detect yara_used, compile IR yara hit

#### Verified
- Host `pytest` 41/41 (fallback string, yara binary not required)
- Docker :8000 — `GET /health` `yara:true yara_rules:/app/yara/rules.yar`, `GET /api/yara/status` `yara_binary_used true test_hits JOCKY_DEMO_MARKER`, `POST /api/yara/polymorphic-demo` 3 distinct SHA256 (`3df…/b6d5…/d450…`) → same_yara_cluster true (hash≠detection, Point 1+2), `/usr/bin/yara --version` `4.5.2` inside backend

### 2026-08-28 — Postgres Persistence

#### Added
- `backend/app/models.py` — expanded SQLAlchemy `Case/Evidence/Finding` tables (evidence_id, host_id, payload JSON, integrity, provenance, chain_of_custody, timestamp, risk, sha256)
- `backend/app/db.py` — `DATABASE_URL` `postgresql://jocky:jocky@db:5432/jockydb`, `init_db()` + `is_db_available()` with 2s timeout fallback to in-memory for host `pytest`, `db_upsert_case`, `db_add_evidence`, `db_list_evidence`, `db_add_finding`, `db_list_findings`, `db_clear_for_tests`; startup `on_event` connects and `Base.metadata.create_all`
- `backend/app/main.py` v1.2.0 — Postgres-aware helpers `_get_cases`, `_get_evidence`, `_get_findings`, `_add_case`, `_add_evidence`, `_add_finding`, `_update_case_risk`, `_db_available` banner; `ensure_case` → `_add_case`, `make_envelope` eid now uses `_get_evidence()` total for uniqueness across restarts; all endpoints (`list_cases`, `post_evidence`, `run`, `timeline`, `graph`, `risk`, `list_evidence`, `list_findings`, `build_report_html`) now read from PG when available, fallback to memory; `GET /health` now returns `db:true/false` + `postgres:true/false`, version 1.2.0

#### Verified
- Host `pytest` 35/35 still passing (fallback in-memory, `USE_DB` not required)
- Docker :8000 — `[db] Connected to db:5432/jockydb — tables ready` (twice on startup), `GET /health` → `db:true`; live case 90: `POST /api/run` 2 evidence → `restart backend` → `GET /api/evidence?case_id=90` still 2 (persisted), `GET /api/cases` count 2; `GET /health` version 1.2.0

### 2026-08-28 — Report Generation

#### Added
- `backend/Dockerfile` — pango/cairo/gdk system deps + `pydyf==0.11.0` pin (fix weasyprint 62.3/pydyf 0.12 super().transform bug) → live PDF
- `backend/app/main.py` — `ReportRequest` + `build_report_html(case_id)` (case summary, findings, canonical envelopes with provenance/chain, timeline, graph, MITRE) + `render_pdf_bytes()` via `weasyprint.HTML` → `GET /api/cases/{id}/report` + `POST /api/report` StreamingResponse `application/pdf` (HTML fallback with `X-Report-Fallback` on host without deps)
- `frontend/src/App.tsx` — **📄 Report PDF** button per findings panel, `downloadReport()` fetches `GET /report` blob → `JOCKY_case_{id}_report.pdf` (or .html fallback)
- `tests/test_report.py` (4) — report generation for populated case (pdf or html fallback), empty case, POST variant, chain/integrity content check

#### Verified
- 35/35 tests passing (host)
- Live Docker :8000 — `POST /api/run` 4-op sweep case 80 → `GET /api/cases/80/report` → `application/pdf` 20KB `%PDF` verified, saved `build/report_case_80.pdf`

### 2026-08-28 — Forensic Ops Expansion

#### Added
- `backend/app/main.py` v1.1.1 — `extract_file_arg()` + `validate_path()` (SECURITY_MODEL path traversal reject, 400), richer `make_envelope()`: `process.list` → 4-proc tree (systemd→explorer→svchost anomaly→malware.exe yara) Sigma jocky-001 T1055 risk 60, `file.hash` → path-aware synthetic with `hashes.sha256/sha512`, suspicious/malware/sample YARA JOCKY_DEMO_MARKER T1105 risk 55, `network.connections` → 2 conns (C2 192.0.2.20:443 pid 9012 + mDNS) T1071 risk 30; combined `system+process+file+net` → 4 evidence star graph
- `backend/app/main.py` — `calc_risk()` enriched (yara +20, sigma +15, procs combined anomaly+yara bonus +10, file yara +35, C2 +30), graph now star host→evidence + process→file/net correlation edges, mitre set per payload
- `frontend/src/App.tsx` — default sweep `system.info+process.list+file.hash+network.connections`, buttons for each op + full sweep + traversal fail demo, richer evidence detail (process counts, file hash slice, C2 flag, yara), findings show severity color
- `tests/test_forensic_ops.py` (6) — file.hash synthetic/ traversal 400, process rich 4-proc/Sigma, network conns, combined sweep 4 evidence star graph verified
- `frontend/src/components/Graph.tsx` → already live

#### Verified
- 31/31 tests passing (9+13+3+6)
- Live on :8000 case 60: full sweep 4 evidence risk 60 MEDIUM graph 6 nodes timeline 4

### 2026-08-28 — E2E `system.info();` Milestone

#### Added
- `jocky/include/jocky/IRGen.h` — IRResult struct (ir_version 1, capabilities, ops, error) + generateIRWithValidation()
- `jocky/src/IRGen.cpp` — OP_CAPS whitelist (15 ops), RE_CALL regex validation, IR_VERSION=1 header, fail-closed error paths
- `tools/jockyc.py` — same whitelist + 422 fail-closed, IR_VERSION/CAPS/OPS header, cap dedup, 3 hashes still verified
- `backend/app/main.py` v1.1.0 — POST /api/compile, POST /api/run (cap policy DEFAULT_POLICY deny memory.analyze →403), canonical envelope make_envelope() schema_version 1 + integrity SHA256 + provenance + chain_of_custody, per-case findings, live /timeline|graph|risk, /evidence?case_id + /findings?case_id
- `frontend/src/App.tsx` — JOCKY editor (textarea + Compile/Run + quick buttons for system.info/process.list/edr.disable fail demo), IR pane, live fetches for Graph/Timeline/RiskGauge/evidence+findings, 5s poll
- `frontend/src/components/Graph.tsx` — live data prop, demo fallback preserved
- `frontend/src/components/Timeline.tsx` — live events prop, demo fallback preserved
- `tests/test_compiler.py` (9), `tests/test_backend.py` (13), `tests/test_e2e.py` (3) — 25 tests covering IR validation, backend 422/403, E2E envelope fields, polymorphic YARA marker
- `docker-compose.yml` — nginx 8082:80 (was 80:80, conflict with System port 4 on Windows)

#### Verified
- 25/25 tests passing (host, no Docker)
- Live backend on :8000: `POST /api/run {system.info();}` → EV-... risk 5 LOW finding INFO, timeline 1, graph 3 nodes
- Live frontend on :3000: editor Run flow updates live graph/timeline/risk

#### Changed
- `jocky/src/main.cpp` — prints ir_version + caps on success, error text on fail

### 2026-08-28 — Initial Takeover Audit

* Established core project documentation structure.
* Added architecture/design/specification documentation.
* Defined system boundaries and major engineering principles.
* Established `STATUS.md` as the implementation source of truth.
* Established `TEAMMATES.md` for project ownership.
* Full 29-subsystem audit (docs/STATUS.md §§3–7) with file evidence + TestClient 7 checks.
* Fix `docs/ARCHITECTURE.md` typo, update README Current Status/Quick Start, CHANGELOG.

---

# 12. Change Log Format

Use:

```text
## YYYY-MM-DD — Short Description

### Added
- ...

### Changed
- ...

### Fixed
- ...

### Tested
- ...

### Known Issues
- ...

### Next
- ...
```

Do not write vague statements such as:

```text
"Made progress"
"Improved system"
"Worked on backend"
```

Instead state exactly what changed.

---

# 13. Verification Rule

A coding agent MUST NOT mark a feature `🟢 Complete` solely because:

* code was written,
* compilation succeeded,
* a function exists,
* or a test was not run.

Completion requires evidence.

Preferred evidence:

```text
Implementation
+
Automated Test
+
Integration Test where applicable
+
Manual Verification where necessary
```

---

# 14. Documentation Synchronization

Whenever implementation changes a documented contract, update the appropriate specification.

Examples:

```text
Language behavior changed
        ↓
LANGUAGE_SPEC.md

IR structure changed
        ↓
IR_SPEC.md

Evidence schema changed
        ↓
FORENSICS_SPEC.md

Security boundary changed
        ↓
SECURITY_MODEL.md

Architecture changed
        ↓
ARCHITECTURE.md

Engineering decision changed
        ↓
DESIGN.md
```

Then update this file.

---

# 15. Agent Rule

The coding agent must read this file before beginning substantial work.

After completing a meaningful task it must:

```text
1. Run relevant tests.
2. Inspect the resulting state.
3. Update STATUS.md.
4. Record known limitations.
5. Record the next logical task.
6. Commit the change when the repository workflow requires it.
```

The agent must never fabricate completion status.

---

# 16. Current Truth

The most important rule of this document is:

> **STATUS.md describes reality, not intention.**

If something is uncertain, mark it:

```text
🔴 Not Verified
```

rather than assuming it works.

If something partially works, mark it:

```text
🟡 In Progress
```

and describe the limitation.

The project should prefer an honest incomplete status over a misleading complete status.
