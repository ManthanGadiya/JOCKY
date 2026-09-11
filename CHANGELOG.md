# Changelog

All notable changes to JOCKY will be documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## 2026-08-28 — Correlation Enrichment — Temporal + PID + Platform (104 tests)

### Added
- `backend/app/main.py` `GET /api/cases/{id}/graph` → `correlations` (temporal 0.6, pid 0.8, process→file 0.85, process→net 0.9, supports 0.95) + `weight` + `correlation_count` + platform on nodes per `ARCHITECTURE §14` + `FORENSICS §43`
- `tests/test_correlation.py` (6) — full sweep correlations, temporal window, pid, mitre/platform, weight, confidence

## 2026-08-28 — Sigma Auto-Tune — Per-Evidence Tuning (124 tests)

### Added
- `backend/app/sigma_tuner.py` — `get_rules`/`tune_rule`/`auto_tune` (confidence 0.5-0.95, hit-rate >0.5→0.7) + `GET /api/sigma/rules` + `POST /api/sigma/tune` + `POST /api/sigma/auto-tune` + `GET /api/sigma/status`
- `tests/test_sigma_tuning.py` (6) — rules, tune 0.75, invalid 400, auto_tune, direct

## 2026-08-28 — Timeline / Graph / Risk Detail — Expand + History (118 tests)

### Added
- `backend/app/main.py` — `GET /api/cases/{id}/risk/history` + `/risk/breakdown` + `GET /api/cases/{id}/graph/expand?node_id=`
- `frontend/src/components/Timeline.tsx` — search + minRisk filter + filtered count + click
- `frontend/src/components/RiskGauge.tsx` — history sparkline + breakdown toggle
- `frontend/src/components/Graph.tsx` — onSelect
- `frontend/src/App.tsx` — riskHistory + selectedNode expand
- `tests/test_timeline_graph_risk_detail.py` (6) — history, breakdown, expand node/all/404, UI presence

## 2026-08-28 — Auth Hardening — JWT per SECURITY §19-20 (112 tests)

### Added
- `backend/app/auth.py` — `create_token`/`verify_token` `HS256` + `get_current_user` (`Bearer`/`X-API-Key`, `AUTH_REQUIRED` env default false, strict 401 when true)
- `backend/app/main.py` — `POST /api/auth/login` + `GET /api/auth/me` + `GET /api/auth/status` + `auth_required` in storage status
- `tests/test_auth.py` (8) — login JWT, verify, bypass, invalid 401, strict mode

## 2026-08-28 — Report Hardening — Versioned History (98 tests)

### Added
- `backend/app/storage.py` — `list_reports` + `delete_reports_for_case` + `put_report` versioned `_{ts}_{sha8}.pdf` per `FORENSICS §64`
- `backend/app/main.py` — `GET /api/cases/{id}/reports` + `GET /api/cases/{id}/reports/{key}`
- `tests/test_report_hardening.py` (3) — history list, direct storage list, health storage

## 2026-08-28 — Dashboard Enrichment — Timeline Search + Risk History + Graph Select

### Added
- `frontend/src/components/Timeline.tsx` — search `q` + `minRisk` filter (≥30/≥60/≥80) + filtered count + click handler
- `frontend/src/components/RiskGauge.tsx` — `history` sparkline SVG (last 20) + LOW level + correct weights
- `frontend/src/components/Graph.tsx` — `onSelect` + `onNodeClick`
- `frontend/src/App.tsx` — `riskHistory` + `selectedNode` wiring, chip shows `type risk mitre platform`

## 2026-08-28 — Case Isolation UI — Cases + Host/Platform Filters (95 tests)

### Added
- `backend/app/main.py` — `POST /api/cases` (CaseCreate auto-increment, per ARCHITECTURE §10)
- `frontend/src/App.tsx` — case isolation bar: case dropdown + `+ New Case`, `hostFilter`/`typeFilter`/`platformFilter`, `runPlatform` selector, `filteredEvidence` + filtered counts (FORENSICS §7, ARCHITECTURE §11)
- `tests/test_case_isolation.py` (5) — create+isolation, list grows, host/platform filters, UI presence

### Verified
- `pytest` 95/95 (5 new)

## 2026-08-28 — Harden & Persist — MinIO + Redis (90 tests)

### Added
- `backend/app/storage.py` — MinIO `jocky-reports`/`jocky-evidence` (auto-create, mem fallback), `put_report`/`get_report`/`put_bytes`/`get_bytes`/`put_evidence_artifact`, `storage_status()`
- `backend/app/cache.py` — Redis `cache_get/set/invalidate` (TTL 60/300, mem fallback), `cache_status()`
- `backend/app/main.py` — `GET /health` `minio`/`redis` fields + `storage`/`cache`, `GET /api/storage/status`, `POST /api/artifacts/upload` (5MB 413) + `GET /api/artifacts/{key}`, `POST /api/evidence` artifact + cache invalidate, `GET /api/cases/{id}/report` MinIO + Redis `X-Report-Cached`
- `tests/test_storage.py` (8) — health, storage status, put/get, cache, report→MinIO, evidence artifact, artifact upload/get, 413

### Verified
- `pytest` 90/90 (8 new)

## 2026-08-28 — Detection Depth — YARA 5 + Sigma 2 + Behavioral Engine

### Added
- `backend/app/detection_engine.py` — `load_sigma_rules()` (yaml + fallback), `sigma_scan()` (jocky-001 T1055 ppid anomaly, jocky-002 T1068 BYOVD), `behavioral_scan()` (13 weights: ppid/hollowed/unbacked/reflective/vuln/loldrivers/yara/sigma/C2), `detect()` (sigma+behavioral → rule/severity/mitre/confidence/source), `risk_for_payload()`
- `yara/rules.yar` — + `File_Suspicious_PE` (T1105) + `Network_C2_Beacon` (T1071) → 5 rules
- `backend/app/main.py` — `yara_scan_content()` fallback adds `File_Suspicious_PE`/`Network_C2_Beacon`/`rtc_core` strings
- `backend/requirements.txt` — `pyyaml==6.0.3`
- `tests/test_detection_depth.py` (11) — sigma load/ppid/byovd/negative, behavioral hollowing + full synthetic, yara 5 presence + API, combined detect, risk deterministic

### Verified
- `pytest` 82/82 (11 new)

## 2026-08-28 — Platform Providers — Windows vs Linux Abstraction (IProcessProvider)

### Added
- `backend/app/providers/base.py` — `ISystem/IProcess/IFile/INetwork/IDriverProvider` ABCs (DESIGN §22-23)
- `backend/app/providers/windows.py` — `Windows*Provider` synthetic WinAPI (`C:\\Windows\\...`, `SYSTEM`, `command_line`) + `linux.py` synthetic `/proc` (`uid`, `inode`, `lsmod`, `ELF`)
- `backend/app/providers/factory.py` — `detect_platform()` + `get_providers(platform)` + `platform_from_request()` — LANGUAGE_SPEC §27 same JOCKY, different adapter
- `backend/app/main.py` — `RunRequest.platform` + `_platform_provider_payload()` + `make_envelope(..., platform)` platform field; `POST /api/run` validates platform; same `T1105/T1055` but different platform/payload per FORENSICS §67
- `tests/test_platform_providers.py` (10) — factory, contract windows vs linux, file/net, platform_from_request, API windows/linux/invalid, same JOCKY diff platform same MITRE/risk, compile platform-agnostic

### Verified
- `pytest` 71/71 (10 new) — contract holds per TEST_PLAN §57

## 2026-08-28 — Compiler Grammar-Wired — Lexer/Parser per g4 replaces RE_CALL

### Added
- `tools/jocky_lexer.py` — `lex()` per `grammar/jocky.g4` + `jocky/src/Lexer.cpp` (ID/DOT/LPAREN/RPAREN/SEMI/COMMA/STRING/NUMBER/OP/KW/END, WS/COMMENT skip, line:col), `parse_member_calls()` per g4 `MemberCall`, `validate_and_collect()` with `at line:col` fail-closed errors, syntax checks for unterminated string / unmatched '('; single-source `OP_CAPS`
- `tools/jockyc.py` + `backend/app/main.py` — now both import `jocky_lexer` (single source; removes `RE_CALL` regex); `.tokens` real dump, `.ast` calls+tokens
- `tests/test_compiler_grammar.py` (12) — lex, comment/string, keywords, extract, syntax errors, whitelist, dedup, g4 coverage, jockyc+backend integration

### Verified
- `pytest` 61/61 (12 new) — both host fallback and backend reject `edr.disable()` with `at 1:1` location

## 2026-08-28 — Agent Real POST via Nginx — Layer 4 → L5 → L6

### Added
- `agent/agent.py` — stdlib `urllib` real transport: `GET /health` via `http://nginx:80`, `POST /api/evidence` per fixture, `POST /api/run` JOCKY sweep via nginx (same 422/403 fail-closed), verification `GET /evidence?case_id` + `timeline/graph/risk` via nginx, fail-closed demo `edr.disable→422`; env `BACKEND_URL/HOST_ID/CASE_ID/JOCKY_SOURCE/FIXTURE_DIR/AGENT_POLL_SECONDS`, wait-for-nginx loop, idle `sleep 3600` preserving tail semantics
- `agent/Dockerfile` — `python3-urllib3` + `COPY agent/agent.py` + `CMD ["python3","/app/agent.py","--scan"]` (C++ stub retained)
- `docker-compose.yml` — `agent` now `HOST_ID/CASE_ID/JOCKY_SOURCE/FIXTURE_DIR/AGENT_POLL_SECONDS=0` + `healthcheck curl -sf http://nginx:80/health`
- `tests/test_agent.py` (8) — mocked fixture POST, JOCKY 200/422/403, integration `agent_scan_once` via TestClient, compose + Dockerfile asserts

### Verified
- `pytest` 49/49 (8 new) — `agent_scan_once` integration posts via mocked nginx to real backend, evidence count ≥1, timeline ≥1
- `docker-compose.yml` `BACKEND_URL=http://nginx:80` + `healthcheck` `http://nginx:80/health` verified

## 2026-08-28 — YARA Binary — hash ≠ detection (Point 1+2) via yara 4.5.2

### Added
- `backend/Dockerfile` — `yara` apt (`yara 4.5.2`) alongside pango/cairo
- `docker-compose.yml` — `backend` volumes `yara:/app/yara:ro` + `testdata:/app/testdata:ro` (rules at `/app/yara/rules.yar`)
- `backend/app/main.py` — `yara_scan_content(content) -> (hits, yara_used)` helper (tries `yara /app/yara/rules.yar` binary via `subprocess` `4.5.2`, fallback string `JOCKY_DEMO_MARKER/BYOVD_RTCore64/hollowed` for host); `_yara_rules_path()` probes `/app/yara/rules.yar` etc; `YaraScanRequest` + `PolyDemoRequest`, endpoints `POST /api/yara/scan` (sha256 + hits + yara_used), `GET /api/yara/status` (yara_available, test_hits), `POST /api/yara/polymorphic-demo` (hash≠detection: 3 seeds→ distinct hashes but same_yara_cluster), `POST /api/detect` now `yara_used` flag + health `yara:true`
- `frontend/src/App.tsx` — YARA panel: `GET /api/yara/status` badge `YARA ✅ binary` vs fallback, `Run YARA Poly Demo` button → `POST /api/yara/polymorphic-demo` (shows 3 seeds sha12 hits + yara_used + distinct_hashes/same_yara_cluster), links to `/api/yara/status` + `/api/docs`
- `tests/test_yara.py` (6) — yara status, scan fallback, BYOVD, polymorphic hash≠detection, detect yara_used, compile IR yara hit

### Verified
- Host `pytest` 41/41 (fallback string, yara binary not required on host)
- Docker :8000 — `GET /health` `yara:true yara_rules:/app/yara/rules.yar`, `GET /api/yara/status` `yara_binary_used true`, `POST /api/yara/polymorphic-demo` 3 distinct SHA256 (`3df…/b6d5…/d450…`) → `same_yara_cluster true` (hash≠detection)

## 2026-08-28 — Postgres Persistence — evidence/cases/findings survive restart

### Added
- `backend/app/models.py` — expanded `Case/Evidence/Finding` SQLAlchemy tables (evidence_id, host_id, payload/integrity/provenance JSON, chain_of_custody, timestamp)
- `backend/app/db.py` — `DATABASE_URL` `postgresql://jocky:jocky@db:5432/jockydb`, `init_db()` with 2s timeout + `is_db_available()` fallback to in-memory for host `pytest`, helpers `db_upsert_case`, `db_add_evidence/findings`, `db_list_*`, `db_clear_for_tests`; startup `on_event` creates tables
- `backend/app/main.py` v1.2.0 — Postgres-aware wrappers `_get_cases/_get_evidence/_get_findings/_add_*`; `make_envelope` now uses `_get_evidence()` total for EV id uniqueness; `GET /health` returns `db:true postgres:true`; all endpoints read from PG when available, fallback to memory; `ensure_case` → `_add_case`
- `docs/STATUS.md` — Database 🟢 Verified

### Changed
- `STATUS.md` / `docs/STATUS.md` — Backend now `+ postgres`, Database row 🟢 Verified

### Verified
- Host `pytest` 35/35 still passing (in-memory fallback, no PG)
- Docker :8000 — `[db] Connected to db:5432/jockydb — tables ready`, `GET /health` `db:true`, live case 90: 2 evidence → `docker compose restart backend` → `GET /api/evidence?case_id=90` still 2 (persisted)

## 2026-08-28 — Report Generation — PDF via WeasyPrint

### Added
- `backend/Dockerfile` — `libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0 libcairo2` + `pydyf==0.11.0` pin (fixes weasyprint 62.3 `super().transform` bug)
- `backend/app/main.py` — `ReportRequest` + `build_report_html()` + `render_pdf_bytes()` (WeasyPrint) → `GET /api/cases/{id}/report` + `POST /api/report` → `application/pdf` 20KB per case (case summary, findings, evidence table with provenance/chain, timeline, graph). Fallback HTML with `X-Report-Fallback` on host without pango deps.
- `frontend/src/App.tsx` — **📄 Report PDF** button (findings panel) → `fetch GET /report` blob → `JOCKY_case_{id}_report.pdf` download (handles pdf vs html fallback)
- `tests/test_report.py` (4) — populated report, empty case, POST variant, chain/integrity content

### Changed
- `docs/STATUS.md` + `STATUS.md` — Report 🟢 Verified, 35 tests, Docker pango deps

### Verified
- Host `pytest` 35/35 (host fallback HTML)
- Docker :8000 `POST /api/run` 4-op sweep case 80 → `GET /api/cases/80/report` → `application/pdf` `%PDF` 20KB verified live (saved `build/report_case_80.pdf`)

## 2026-08-28 — Forensic Ops Expansion — process/file/network enriched + graph correlation

### Added
- `backend/app/main.py` v1.1.1 — `extract_file_arg()` + `validate_path()` (400 traversal reject), enriched `make_envelope()`: `process.list` 4-proc tree Sigma T1055 risk 60, `file.hash` path-aware YARA T1105 risk 55, `network.connections` C2 T1071, combined sweep 4 evidence risk 60, star graph `host→evidence` + `process→file/net` edges with mitre set
- `frontend/src/App.tsx` — default sweep now 4 ops, buttons for `file.hash`/`network.connections`/`full sweep`/`traversal fail`, richer evidence detail panel (process counts, file hash slice, C2 flag)
- `tests/test_forensic_ops.py` (6) — forensic ops E2E coverage including path traversal, rich payloads, combined graph/timeline

### Changed
- `backend/app/main.py` — `calc_risk()` now aggregates `processes` anomaly+yara bonus + file yara + C2 remote 192.0.2.20; graph now star + correlation edges
- `docs/STATUS.md` + `STATUS.md` — 31 tests, forensic ops enriched, docker still Up

### Verified
- `pytest` 31/31 passing
- Live `POST /api/run` full sweep case 60: 4 evidence risk 60 MEDIUM graph 6 nodes timeline 4; `file.hash("../../etc/passwd")` → 400 rejected

## 2026-08-28 — E2E `system.info();` Milestone — First Query from Dashboard Live

### Added
- `jocky/include/jocky/IRGen.h` — `IRResult` (ir_version 1, capabilities, ops, error) + `generateIRWithValidation()`
- `jocky/src/IRGen.cpp` — OP_CAPS whitelist (15 ops → 8 caps), `RE_CALL` regex validation, `IR_VERSION=1` header, fail-closed `generateIRWithValidation()`; C++ path now rejects unknown ops with code 2
- `jocky/src/main.cpp` — prints `ir_version` + caps on success; prints validation error on fail
- `tools/jockyc.py` — same whitelist, `validate_and_collect()` + `IR_VERSION=1`/`IR_CAPS`/`IR_OPS` header, dedup caps, polymorphic still yields 3 distinct SHA256
- `backend/app/main.py` v1.1.0 — `POST /api/compile` (ir_version 1, caps/ops, 422 on unknown), `POST /api/run` (cap policy DEFAULT_POLICY: `memory.analyze` → 403 deny, `system.read` allow; canonical envelope `schema_version 1` + `integrity.sha256` + `provenance` + `chain_of_custody`; per-case `findings` + risk; live `/timeline` `/graph` `/risk` with case_id filtering; `/evidence?case_id=` + `/findings?case_id=`)
- `frontend/src/App.tsx` — JOCKY editor (textarea + **Compile**/**Run** buttons + quick inserts for `system.info();`/`process.list();`/`edr.disable();` fail demo), IR pane (shows `IR_VERSION=1`), live fetches for Graph/Timeline/RiskGauge/evidence+findings, 5s poll, case 1 default
- `frontend/src/components/Graph.tsx` — now takes `data` prop (live nodes/edges/mitre) with demo fallback; auto-layout for backend graph
- `frontend/src/components/Timeline.tsx` — now takes `events` prop with demo fallback
- `tests/test_compiler.py` (9 tests), `tests/test_backend.py` (13), `tests/test_e2e.py` (3) — 25 tests covering IR version/caps, unknown op 422 fail-closed, memory 403, polymorphic YARA marker, E2E envelope field completeness
- `docker-compose.yml` — `nginx` host port `8082:80` (was `80:80` conflicting with SYSTEM PID 4 on Windows)

### Changed
- `docker-compose.yml` + live stack verified: `backend` :8000 + `frontend` :3000 + `nginx` 8082→80 + `db` healthy + `redis`/`minio`/`jocky`/`detector` all Up (2026-08-28 live curl)
- `docs/STATUS.md` + `STATUS.md` mirror — updated 29-row audit table: IR/validation, evidence envelope, backend, graph/timeline/dashboard all 🟢 Verified; Docker + E2E now 🟢; `Current Milestone` marked complete for `system.info();`; `Known Limitations` reduced
- `README.md` current status will be refreshed on next commit (see audit → E2E delta)

### Verified
- `pytest` 25/25 passing on host (no Docker)
- Live `POST /api/run {system.info();}` via `http://localhost:8000` → `EV-... schema_version 1` risk 5 LOW finding INFO → `GET /api/cases/1/timeline` 1 event, `graph` 3 nodes, `risk` 5
- Frontend :3000 serves new App.tsx (editor + live wiring) — `curl http://localhost:3000` returns Vite shell; manual browser Run flow updates live panels

### Fixed
- `edr.disable();` and `security.disable();` now fail-closed (exit 2 / HTTP 422) instead of silently succeeding with `nop`
- `memory.analyze(1234);` now correctly denied 403 per SECURITY_MODEL default-deny policy

## 2026-08-28 — Initial Takeover Audit

### Added
- `docs/STATUS.md` — full implementation audit (2026-08-28) distinguishing Implemented / Verified / Scaffolded / Not Started per AGENTS.md §30; covers all 29 subsystems with file evidence and TestClient verification.
- `docs/ARCHITECTURE.md` — corrected copy of `docs/ARCHITECHTURE.md` (filename typo fix; both retained for compatibility with existing references).

### Changed
- `README.md` — `Current Status` section replaced with audit-backed verdict (verified host compiler polymorphism 3 hashes, verified backend API risk 90 CRITICAL / 40, vs. not-connected pipeline, no tests, Docker not verified).
- `README.md` — `Quick Start` expanded into 2a Host-Verified Path (tools/jockyc.py without Docker) and 2b/3 Docker path, with explicit NOT VERIFIED labels and references to docs/STATUS.md §6.
- `STATUS.md` (root) — replaced generic template with audit-backed content (mirrors `docs/STATUS.md`).

### Verified (with evidence logged in docs/STATUS.md §6)
- Host fallback compiler: `tools/jockyc.py examples/test.jocky` with seeds 1/2/3 produces 3 distinct SHA256 (9EF588… / 58D518… / 0D0D25…).
- Backend FastAPI via TestClient: `GET /health`, `POST /api/evidence` (hollowing risk 90, byovd 40), `GET /api/cases/1/risk|timeline|graph`, `POST /api/detect` YARA hits.

### Known Issues (audit §7)
- Lexer/Parser/AST stubs; semantic analysis and capability enforcement missing; unknown ops not rejected.
- IR validation missing; runtime is 13-line hardcoded provider; evidence normalization missing.
- Agent stub prints but does not POST; backend in-memory only (Postgres/SQLAlchemy not wired).
- Detection is Python string-contains (YARA binary not invoked); timeline/graph are static mocks.
- Dashboard has no JOCKY editor / Run button; report generation not started.
- `tests/` does not exist; automated tests 0; Docker compose not verified on audit host.
- Windows/Linux platform providers not verified.

### Next
- Fix repository hygiene (commit audit docs), then milestone "First Usable E2E Query: system.info();" — see docs/STATUS.md §8–§9.

---

## 2026-08-28 — Prior (Initial Commit)

### Added
- Project scaffold: compiler (`jocky/`), runtime (`runtime/`), agent (`agent/`), backend (`backend/`), frontend (`frontend/`), testdata (`testdata/`), Docker environment (`Dockerfile`, `docker-compose.yml`, `nginx/`), detection (`yara/`, `sigma/`), documentation (`docs/`), examples (`examples/test.jocky`).
- Documentation foundation: `ARCHITECHTURE.md`, `LANGUAGE_SPEC.md`, `IR_SPEC.md`, `FORENSICS_SPEC.md`, `SECURITY_MODEL.md`, `TEST_PLAN.md`, `ROADMAP.md`, `DESIGN.md`.
