# Changelog

All notable changes to JOCKY will be documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
