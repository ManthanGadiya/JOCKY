# Changelog

All notable changes to JOCKY will be documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
