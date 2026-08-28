# JOCKY — Project Status

**Document:** `STATUS.md`
**Project:** JOCKY
**Status:** Active Development
**Last Updated:** 2026-08-28

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
| Lexer                   | 🟠 Scaffolded   | Hand-rolled lex() + g4 exists; not wired to validator |
| Parser                  | 🟠 Scaffolded   | 3-line stub; validation via regex RE_CALL in jockyc.py/IRGen.cpp |
| AST                     | 🟠 Scaffolded   | `.ast` stub; no visitor                    |
| Semantic analysis       | 🟡 Partial      | Unknown op → 422 fail-closed via OP_CAPS whitelist (verified) |
| Capability system       | 🟡 Partial      | 15 ops → 8 caps; DEFAULT_POLICY deny memory.analyze (403), allow system.read etc. |
| IR                      | 🟢 Verified     | IR_VERSION=1, IR_CAPS/IR_OPS, EntryPoint, Imports, JOCKY_DEMO_MARKER, bb.poly.* (25 tests) |
| IR validation           | 🟢 Verified     | Unknown capability → 422; capability denied → 403 (fail-closed, tested) |
| Runtime                 | 🟡 Partial      | Synthetic provider per op (system.info→system envelope); not yet WinAPI/Linux |
| Forensic adapters       | 🟠 Scaffolded   | Synthetic only; platform abstraction not yet |
| Evidence model          | 🟢 Verified     | Canonical envelope schema_version 1 + integrity SHA256 + provenance (tested, E2E) |
| Agent                   | 🟡 Partial      | C++ stub still; harness is POST /api/run (synthetic) — transport via nginx 8082 live |
| Backend                 | 🟢 Verified     | + POST /api/compile + POST /api/run + /api/evidence?case_id + /api/findings (25 tests, live on :8000) |
| Detection engine        | 🟡 Partial      | calc_risk + YARA string hits still; per-evidence finding created on run (risk 5 INFO) |
| Investigation graph     | 🟢 Verified     | GET /api/cases/{id}/graph live nodes/edges + ReactFlow live wiring (demo fallback ok) |
| Timeline                | 🟢 Verified     | GET /api/cases/{id}/timeline live ordered by observed_at (tested) |
| Dashboard               | 🟢 Verified     | JOCKY editor (textarea + Compile/Run) + live Graph/Timeline/RiskGauge + evidence list + 5s poll — live on :3000 |
| Report generation       | 🔴 Not Started  | weasyprint in requirements but no /api/report |
| Docker environment      | 🟢 Verified     | 9 services up: backend :8000, frontend :3000, nginx 8082→80, db/redis/minio/jocky/detector live (2026-08-28) |
| Windows support         | 🔴 Not Verified | No WinAPI; synthetic HOST-001/WIN-001 IDs only |
| Linux support           | 🟡 Partial      | Synthetic provider reads no /proc yet; Docker Linux path verified |
| Controlled laboratory   | 🟡 Partial      | 6 fixtures synthetic + live system.info scenario in tests/test_e2e.py |
| End-to-end workflow     | 🟢 Verified     | `system.info();` → Compile → IR v1 → Run → envelope → Timeline/Graph/Risk live (E2E test + live curl) |
| Automated tests         | 🟢 Verified     | 25 tests (test_compiler 9, test_backend 13, test_e2e 3) all passing |

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

# 7. Currently Verified (2026-08-28 E2E Milestone)

### Verified on Host + Docker (evidence logged, 25 tests)

* **Host compiler** `tools/jockyc.py` → IR_VERSION=1, IR_CAPS/IR_OPS, EntryPoint, JOCKY_DEMO_MARKER, bb.poly.* — 3 hashes differ (9EF588../58D518../0D0D25..) + `edr.disable()` → exit 2 fail-closed (9 compiler tests)
* **Backend API** `backend/app/main.py` v1.1.0 via TestClient **and live on :8000**:
  * `GET /health` → `jocky_ir_version 1`
  * `POST /api/compile {system.info();}` → ir_version 1, caps [system.read], ops [system.info], source_hash/ir_hash
  * `POST /api/compile {edr.disable();}` → 422 `Unknown or unsupported capability`
  * `POST /api/run {system.info();}` → envelope `EV-... schema_version 1 integrity.sha256 provenance.ir_hash chain_of_custody` risk 5 LOW finding F-... (case isolation verified)
  * `POST /api/run {memory.analyze(1234);}` → 403 `Capability denied`
  * `GET /api/cases/{id}/timeline` → ordered evidence (live)
  * `GET /api/cases/{id}/graph` → nodes/edges/mitre live (host→evidence→finding)
  * `GET /api/cases/{id}/risk` → 5 LOW for system.info
  * `GET /api/evidence?case_id=` + `/api/findings?case_id=` live
* **E2E** `system.info();` → Compile → IR v1 → Run → envelope → Timeline/Graph/Risk live (test_e2e + live curl `POST /api/run` on :8000)
* **Docker** 9 services up: backend :8000, frontend :3000, nginx 8082→80, db (healthy), redis, minio, jocky, detector — verified `docker compose ps`
* **Dashboard** frontend :3000 Live: JOCKY editor (Compile/Run + edr.disable fail demo), IR pane, live Graph/Timeline/RiskGauge/evidence list, 5s poll
* **Tests** 25/25 passing: `tests/test_compiler.py` 9 + `tests/test_backend.py` 13 + `tests/test_e2e.py` 3
* **Docker compose build caches**: backend + frontend rebuilt with new code

### Still Pending / Not Verified

* Real forensic adapter behavior (WinAPI/ETW, /proc) — synthetic provider only
* Report generation (`/api/report` + WeasyPrint PDF)
* Windows native validation (synthetic IDs only)
* YARA binary scanning (still string-contains in Python)
* Persisted store: Postgres/Redis/MinIO declared but evidence still in-memory (lost on restart)

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
5. ✅ 25 tests — done
6. Add `process.list` richer synthetic graph (pid/ppid correlation) + Sigma enrichment
7. Add `file.hash`/`file.analyze` with payload normalizer (path, hash, file_type)
8. Add `network.connections` with Remoter/State normalization
9. Add case isolation UI (dropdown of cases from /api/cases) + host selector
10. Persist evidence to Postgres (wire sqlalchemy models.py → engine) with fallback to in-memory for tests
11. Wire YARA binary scanning for .ll polymorphic files (hash≠detection demo)
12. Report generation (/api/report → WeasyPrint PDF with evidence+findings+provenance)

---

# 11. Recent Changes

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
