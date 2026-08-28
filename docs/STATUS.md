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

# 7. Currently Verified (2026-08-28 — Forensic Ops Expansion)

### Verified on Host + Docker (evidence logged, 31 tests)

* **Host compiler** `tools/jockyc.py` → IR_VERSION=1, IR_CAPS/IR_OPS, EntryPoint, JOCKY_DEMO_MARKER, bb.poly.* — 3 hashes differ + `edr.disable()` → exit 2 fail-closed (9 compiler tests)
* **Backend API** `backend/app/main.py` v1.1.1 (enriched) via TestClient **and live on :8000**:
  * `POST /api/run {system.info();}` → risk 5 LOW (`type:system` envelope)
  * `POST /api/run {process.list();}` → 4 correlated processes (systemd→explorer→svchost ppid_anomaly→malware.exe yara) risk 60 HIGH, Sigma jocky-001, MITRE T1055
  * `POST /api/run {file.hash("/evidence/sample.exe");}` → path extracted + validate_path traversal 400, hashes sha256/sha512, YARA JOCKY_DEMO_MARKER for suspicious/malware/sample, risk 55
  * `POST /api/run {network.connections();}` → 2 conns (C2 192.0.2.20:443 pid 9012 malware.exe + mDNS), MITRE T1071, risk 30
  * `POST /api/run {system.info(); process.list(); file.hash("/tmp/malware.exe"); network.connections();}` → 4 evidence, risk 60 MEDIUM, star graph host→each evidence + process→file/process→net edges, timeline 4
  * Fail-closed: `file.hash("../../etc/passwd")` → 400 traversal rejected (SECURITY_MODEL path security), `memory.analyze` → 403, unknown op → 422
  * Live verified on :8000 case 60 (full sweep 4 evidence, risk 60, graph 6 nodes, timeline 4)
* **E2E** `system.info();` + `process.list` + `file.hash` + `network.connections` via `POST /api/run` → live curl + `tests/test_e2e.py` + `tests/test_forensic_ops.py` (6)
* **Docker** 9 services Up verified: backend 8000, frontend 3000 (full sweep editor), nginx 8082, db healthy, redis/minio/jocky/detector
* **Dashboard** :3000 — JOCKY editor now default `system.info()+process.list+file.hash+network.connections`, buttons for each op + full sweep + traversal fail demo, IR pane IR_VERSION=1, live evidence detail (process counts, file hashes, C2 flags), star graph with correlation edges
* **Tests** 31/31 passing: `test_compiler` 9 + `test_backend` 13 + `test_e2e` 3 + `test_forensic_ops` 6

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
