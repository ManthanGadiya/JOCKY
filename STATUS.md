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
| Documentation structure | 🟡 In Progress  | Core specifications being established      |
| JOCKY language          | 🟡 In Progress  | Language implementation evolving           |
| Lexer                   | 🟡 In Progress  | Verify against `LANGUAGE_SPEC.md`          |
| Parser                  | 🟡 In Progress  | Verify AST behavior                        |
| AST                     | 🟡 In Progress  | Core representation under development      |
| Semantic analysis       | 🟡 In Progress  | Capability validation required             |
| Capability system       | 🟡 In Progress  | Must remain explicit and fail-closed       |
| IR                      | 🟡 In Progress  | Versioned representation under development |
| IR validation           | 🟡 In Progress  | Security boundary                          |
| Runtime                 | 🟡 In Progress  | Operation dispatch under development       |
| Forensic adapters       | 🟡 In Progress  | Platform abstraction                       |
| Evidence model          | 🟡 In Progress  | Canonical schema under development         |
| Agent                   | 🟡 In Progress  | Collection/transport pipeline              |
| Backend                 | 🟡 In Progress  | API and persistence                        |
| Detection engine        | 🟡 In Progress  | Rule pipeline                              |
| Investigation graph     | 🟡 In Progress  | Backend-derived visualization              |
| Timeline                | 🟡 In Progress  | Evidence-driven                            |
| Dashboard               | 🟡 In Progress  | UI integration                             |
| Report generation       | 🟡 In Progress  | Requires stable investigation model        |
| Docker environment      | 🟡 In Progress  | Reproducible development/demo environment  |
| Windows support         | 🔴 Not Verified | Requires platform validation               |
| Linux support           | 🟡 In Progress  | Primary development environment            |
| Controlled laboratory   | 🟡 In Progress  | Synthetic fixtures preferred               |
| End-to-end workflow     | 🔴 Not Verified | Must pass complete pipeline                |
| Automated tests         | 🟡 In Progress  | Expand with each subsystem                 |

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

# 7. Currently Verified

Only place features in this section when there is concrete evidence that they work.

### Verified

* Project builds successfully.
* Docker development environment starts successfully.
* Core repository structure exists.
* Documentation foundation exists.

### Pending Verification

* Complete JOCKY compilation pipeline.
* Complete IR execution pipeline.
* Real forensic adapter behavior.
* Evidence integrity verification.
* Agent-to-backend communication.
* Detection-to-dashboard flow.
* Complete Windows compatibility.
* Complete Linux compatibility.
* End-to-end controlled laboratory scenario.

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

## Milestone: Core Platform Foundation

### Goal

Establish the foundation required for the complete JOCKY pipeline.

### Exit Criteria

```text
[ ] JOCKY source can be parsed
[ ] AST can be generated
[ ] Semantic validation works
[ ] Capabilities are explicit
[ ] Valid IR can be generated
[ ] Invalid IR is rejected
[ ] Runtime can execute approved operations
[ ] Evidence can be generated
[ ] Evidence can be normalized
[ ] Evidence can reach backend
[ ] Detection can consume evidence
[ ] Dashboard can display findings
[ ] Controlled lab scenario passes end-to-end
```

---

# 10. Immediate Next Tasks

Tasks should be ordered by dependency.

1. Verify current repository state.
2. Verify compiler pipeline.
3. Stabilize language semantics.
4. Stabilize IR contract.
5. Implement/verify capability validation.
6. Implement/verify runtime operation dispatch.
7. Implement canonical evidence model.
8. Implement controlled forensic adapters.
9. Implement agent transport.
10. Implement backend ingestion.
11. Implement detection pipeline.
12. Connect dashboard.
13. Build reproducible laboratory scenarios.
14. Add end-to-end tests.
15. Validate Windows/Linux compatibility.

---

# 11. Recent Changes

Every meaningful implementation session should add an entry.

### 2026-08-28

* Established core project documentation structure.
* Added architecture/design/specification documentation.
* Defined system boundaries and major engineering principles.
* Established `STATUS.md` as the implementation source of truth.
* Established `TEAMMATES.md` for project ownership.

Future entries must describe actual repository changes.

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
