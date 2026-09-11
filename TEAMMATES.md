# JOCKY — Teammates & Ownership

**Document:** `TEAMMATES.md`
**Project:** JOCKY
**Purpose:** Team structure, responsibilities, ownership, and collaboration rules
**Last Updated:** 2026-08-28

---

# 1. Purpose

This document defines:

* project members,
* their responsibilities,
* ownership boundaries,
* communication expectations,
* review responsibilities,
* and how work is divided.

The goal is to prevent duplicated work and unclear ownership.

This document should contain **real project information only**.

Do not invent team members, responsibilities, or contributions.

---

# 2. Team

| Member  | Role                     | Primary Ownership                                      | Secondary Ownership                  |
| ------- | ------------------------ | ------------------------------------------------------ | ------------------------------------ |
| Manthan | Project Lead / Developer | Architecture, integration, compiler/platform direction + Phase 15 Real `psutil`/`/proc` live + Docker health (`pg_isready -d jockydb`, `python urllib` healthcheck) | Documentation, testing, final review, `fix/docker-all-issues` (`Evidence.timestamp Any`, `timeline.json` list wrap) |
| TBD     | Developer                | TBD                                                    | TBD                                  |
| TBD     | Developer                | TBD                                                    | TBD                                  |
| TBD     | Developer                | TBD                                                    | TBD                                  |

Replace `TBD` with actual teammates when the team is finalized.

---

# 3. Ownership Areas

JOCKY is divided into the following engineering areas.

```text
                    JOCKY
                      │
       ┌──────────────┼──────────────┐
       │              │              │
    Language        Runtime       Forensics
       │              │              │
    Compiler         Agent        Evidence
       │              │              │
       └──────────────┼──────────────┘
                      │
                   Backend
                      │
                ┌─────┴─────┐
                │           │
             Detection    Frontend
                │           │
                └─────┬─────┘
                      │
                  Integration
```

---

# 4. Project Lead

## Responsibilities

The project lead is responsible for:

* overall technical direction,
* architecture decisions,
* scope control,
* integration,
* security boundaries,
* milestone planning,
* final technical review,
* documentation consistency,
* and project demonstration.

The project lead should ensure that individual components continue to follow the system contracts.

---

# 5. Language / Compiler Ownership

Responsibilities include:

```text
Lexer
Parser
AST
Semantic Analysis
Capability Analysis
IR Generation
Compiler CLI
Compiler Tests
```

The owner must ensure that compiler behavior matches:

```text
LANGUAGE_SPEC.md
IR_SPEC.md
SECURITY_MODEL.md
```

---

# 6. IR Ownership

Responsibilities include:

```text
IR schema
IR versioning
IR serialization
IR validation
IR compatibility
IR tests
```

The IR owner must coordinate closely with both:

```text
Compiler
Runtime
```

because the IR is the contract between them.

---

# 7. Runtime / Agent Ownership

Responsibilities include:

```text
Runtime dispatcher
Capability enforcement
Operation handlers
Agent lifecycle
Configuration
Logging
Transport
```

The runtime owner must ensure that the agent cannot execute operations outside the approved capability model.

---

# 8. Forensics Ownership

Responsibilities include:

```text
Forensic abstractions
Platform adapters
Evidence collection
Evidence normalization
Provenance
Integrity metadata
```

Platform-specific implementation must remain behind the common forensic interfaces wherever practical.

---

# 9. Backend Ownership

Responsibilities include:

```text
API
Authentication
Authorization
Case management
Agent management
Evidence ingestion
Database
Persistence
Report generation
```

Backend changes must preserve API and evidence contracts.

---

# 10. Detection Ownership

Responsibilities include:

```text
Detection rules
Rule engine
Correlation
Severity
Confidence
Risk scoring
Finding generation
```

Detection logic should consume canonical evidence rather than directly depending on endpoint-specific implementation.

---

# 11. Frontend Ownership

Responsibilities include:

```text
Dashboard
Case view
Evidence view
Timeline
Investigation graph
Risk presentation
Finding presentation
Report access
```

The frontend should remain a presentation layer and should not bypass backend security boundaries.

---

# 12. Testing Ownership

Testing is a shared responsibility.

Every developer is responsible for testing the code they modify.

Testing should cover:

```text
Unit Tests
Integration Tests
Security Tests
Regression Tests
End-to-End Tests
```

A feature should not be considered complete simply because it works manually once.

---

# 13. Documentation Ownership

Documentation is also shared.

The developer changing a contract is responsible for updating the corresponding documentation.

Examples:

| Change                 | Documentation       |
| ---------------------- | ------------------- |
| Language syntax        | `LANGUAGE_SPEC.md`  |
| Compiler architecture  | `ARCHITECTURE.md`   |
| IR structure           | `IR_SPEC.md`        |
| Evidence structure     | `FORENSICS_SPEC.md` |
| Security behavior      | `SECURITY_MODEL.md` |
| Testing strategy       | `TEST_PLAN.md`      |
| Future work            | `ROADMAP.md`        |
| Engineering decision   | `DESIGN.md`         |
| Current implementation | `STATUS.md`         |

---

# 14. Ownership vs Contribution

Ownership does not mean that only one person can modify a component.

It means the owner is responsible for understanding:

```text
Current state
Design
Known issues
Tests
Dependencies
Integration requirements
```

Other teammates may contribute through pull requests or shared development.

---

# 15. Cross-Component Dependencies

Important dependencies include:

```text
Compiler
   ↕
IR
   ↕
Runtime
   ↕
Forensics
   ↕
Evidence
   ↕
Backend
   ↕
Detection
   ↕
Frontend
```

Changes at a lower layer may affect every layer above it.

Therefore, contract changes require communication with dependent owners.

---

# 16. Change Ownership

Before making a major change:

```text
Identify owner
      ↓
Understand existing contract
      ↓
Implement change
      ↓
Run tests
      ↓
Update documentation
      ↓
Inform dependent owners
```

Do not silently change a shared contract.

---

# 17. Code Review Expectations

A review should check:

### Correctness

* Does the implementation satisfy the specification?
* Are edge cases handled?

### Security

* Does the change introduce an unnecessary capability?
* Can an untrusted input cross a security boundary?
* Does the implementation fail closed?

### Maintainability

* Is the design understandable?
* Is responsibility placed in the correct component?

### Testing

* Are relevant tests present?
* Are negative cases covered?

### Documentation

* Are affected specifications updated?

---

# 18. Definition of Done

A task is considered complete only when:

```text
[ ] Implementation finished
[ ] Relevant tests written/updated
[ ] Tests pass
[ ] Security implications reviewed
[ ] Documentation updated
[ ] Integration verified
[ ] STATUS.md updated
```

Not every task requires every item to the same depth, but the owner must explicitly record exceptions.

---

# 19. Git Workflow

Use small, meaningful commits.

Preferred:

```text
feat: add JOCKY process listing operation
fix: reject invalid IR capability
test: add evidence normalization cases
docs: update forensic evidence contract
refactor: isolate platform process provider
```

Avoid:

```text
update
changes
stuff
final
final2
working
```

---

# 20. Commit Principle

Each meaningful commit should represent one coherent change.

A commit should ideally answer:

> What changed, and why?

Avoid combining unrelated changes into one commit.

---

# 21. Pull Request / Review Principle

Before merging a significant change:

```text
Implementation
      ↓
Tests
      ↓
Documentation
      ↓
Security Review
      ↓
Integration
      ↓
Merge
```

---

# 22. Communication

When a change affects another subsystem, communicate:

```text
What changed
Why it changed
What interface changed
What could break
What the dependent developer needs to update
```

Example:

```text
IR v1 now requires an explicit capability field.

Compiler:
must emit the field.

Runtime:
must validate the field.

Tests:
must include missing-capability rejection.
```

---

# 23. Conflict Resolution

When two design approaches conflict:

1. Check the relevant specification.
2. Check `SECURITY_MODEL.md`.
3. Check `DESIGN.md`.
4. Discuss the trade-off.
5. Choose the smallest safe change.
6. Update documentation if the contract changes.

Do not resolve architectural conflicts by silently implementing whichever option is easiest.

---

# 24. AI Coding Agent Collaboration

AI coding agents may contribute code, tests, documentation, and refactoring.

However:

> **AI-generated code is not automatically considered verified code.**

The human project team remains responsible for:

```text
Architecture
Security
Scope
Testing
Final acceptance
```

Agents must follow:

```text
AGENTS.md
```

when it is established.

---

# 25. AI Agent Rules

Agents should:

```text
Read relevant documentation first.

Inspect the existing implementation before modifying it.

Prefer existing abstractions over creating duplicates.

Make the smallest coherent change.

Run relevant tests.

Never fabricate test results.

Never claim functionality is complete without verification.

Update STATUS.md after meaningful work.

Update specifications when contracts change.

Keep security boundaries intact.
```

---

# 26. Knowledge Sharing

No subsystem should become understandable only to one person.

For important components, maintain:

```text
Architecture documentation
Setup instructions
Testing instructions
Known limitations
Design rationale
```

The goal is to eliminate single-person dependency.

---

# 27. Handover Requirement

When transferring ownership of a component, provide:

```text
Current implementation status
How to run it
How to test it
Known bugs
Open design questions
Dependencies
Relevant documentation
```

---

# 28. Meeting / Progress Format

For project updates, use:

```text
### Completed
- ...

### In Progress
- ...

### Blocked
- ...

### Decisions
- ...

### Next
- ...
```

This keeps progress discussions focused on engineering reality.

---

# 29. Responsibility Matrix

Use this matrix once the actual team is finalized.

| Area          | Primary | Reviewer | Backup |
| ------------- | ------- | -------- | ------ |
| Architecture  | Manthan | TBD      | TBD    |
| Language      | Manthan | TBD      | TBD    |
| Compiler      | Manthan | TBD      | TBD    |
| IR            | Manthan | TBD      | TBD    |
| Runtime       | Manthan | TBD      | TBD    |
| Agent         | Manthan | TBD      | TBD    |
| Forensics     | Manthan | TBD      | TBD    |
| Backend       | Manthan | TBD      | TBD    |
| Detection     | Manthan | TBD      | TBD    |
| Frontend      | Manthan | TBD      | TBD    |
| Testing       | Manthan | All      | TBD    |
| Documentation | Manthan | All      | TBD    |
| Integration   | Manthan | All      | TBD    |
| Docker        | Manthan | All      | TBD    |

---

# 30. Final Principle

JOCKY is a system rather than a collection of independent modules.

Therefore:

```text
Individual Ownership
        +
Shared Contracts
        +
Continuous Testing
        +
Documentation
        +
Review
        =
Reliable Project
```

The objective is not merely to divide the code between teammates.

The objective is to ensure that every person understands:

```text
what they own,
what they depend on,
what depends on them,
and what must remain true
when they change their component.
```
