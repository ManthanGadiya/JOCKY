# JOCKY — Development Roadmap

**Document:** `docs/ROADMAP.md`
**Project:** JOCKY
**Version:** 1.0
**Status:** Development Roadmap
**Last Updated:** 2026-08-28

---

# 1. Purpose

This document defines the implementation roadmap for JOCKY.

The roadmap converts the project specifications into an ordered development plan.

The primary rule is:

> **Build the smallest safe foundation first, then progressively add compiler, forensic, detection, and investigation capabilities.**

No later phase should bypass the architectural, security, or testing requirements established by earlier phases.

---

# 2. Project Development Model

JOCKY should be developed in the following progression:

```text
Foundation
    ↓
Language
    ↓
AST / Semantic Analysis
    ↓
IR
    ↓
Compiler
    ↓
Capability System
    ↓
Forensic Runtime
    ↓
Agent
    ↓
Evidence Pipeline
    ↓
Backend
    ↓
Detection
    ↓
Investigation UI
    ↓
Reports
    ↓
Controlled Laboratory
    ↓
Cross-Platform Validation
    ↓
Hardening
    ↓
Final Demonstration
```

---

# 3. Phase 0 — Project Foundation

### Objective

Establish a clean, reproducible development environment.

### Tasks

```text
Repository structure
Build system
Docker environment
Dependency management
Formatting
Linting
Basic CI
Development documentation
Environment configuration
```

### Deliverables

```text
✓ Repository builds
✓ Docker environment starts
✓ CI runs
✓ Basic test framework exists
✓ Development instructions exist
```

### Exit Criteria

A new developer should be able to clone the repository and build the project without manually reconstructing the development environment.

---

# 4. Phase 1 — Core JOCKY Language

### Objective

Implement the minimal language frontend.

### Components

```text
Lexer
Parser
AST
Error reporting
```

### Initial language features

```text
Identifiers
Literals
Strings
Numbers
Booleans
Function calls
Statements
Comments
```

Example:

```text
system.info();
process.list();
```

### Deliverables

```text
✓ Lexer
✓ Parser
✓ AST representation
✓ Syntax errors
✓ Lexer tests
✓ Parser tests
```

### Exit Criteria

Valid JOCKY programs can be parsed into a deterministic AST.

---

# 5. Phase 2 — Semantic Analysis

### Objective

Make the language understand what programs mean rather than merely whether they are syntactically valid.

### Components

```text
Symbol handling
Type checking
Operation validation
Argument validation
Capability discovery
Semantic diagnostics
```

### Example

```text
file.hash("sample.exe");
```

should be accepted if the operation and argument type are valid.

Invalid usage must be rejected before IR generation.

### Deliverables

```text
✓ Type checking
✓ Function signatures
✓ Semantic validation
✓ Capability mapping
✓ Semantic diagnostics
```

### Exit Criteria

Invalid semantic programs cannot reach code generation.

---

# 6. Phase 3 — Intermediate Representation

### Objective

Create the stable intermediate representation used between the language and runtime.

### Components

```text
IR data model
IR serialization
IR parser
IR validator
IR versioning
```

### Requirements

The IR must be:

```text
Deterministic
Versioned
Explicit
Validatable
Capability-aware
```

### Deliverables

```text
✓ IR specification implemented
✓ IR generator
✓ IR parser
✓ IR validator
✓ IR tests
```

### Exit Criteria

The compiler can transform a valid AST into valid IR.

---

# 7. Phase 4 — Compiler Pipeline

### Objective

Connect the language frontend to the IR backend.

Pipeline:

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
IR Generation
     ↓
IR Validation
```

### Deliverables

```text
✓ jockyc executable
✓ Source compilation
✓ Compiler diagnostics
✓ IR output
✓ Compiler tests
✓ Golden tests
```

### Example

```text
jockyc examples/basic.jocky -o build/basic.ir
```

### Exit Criteria

A valid JOCKY program can be compiled into validated IR.

---

# 8. Phase 5 — Capability and Security Enforcement

### Objective

Make security policy a first-class part of execution.

### Components

```text
Capability registry
Capability declarations
Policy evaluation
Authorization
Resource limits
Audit events
```

### Principle

```text
Requested Capability
        ↓
Policy Check
        ↓
Allowed?
   ↙         ↘
 YES          NO
 ↓             ↓
Execute      Reject
```

### Deliverables

```text
✓ Capability registry
✓ Capability checking
✓ Denial handling
✓ Resource limits
✓ Security tests
✓ Audit logging
```

### Exit Criteria

A program cannot perform an operation outside its granted capability set.

---

# 9. Phase 6 — Forensic Runtime

### Objective

Implement the safe forensic operations exposed by JOCKY.

### Initial operations

```text
system.info()
process.list()
file.hash()
file.analyze()
network.connections()
driver.scan()
memory.analyze()
```

The exact operation set must follow `LANGUAGE_SPEC.md` and `FORENSICS_SPEC.md`.

### Architecture

```text
JOCKY Operation
       ↓
Runtime Interface
       ↓
Platform Adapter
       ↓
Evidence Normalizer
       ↓
Evidence Object
```

### Deliverables

```text
✓ Runtime interfaces
✓ Fixture-based runtime
✓ Forensic data normalization
✓ Error handling
✓ Runtime tests
```

### Exit Criteria

Supported forensic operations can produce structured evidence.

---

# 10. Phase 7 — Evidence Model

### Objective

Create a stable evidence representation.

### Evidence should support:

```text
Identity
Type
Timestamp
Source
Content
Hash
Provenance
Case association
```

### Pipeline

```text
Collection
    ↓
Normalization
    ↓
Integrity Metadata
    ↓
Provenance
    ↓
Evidence Object
```

### Deliverables

```text
✓ Evidence schema
✓ Serialization
✓ Hashing
✓ Provenance metadata
✓ Integrity verification
✓ Tamper tests
```

### Exit Criteria

Evidence can be stored, retrieved, and integrity-checked.

---

# 11. Phase 8 — Agent

### Objective

Build the endpoint component responsible for authorized forensic collection.

### Components

```text
Agent configuration
Agent identity
Authentication
Capability policy
Runtime execution
Evidence packaging
Transport
Logging
```

### Agent architecture

```text
        Agent
          │
    ┌─────┴─────┐
    │           │
Collector     Policy
    │           │
    └─────┬─────┘
          ↓
       Evidence
          ↓
       Transport
```

### Deliverables

```text
✓ Agent executable
✓ Configuration
✓ Authentication
✓ Collection
✓ Evidence generation
✓ Backend communication
```

### Exit Criteria

An authorized agent can collect supported evidence and submit it securely.

---

# 12. Phase 9 — Backend

### Objective

Create the central investigation backend.

### Components

```text
API
Authentication
Authorization
Case management
Agent management
Evidence ingestion
Evidence storage
Investigation management
```

### Core flow

```text
Agent
  ↓
API
  ↓
Validation
  ↓
Evidence Store
  ↓
Case
```

### Deliverables

```text
✓ Backend service
✓ API contracts
✓ Database schema
✓ Authentication
✓ Authorization
✓ Evidence ingestion
✓ Backend tests
```

### Exit Criteria

The backend can securely receive and store evidence.

---

# 13. Phase 10 — Detection Engine

### Objective

Transform forensic observations into useful investigation findings.

### Components

```text
Rule engine
Indicator evaluation
Finding generation
Severity
Confidence
Evidence references
MITRE mapping
Correlation
```

### Pipeline

```text
Evidence
   ↓
Normalization
   ↓
Detection Rules
   ↓
Indicators
   ↓
Findings
   ↓
Risk
```

### Deliverables

```text
✓ Rule format
✓ Detection engine
✓ Initial rules
✓ Negative tests
✓ Correlation
✓ Finding model
```

### Exit Criteria

Controlled forensic fixtures produce the expected findings.

---

# 14. Phase 11 — Investigation Model

### Objective

Connect evidence and findings into an investigation.

### Components

```text
Case
Host
Evidence
Event
Finding
Relationship
Timeline
Risk
```

### Conceptual graph

```text
Case
 │
 ├── Host
 │    ├── Process
 │    ├── File
 │    ├── Driver
 │    └── Network Event
 │
 ├── Evidence
 │
 ├── Findings
 │
 └── Timeline
```

### Exit Criteria

An investigation can be represented as structured relationships rather than isolated records.

---

# 15. Phase 12 — Dashboard

### Objective

Provide investigators with a usable visualization layer.

### Main areas

```text
Cases
Hosts
Evidence
Timeline
Graph
Findings
Risk
Reports
```

### Dashboard architecture

```text
Browser
   ↓
Frontend
   ↓
API
   ↓
Backend
   ↓
Database
```

### Deliverables

```text
✓ Authentication screen
✓ Case list
✓ Investigation view
✓ Timeline
✓ Graph
✓ Findings
✓ Risk display
✓ Evidence view
```

### Exit Criteria

A complete investigation can be understood through the dashboard without manually querying the database.

---

# 16. Phase 13 — Report Generation

### Objective

Generate reproducible investigation reports.

### Report contents

```text
Case metadata
Host information
Evidence identifiers
Evidence hashes
Timeline
Findings
Risk
Detection results
Provenance
Generation metadata
```

### Deliverables

```text
✓ Report generator
✓ PDF/export format
✓ Integrity metadata
✓ Report tests
```

### Exit Criteria

A complete case can be exported into a structured investigation report.

---

# 17. Phase 14 — Controlled Laboratory

### Objective

Provide reproducible demonstrations of defensive detection capabilities without requiring uncontrolled offensive execution.

### Laboratory design

```text
Synthetic Fixture
      ↓
Forensic Runtime
      ↓
Evidence
      ↓
Detection
      ↓
Finding
      ↓
Dashboard
```

### Example scenarios

```text
LAB-001 Process Hollowing Indicators
LAB-002 Suspicious Driver Indicators
LAB-003 Suspicious Process Relationship
LAB-004 Network Anomaly
LAB-005 File Integrity Anomaly
```

The scenarios should use synthetic or safely captured forensic observations.

### Deliverables

```text
✓ Lab fixtures
✓ Scenario definitions
✓ Expected findings
✓ Reproduction scripts
✓ Documentation
```

### Exit Criteria

A reviewer can reproduce the same investigation result from a clean environment.

---

# 18. Phase 15 — Cross-Platform Support

### Objective

Validate the platform abstraction.

Target platforms:

```text
Windows
Linux
```

### Architecture

```text
             JOCKY
               │
        Common Runtime API
          /           \
         /             \
Windows Adapter     Linux Adapter
```

### Requirements

The same JOCKY semantic operation should produce platform-appropriate evidence.

Example:

```text
process.list();
```

should use:

```text
Windows → Windows implementation
Linux   → Linux implementation
```

while maintaining the common evidence contract.

### Deliverables

```text
✓ Windows adapter
✓ Linux adapter
✓ Contract tests
✓ Platform-specific tests
✓ Documentation
```

---

# 19. Phase 16 — Hardening

### Objective

Treat JOCKY as a security-sensitive system.

### Areas

```text
Input validation
Authentication
Authorization
Capability enforcement
Resource limits
IR validation
Evidence integrity
Transport security
Secret management
Logging
Error handling
```

### Security review

Every interface should be reviewed:

```text
Source → Compiler
Compiler → IR
IR → Runtime
Runtime → Agent
Agent → Backend
Backend → Database
Backend → Frontend
```

### Exit Criteria

No known critical security invariant is untested.

---

# 20. Phase 17 — Performance and Reliability

### Objective

Measure system behavior under realistic workloads.

### Measure

```text
Compilation latency
IR validation latency
Evidence processing
API latency
Detection latency
Database throughput
Report generation
Memory usage
```

### Reliability testing

Include:

```text
Network failure
Backend restart
Database failure
Malformed evidence
Large evidence
Invalid IR
Agent restart
```

---

# 21. Phase 18 — End-to-End Validation

### Objective

Validate the complete system.

Test:

```text
JOCKY Source
     ↓
Compiler
     ↓
IR
     ↓
Agent
     ↓
Forensic Collection
     ↓
Evidence
     ↓
Backend
     ↓
Database
     ↓
Detection
     ↓
Finding
     ↓
Risk
     ↓
Dashboard
     ↓
Report
```

### Exit Criteria

At least one complete investigation can be reproduced from start to finish.

---

# 22. Phase 19 — Documentation Completion

Before final release, verify:

```text
ARCHITECTURE.md
LANGUAGE_SPEC.md
IR_SPEC.md
FORENSICS_SPEC.md
SECURITY_MODEL.md
TEST_PLAN.md
ROADMAP.md
DESIGN.md
STATUS.md
TEAMMATES.md
AGENTS.md
README.md
```

All documents must agree with the actual implementation.

---

# 23. Phase 20 — SIH Demonstration Preparation

### Objective

Turn the implementation into a reproducible demonstration.

### Demo should show

```text
1. Start project
2. Create/select investigation
3. Compile JOCKY program
4. Run authorized forensic analysis
5. Generate evidence
6. Submit evidence
7. Detect simulated indicators
8. Display timeline
9. Display investigation graph
10. Show risk
11. Show evidence integrity
12. Generate report
```

---

# 24. Recommended Demonstration Scenario

Use one primary scenario rather than attempting to demonstrate every capability.

Example:

```text
Investigation:
    LAB-001

Host:
    PC-01

Evidence:
    Process + Memory + File observations

Detection:
    Simulated process hollowing indicators

Result:
    Finding generated

Dashboard:
    Timeline + Graph + Risk

Report:
    Evidence hashes + findings + provenance
```

The scenario should be completely reproducible.

---

# 25. Milestone M0 — Foundation Complete

```text
✓ Repository
✓ Build
✓ Docker
✓ CI
✓ Test framework
✓ Documentation skeleton
```

---

# 26. Milestone M1 — Language Complete

```text
✓ Lexer
✓ Parser
✓ AST
✓ Semantic analysis
✓ Error reporting
```

---

# 27. Milestone M2 — Compiler Complete

```text
✓ IR
✓ IR validation
✓ Compiler
✓ Golden tests
```

---

# 28. Milestone M3 — Safe Runtime Complete

```text
✓ Capability model
✓ Runtime interfaces
✓ Forensic operations
✓ Evidence generation
```

---

# 29. Milestone M4 — Agent Complete

```text
✓ Agent
✓ Authentication
✓ Collection
✓ Evidence transport
```

---

# 30. Milestone M5 — Backend Complete

```text
✓ API
✓ Database
✓ Case management
✓ Evidence ingestion
✓ Authorization
```

---

# 31. Milestone M6 — Detection Complete

```text
✓ Rules
✓ Findings
✓ Correlation
✓ Risk scoring
```

---

# 32. Milestone M7 — Investigation UI Complete

```text
✓ Cases
✓ Evidence
✓ Timeline
✓ Graph
✓ Findings
✓ Risk
```

---

# 33. Milestone M8 — Reporting Complete

```text
✓ Report generation
✓ Evidence references
✓ Integrity information
✓ Reproducible report
```

---

# 34. Milestone M9 — Laboratory Complete

```text
✓ Controlled scenarios
✓ Synthetic fixtures
✓ Expected results
✓ Reproducibility
```

---

# 35. Milestone M10 — Cross-Platform Complete

```text
✓ Windows adapter
✓ Linux adapter
✓ Contract tests
```

---

# 36. Milestone M11 — Security Hardening Complete

```text
✓ Security review
✓ Security regression suite
✓ Resource limits
✓ Authorization tests
✓ Capability tests
✓ IR validation tests
```

---

# 37. Milestone M12 — Final Demonstration Ready

The project is demonstration-ready when:

```text
✓ Clean environment setup documented
✓ Complete E2E flow works
✓ Controlled lab scenario works
✓ Dashboard works
✓ Report generation works
✓ Tests pass
✓ Security boundaries are documented
✓ Known limitations are documented
```

---

# 38. What Must NOT Be Done Prematurely

Do not begin by implementing advanced functionality simply because it appears impressive.

Avoid building:

```text
Complex detection correlation
Advanced UI
Large runtime surface
Platform-specific optimizations
Performance tuning
```

before the foundations are stable.

The dependency order matters.

---

# 39. Critical Dependency Rule

The following dependencies must be respected:

```text
Language
   ↓
Semantic Analysis
   ↓
IR
   ↓
IR Validation
   ↓
Capability System
   ↓
Runtime
```

and:

```text
Runtime
   ↓
Evidence
   ↓
Backend
   ↓
Detection
   ↓
Investigation
   ↓
Dashboard
```

A later component should not invent its own incompatible representation.

---

# 40. Vertical Slice Strategy

After the compiler foundation is stable, development should use vertical slices.

Instead of implementing every possible feature independently:

```text
100% Compiler
100% Runtime
100% Backend
100% UI
```

build one complete path:

```text
JOCKY
 ↓
Compiler
 ↓
One forensic operation
 ↓
Evidence
 ↓
Backend
 ↓
One detection rule
 ↓
Dashboard
 ↓
Report
```

Then expand the system.

This exposes architectural problems much earlier.

---

# 41. First Vertical Slice

Recommended first complete slice:

```text
system.info()
```

Pipeline:

```text
system.info()
     ↓
Lexer
     ↓
Parser
     ↓
Semantic Analysis
     ↓
IR
     ↓
IR Validation
     ↓
Runtime
     ↓
Evidence
     ↓
Backend
     ↓
Case
     ↓
Dashboard
```

Once this works, additional operations can reuse the established interfaces.

---

# 42. Second Vertical Slice

Recommended second slice:

```text
process.list()
```

Pipeline:

```text
process.list()
     ↓
Compiler
     ↓
Capability Check
     ↓
Runtime
     ↓
Process Evidence
     ↓
Detection
     ↓
Timeline
     ↓
Dashboard
```

---

# 43. Third Vertical Slice

Recommended third slice:

```text
file.hash("sample");
```

Pipeline:

```text
file.hash()
     ↓
File Evidence
     ↓
Integrity Metadata
     ↓
Backend
     ↓
Investigation
     ↓
Report
```

---

# 44. Controlled Detection Slice

After the basic slices work:

```text
Synthetic suspicious-process fixture
          ↓
Agent
          ↓
Evidence
          ↓
Detection rule
          ↓
Finding
          ↓
Risk
          ↓
Dashboard
```

This becomes the foundation of the final demonstration.

---

# 45. Definition of a Phase

A phase is not complete merely because the implementation exists.

A phase is complete when:

```text
Implementation
     +
Tests
     +
Documentation
     +
Security Review
     +
Integration Validation
```

are all complete where applicable.

---

# 46. Development Discipline

After every meaningful implementation unit:

```text
Implement
   ↓
Test
   ↓
Review
   ↓
Document
   ↓
Commit
```

Commits should represent meaningful, reviewable changes.

Avoid enormous commits containing unrelated work.

---

# 47. Status Tracking

`docs/STATUS.md` should contain the current state of every roadmap phase.

Example:

```text
Phase 0  Foundation       COMPLETE
Phase 1  Language         IN PROGRESS
Phase 2  Semantics        NOT STARTED
Phase 3  IR               NOT STARTED
...
```

The status document is the current truth.

The roadmap describes the intended future.

---

# 48. Roadmap vs Status

These documents have different responsibilities.

```text
ROADMAP.md
    ↓
Where the project is going

STATUS.md
    ↓
Where the project currently is
```

Do not turn `ROADMAP.md` into a constantly changing progress log.

---

# 49. Final Architecture Goal

The completed system should conceptually look like:

```text
                    ┌───────────────┐
                    │ JOCKY Source  │
                    └───────┬───────┘
                            │
                            ▼
                    ┌───────────────┐
                    │    Compiler   │
                    └───────┬───────┘
                            │
                            ▼
                    ┌───────────────┐
                    │      IR       │
                    └───────┬───────┘
                            │
                     Validation
                            │
                            ▼
                    ┌───────────────┐
                    │     Agent     │
                    └───────┬───────┘
                            │
                            ▼
                    ┌───────────────┐
                    │   Evidence    │
                    └───────┬───────┘
                            │
                            ▼
                    ┌───────────────┐
                    │    Backend    │
                    └───────┬───────┘
                            │
                 ┌──────────┴──────────┐
                 ▼                     ▼
          ┌───────────────┐    ┌───────────────┐
          │   Detection   │    │ Investigation │
          └───────┬───────┘    └───────┬───────┘
                  │                    │
                  └──────────┬─────────┘
                             ▼
                    ┌───────────────┐
                    │   Dashboard   │
                    └───────┬───────┘
                            │
                            ▼
                    ┌───────────────┐
                    │    Report     │
                    └───────────────┘
```

---

# 50. Final Roadmap Principle

JOCKY should not be judged by how many advanced components exist.

It should be judged by whether the entire chain works reliably:

```text
WRITE
  ↓
COMPILE
  ↓
VALIDATE
  ↓
COLLECT
  ↓
PROTECT
  ↓
STORE
  ↓
DETECT
  ↓
INVESTIGATE
  ↓
EXPLAIN
```

The strongest demonstration is therefore not the largest feature set.

It is a **small, complete, reproducible, secure investigation pipeline** that can be expanded without redesigning the foundation.
