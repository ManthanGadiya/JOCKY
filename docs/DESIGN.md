# JOCKY — System Design

**Document:** `docs/DESIGN.md`
**Project:** JOCKY
**Version:** 1.0
**Status:** Engineering Design
**Last Updated:** 2026-08-28

---

# 1. Purpose

This document defines the concrete engineering design decisions for JOCKY.

`ARCHITECTURE.md` describes the system's major components and relationships.

`DESIGN.md` explains:

* how those components are designed internally,
* why particular boundaries exist,
* what contracts they must satisfy,
* which design alternatives are intentionally rejected,
* and how the system should evolve without breaking its security model.

The design must remain consistent with:

```text
docs/ARCHITECTURE.md
docs/LANGUAGE_SPEC.md
docs/IR_SPEC.md
docs/FORENSICS_SPEC.md
docs/SECURITY_MODEL.md
docs/TEST_PLAN.md
docs/ROADMAP.md
```

When these documents disagree, the conflict must be resolved explicitly rather than silently choosing one interpretation.

---

# 2. Core Design Principles

JOCKY follows these principles.

## 2.1 Safety by construction

Security-sensitive behavior must be constrained by architecture rather than relying only on developer discipline.

```text
Source
  ↓
Semantic Validation
  ↓
Capability Analysis
  ↓
IR
  ↓
IR Validation
  ↓
Runtime Policy
  ↓
Execution
```

No single component should be trusted to enforce every security boundary.

---

## 2.2 Explicit capabilities

Every runtime operation must correspond to an explicit capability.

The system must not have an implicit mechanism where a JOCKY program can acquire additional privileges during execution.

---

## 2.3 Separation of concerns

The following responsibilities must remain separate:

```text
Language
Compiler
IR
Runtime
Agent
Evidence
Backend
Detection
Presentation
```

A UI component must not become responsible for forensic collection.

The compiler must not become responsible for evidence storage.

The detection engine must not become responsible for endpoint collection.

---

## 2.4 Evidence-first design

Forensic operations should produce structured evidence rather than arbitrary console output.

Conceptually:

```text
Operation
    ↓
Observation
    ↓
Normalized Evidence
    ↓
Integrity Metadata
    ↓
Backend
```

This makes results machine-readable, reproducible, and suitable for later investigation.

---

## 2.5 Deterministic core

The compiler, IR validation, normalization, and detection logic should be deterministic wherever practical.

Given the same:

```text
source
configuration
fixture
rules
```

the system should produce semantically equivalent results.

---

## 2.6 Platform abstraction

JOCKY language semantics should remain independent from operating-system implementation details.

```text
             JOCKY
               │
               ▼
        Runtime Contract
          /           \
         /             \
Windows Adapter     Linux Adapter
```

Platform-specific implementation belongs below the common runtime interface.

---

# 3. High-Level System

The completed system is designed as:

```text
                         ┌─────────────────┐
                         │  JOCKY Program  │
                         └────────┬────────┘
                                  │
                                  ▼
                         ┌─────────────────┐
                         │    Compiler     │
                         └────────┬────────┘
                                  │
                                  ▼
                         ┌─────────────────┐
                         │       IR        │
                         └────────┬────────┘
                                  │
                           Validation
                                  │
                                  ▼
                         ┌─────────────────┐
                         │      Agent      │
                         └────────┬────────┘
                                  │
                                  ▼
                         ┌─────────────────┐
                         │    Evidence     │
                         └────────┬────────┘
                                  │
                                  ▼
                         ┌─────────────────┐
                         │     Backend     │
                         └────────┬────────┘
                                  │
                 ┌────────────────┴────────────────┐
                 ▼                                 ▼
        ┌─────────────────┐               ┌─────────────────┐
        │ Detection       │               │ Investigation   │
        └────────┬────────┘               └────────┬────────┘
                 │                                 │
                 └────────────────┬────────────────┘
                                  ▼
                         ┌─────────────────┐
                         │    Dashboard    │
                         └────────┬────────┘
                                  │
                                  ▼
                         ┌─────────────────┐
                         │     Report      │
                         └─────────────────┘
```

---

# 4. Repository Design

The repository should separate implementation from documentation and tests.

Recommended structure:

```text
JOCKY/
│
├── docs/
│   ├── ARCHITECTURE.md
│   ├── LANGUAGE_SPEC.md
│   ├── IR_SPEC.md
│   ├── FORENSICS_SPEC.md
│   ├── SECURITY_MODEL.md
│   ├── TEST_PLAN.md
│   ├── ROADMAP.md
│   ├── DESIGN.md
│   ├── STATUS.md
│   ├── TEAMMATES.md
│   └── AGENTS.md
│
├── compiler/
├── runtime/
├── agent/
├── backend/
├── frontend/
├── detection/
├── tests/
├── testdata/
├── examples/
├── scripts/
├── docker/
└── README.md
```

The actual repository may differ, but responsibilities should remain clearly separated.

---

# 5. Language Design

JOCKY is designed as a domain-specific language for authorized forensic investigation.

The language should expose high-level forensic intent.

Example:

```text
system.info();

process.list();

file.hash("sample.exe");

network.connections();
```

The language should describe **what forensic observation is requested**, rather than exposing arbitrary operating-system primitives.

---

# 6. Why a DSL?

A DSL provides several advantages.

### Without a DSL

An investigator would need to understand:

```text
OS APIs
memory structures
process APIs
filesystem APIs
network APIs
serialization
authentication
```

### With JOCKY

The investigator expresses:

```text
process.list();
```

The platform/runtime layer determines how that observation is safely collected.

This creates a stable abstraction between the investigator and operating-system implementation.

---

# 7. Compiler Design

The compiler follows:

```text
Source
  ↓
Lexer
  ↓
Parser
  ↓
AST
  ↓
Semantic Analysis
  ↓
Capability Analysis
  ↓
IR Generation
  ↓
IR Validation
  ↓
Output
```

Each stage has a single responsibility.

---

# 8. Lexer Design

The lexer converts source characters into tokens.

Example:

```text
process.list();
```

Conceptually becomes:

```text
IDENTIFIER(process)
DOT
IDENTIFIER(list)
LPAREN
RPAREN
SEMICOLON
```

The lexer should not perform semantic validation.

---

# 9. Parser Design

The parser converts tokens into an AST.

Example:

```text
process.list();
```

may become conceptually:

```text
CallExpression
└── Function: process.list
```

The parser should not directly invoke runtime operations.

---

# 10. AST Design

The AST represents user intent independently of machine execution.

Example:

```text
Program
└── CallExpression
    ├── Namespace: process
    ├── Operation: list
    └── Arguments: []
```

The AST should contain enough information for semantic validation and IR generation.

---

# 11. Semantic Analysis

Semantic analysis verifies:

```text
Operation exists
Arguments are valid
Types are correct
Capability is known
Operation is permitted
```

Example:

```text
file.hash("sample.exe");
```

is semantically meaningful.

An operation such as:

```text
unknown.operation();
```

must fail before IR generation.

---

# 12. Capability Registry

The capability registry is the central mapping between language operations and security permissions.

Conceptually:

```text
Operation                    Capability
------------------------------------------------
system.info()                system.read
process.list()               process.read
file.hash()                  file.read
network.connections()        network.read
driver.scan()                driver.read
memory.analyze()             memory.read
```

The exact registry must be defined by the implementation and specifications.

---

# 13. Capability Design

Capabilities should be:

```text
Explicit
Minimal
Auditable
Non-escalatable
Versioned
```

The runtime should receive an already validated capability context.

---

# 14. Capability Flow

```text
JOCKY Operation
      ↓
Capability Lookup
      ↓
Requested Capability
      ↓
Policy Evaluation
      ↓
Allowed?
   ↙       ↘
 YES        NO
 ↓           ↓
Runtime    Reject
```

The `NO` path must terminate the requested operation.

---

# 15. IR Design

The IR is the stable contract between the compiler and execution layer.

The compiler should not generate platform-specific runtime implementation details directly.

Conceptually:

```text
JOCKY
  ↓
Semantic Intent
  ↓
IR
  ↓
Runtime
```

---

# 16. Why IR Exists

The IR provides:

```text
Validation boundary
Versioning
Compiler/runtime decoupling
Testing
Debugging
Future compiler evolution
```

It also provides a convenient location to reject malformed or unsupported operations before runtime processing.

---

# 17. IR Versioning

Every IR representation should have an explicit version.

Example:

```text
IR_VERSION = 1
```

Future versions must be explicitly handled.

Unknown versions must not be interpreted as known versions.

---

# 18. IR Validation

Before runtime execution:

```text
IR
 ↓
Syntax/Structure Validation
 ↓
Opcode Validation
 ↓
Operand Validation
 ↓
Capability Validation
 ↓
Resource Validation
 ↓
Approved IR
```

Only approved IR reaches the runtime.

---

# 19. Runtime Design

The runtime translates validated IR into calls to the forensic abstraction layer.

It should not interpret arbitrary native instructions.

Conceptually:

```text
Validated IR
     ↓
Runtime Dispatcher
     ↓
Operation Handler
     ↓
Platform Adapter
     ↓
Evidence
```

---

# 20. Runtime Dispatcher

The dispatcher maps known operations to registered handlers.

Example:

```text
PROCESS_LIST
      ↓
ProcessListHandler
      ↓
Platform Process Adapter
```

Unknown operations must be rejected.

---

# 21. Runtime Registry

Runtime operations should be explicitly registered.

Conceptually:

```text
Operation Registry

system.info
process.list
file.hash
file.analyze
network.connections
driver.scan
memory.analyze
```

An operation not present in the registry cannot execute.

---

# 22. Forensic Adapter Design

Platform-specific behavior belongs in adapters.

Example:

```text
IProcessProvider
      │
      ├── WindowsProcessProvider
      │
      └── LinuxProcessProvider
```

The runtime interacts with:

```text
IProcessProvider
```

rather than directly depending on Windows or Linux APIs.

---

# 23. Common Interface Contract

A platform adapter should return a common representation.

Example:

```text
Process {
    pid
    parent_pid
    name
    executable
}
```

Platform-specific metadata can be represented as optional fields where necessary.

---

# 24. Evidence Model

Evidence is a first-class object.

Conceptually:

```text
Evidence {
    id
    case_id
    host_id
    type
    timestamp
    source
    content
    hash
    provenance
}
```

The exact schema must follow `FORENSICS_SPEC.md`.

---

# 25. Evidence Normalization

Raw platform observations should not be passed directly to detection rules.

Instead:

```text
Raw Observation
      ↓
Platform Adapter
      ↓
Normalizer
      ↓
Canonical Evidence
```

This prevents detection logic from becoming platform-specific unnecessarily.

---

# 26. Evidence Integrity

Evidence should have integrity metadata.

Conceptually:

```text
Evidence
   ↓
Canonical Representation
   ↓
Cryptographic Hash
   ↓
Integrity Metadata
```

When evidence is retrieved, integrity can be verified against the recorded value.

---

# 27. Provenance

Every evidence object should preserve its origin.

At minimum, where applicable:

```text
Collector
Agent
Host
Timestamp
Case
Collection context
```

Provenance must not be silently discarded during normalization.

---

# 28. Agent Design

The agent is the endpoint-side component.

Responsibilities:

```text
Identity
Authentication
Policy enforcement
IR execution
Collection
Normalization
Evidence packaging
Transport
Logging
```

The agent should not contain investigation UI logic.

---

# 29. Agent Lifecycle

Conceptually:

```text
START
  ↓
Load Configuration
  ↓
Initialize Identity
  ↓
Authenticate
  ↓
Load Policy
  ↓
Receive/Load Approved Work
  ↓
Validate
  ↓
Collect
  ↓
Create Evidence
  ↓
Transmit
  ↓
Audit
  ↓
IDLE / STOP
```

---

# 30. Backend Design

The backend is the central system of record.

Responsibilities:

```text
Authentication
Authorization
Case management
Agent management
Evidence ingestion
Evidence storage
Detection orchestration
Investigation state
Report generation
```

---

# 31. API Boundary

The backend API should expose explicit resources.

Conceptual resources:

```text
/cases
/agents
/evidence
/findings
/timeline
/reports
```

Exact routes must be defined by implementation.

---

# 32. Authentication and Authorization

Authentication answers:

> Who are you?

Authorization answers:

> What are you allowed to do?

These must remain separate concepts.

Example:

```text
Authenticated Agent
        ↓
Authorization Policy
        ↓
Can submit evidence?
```

Authentication alone must never imply unrestricted authorization.

---

# 33. Database Design

The database should represent relationships explicitly.

Conceptually:

```text
Case
 │
 ├── Host
 │
 ├── Evidence
 │
 ├── Findings
 │
 ├── Timeline Events
 │
 └── Reports
```

Foreign keys and integrity constraints should be used where appropriate.

---

# 34. Detection Engine Design

The detection engine consumes normalized evidence.

```text
Evidence
   ↓
Rule Evaluation
   ↓
Indicator
   ↓
Finding
   ↓
Severity / Confidence
```

Detection rules should not directly access operating-system APIs.

---

# 35. Rule Design

Rules should be declarative where practical.

Conceptually:

```text
Rule
{
    id
    name
    description
    conditions
    severity
    confidence
    references
}
```

The exact schema belongs in the detection implementation/specification.

---

# 36. Detection and Collection Separation

Collection answers:

> What happened?

Detection answers:

> Is this observation suspicious according to a known rule?

Keeping these separate allows the same evidence to be evaluated by multiple rules.

---

# 37. Correlation

Correlation combines related observations.

Example:

```text
Process Observation
        +
Memory Observation
        +
Module Observation
        ↓
Correlated Finding
```

The correlated finding must retain references to its source evidence.

---

# 38. Risk Scoring

Risk should be calculated from findings according to an explicit policy.

Conceptually:

```text
Findings
   ↓
Severity
+
Confidence
+
Correlation
   ↓
Risk Policy
   ↓
Risk Score
```

The dashboard should consume the backend's risk result rather than independently inventing a different score.

---

# 39. Investigation Graph

The graph is a representation of relationships.

Example:

```text
Host
 │
 ├── Process
 │     └── File
 │
 ├── Driver
 │
 └── Network Event
```

The graph should be derived from canonical investigation entities.

It should not become an independent source of truth.

---

# 40. Timeline Design

Timeline events should contain:

```text
timestamp
event type
source
related entity
evidence reference
```

Events should be ordered consistently.

Where timestamps have different precision or reliability, that uncertainty should be preserved rather than hidden.

---

# 41. Dashboard Design

The frontend is a presentation layer.

It should consume:

```text
Cases
Evidence
Findings
Timeline
Graph
Risk
Reports
```

The frontend should not directly access the database.

---

# 42. Dashboard Responsibilities

The dashboard should:

```text
Display investigations
Visualize evidence
Visualize relationships
Display findings
Display risk
Provide report access
Show system state
```

It should not perform privileged forensic collection itself.

---

# 43. Optional JOCKY Editor

A future dashboard may include a JOCKY editor.

If implemented:

```text
Browser
   ↓
Editor
   ↓
Backend API
   ↓
Compiler Service
   ↓
Validated IR
```

The browser must not execute arbitrary compiler/runtime operations directly.

The same compiler validation and security policy must apply whether source originates from an IDE or dashboard editor.

---

# 44. Controlled Laboratory Design

The laboratory provides reproducible defensive scenarios.

The preferred design is:

```text
Synthetic Evidence
       ↓
JOCKY Analysis
       ↓
Evidence Pipeline
       ↓
Detection
       ↓
Finding
```

The laboratory should not require implementation of real-world offensive techniques merely to demonstrate detection.

---

# 45. Scenario Packaging

Each scenario should contain:

```text
scenario metadata
input fixtures
expected observations
expected findings
expected risk
expected timeline
```

Example:

```text
LAB-001/
├── scenario.json
├── evidence.json
└── expected.json
```

---

# 46. Reproducibility

A scenario must be reproducible.

Given:

```text
same fixture
same rules
same configuration
same software version
```

the expected investigation result should remain stable unless the specification intentionally changes.

---

# 47. Docker Design

Docker should provide reproducible development and demonstration environments.

Conceptually:

```text
                    Docker Network
                          │
        ┌─────────────────┼─────────────────┐
        │                 │                 │
    Compiler           Backend          Database
        │                 │
        │              Detection
        │                 │
        └────────────── Frontend
```

The exact service structure must follow the repository configuration.

---

# 48. Configuration Design

Configuration should be externalized.

Avoid hard-coding:

```text
credentials
URLs
ports
database passwords
environment-specific settings
```

Use environment-specific configuration where appropriate.

---

# 49. Secret Management

Secrets must never be committed to the repository.

Development may use:

```text
.env
```

or equivalent mechanisms, but secret-containing files must be excluded from version control.

Production secret management should be stronger than local development configuration.

---

# 50. Logging Design

Each major subsystem should produce structured logs.

Useful fields include:

```text
timestamp
component
severity
event
request/correlation ID
case ID
agent ID
```

Logs must avoid exposing credentials or sensitive secret material.

---

# 51. Error Handling

Errors should be explicit and typed where practical.

Conceptual categories:

```text
PARSE_ERROR
SEMANTIC_ERROR
IR_ERROR
CAPABILITY_DENIED
AUTHENTICATION_ERROR
AUTHORIZATION_ERROR
COLLECTION_ERROR
EVIDENCE_ERROR
TRANSPORT_ERROR
STORAGE_ERROR
DETECTION_ERROR
```

Errors should not cause silent fallback into less-restricted behavior.

---

# 52. Fail-Closed Security

Security-sensitive failures should fail closed.

Example:

```text
Capability unknown
      ↓
REJECT
```

not:

```text
Capability unknown
      ↓
Assume allowed
```

Likewise:

```text
IR unknown
      ↓
REJECT
```

---

# 53. Resource Limits

The system should define limits for:

```text
Program size
IR size
Instruction count
Evidence size
File analysis size
Memory usage
Request size
Concurrency
```

The exact limits should be configuration-driven where appropriate.

---

# 54. No Arbitrary Execution Boundary

JOCKY is intentionally not designed as a general-purpose command execution language.

The runtime should expose only explicitly registered operations.

Therefore, the architecture must not contain a generic:

```text
execute(command)
```

style escape hatch.

---

# 55. No Dynamic Capability Escalation

A running JOCKY program must not be able to modify its own capabilities.

Conceptually:

```text
Initial Policy
      ↓
Validated Execution
      ↓
Same Policy
```

not:

```text
Initial Policy
      ↓
Program changes policy
      ↓
Expanded privileges
```

---

# 56. Compiler/Runtime Compatibility

The compiler and runtime must share explicit compatibility information.

Conceptually:

```text
Compiler
   ↓
IR Version 1
   ↓
Runtime supports Version 1
```

If incompatible:

```text
IR Version 2
   ↓
Runtime supports 1
   ↓
REJECT
```

---

# 57. API Versioning

Backend APIs should be versioned when breaking changes are introduced.

Clients should not silently interpret incompatible responses.

---

# 58. Schema Evolution

Database and evidence schema changes should use migrations.

Never modify the schema manually in a way that bypasses the migration history.

---

# 59. Testing Architecture

Testing should mirror system boundaries.

```text
Compiler
   ↓
Compiler Tests

IR
   ↓
IR Tests

Runtime
   ↓
Runtime Tests

Agent
   ↓
Agent Tests

Backend
   ↓
API Tests

Detection
   ↓
Rule Tests

Complete System
   ↓
E2E Tests
```

---

# 60. Design for Testability

Components should expose interfaces that allow controlled test doubles.

Example:

```text
IProcessProvider
IFileProvider
INetworkProvider
IEvidenceStore
ITransport
```

Tests can then use deterministic fixtures rather than depending on the host machine.

---

# 61. Production vs Laboratory

The system should clearly distinguish:

```text
Production/Authorized Collection
```

from:

```text
Controlled Laboratory
```

Laboratory fixtures should never accidentally be interpreted as live endpoint evidence without an explicit indication.

---

# 62. Security Boundaries

The primary boundaries are:

```text
┌───────────────────────────────┐
│ Untrusted JOCKY Source        │
└───────────────┬───────────────┘
                ↓
         Compiler Boundary
                ↓
┌───────────────────────────────┐
│ Validated IR                  │
└───────────────┬───────────────┘
                ↓
         Runtime Boundary
                ↓
┌───────────────────────────────┐
│ Canonical Evidence            │
└───────────────┬───────────────┘
                ↓
         Network/API Boundary
                ↓
┌───────────────────────────────┐
│ Backend                       │
└───────────────────────────────┘
```

Each boundary validates incoming data.

---

# 63. Threat-Oriented Design

The design assumes inputs may be malformed or intentionally hostile.

Potential inputs include:

```text
malformed source
malformed IR
oversized evidence
invalid API requests
unauthorized agents
tampered evidence
unexpected platform data
```

The system should treat all external input as untrusted until validated.

---

# 64. Security Design Rule

Never rely on:

```text
"The compiler already checked it."
```

as the only runtime security guarantee.

The runtime must independently validate the assumptions necessary for safe execution.

Similarly, the backend must validate data received from agents.

---

# 65. Data Flow Security

The intended flow is:

```text
Untrusted Input
      ↓
Validation
      ↓
Canonical Representation
      ↓
Policy
      ↓
Processing
```

not:

```text
Untrusted Input
      ↓
Processing
      ↓
Validation
```

---

# 66. Dependency Strategy

Dependencies should be:

```text
Minimal
Version-pinned where appropriate
Auditable
Documented
Regularly reviewed
```

A dependency should not be introduced merely because it saves a few lines of code.

---

# 67. Build Strategy

The project should support reproducible builds as far as practical.

Build configuration should define:

```text
compiler version
language standard
dependencies
build flags
IR version
runtime version
```

---

# 68. Development Environment

Docker provides the primary reproducible development environment.

Developers may use native tools, but the project should maintain one canonical supported build path.

For example:

```text
Windows Developer
      ↓
Docker / WSL
      ↓
Canonical Linux Build Environment
```

while native Windows builds remain separately validated where required.

---

# 69. Windows/Linux Compatibility

Compatibility should exist at the semantic layer.

Example:

```text
JOCKY:
process.list();
```

Windows:

```text
Windows Process Adapter
```

Linux:

```text
Linux Process Adapter
```

Both produce the common evidence model.

---

# 70. What Must Remain Platform-Specific

The following may remain platform-specific:

```text
OS API calls
filesystem details
process enumeration mechanisms
driver metadata sources
memory acquisition mechanisms
platform-specific metadata
```

These details must not leak unnecessarily into JOCKY language semantics.

---

# 71. Extensibility

Adding a new forensic operation should follow:

```text
Define language operation
        ↓
Define capability
        ↓
Define IR representation
        ↓
Define runtime handler
        ↓
Define evidence schema
        ↓
Implement platform adapters
        ↓
Add tests
        ↓
Add documentation
```

A new operation should not bypass this chain.

---

# 72. Adding a New Detection Rule

Recommended flow:

```text
Define detection requirement
        ↓
Define evidence inputs
        ↓
Implement rule
        ↓
Create positive fixture
        ↓
Create negative fixture
        ↓
Test severity/confidence
        ↓
Document rule
```

---

# 73. Adding a New Platform

A new platform should implement the common runtime contracts.

```text
Common Interface
      ↓
New Platform Adapter
      ↓
Contract Tests
      ↓
Platform Tests
      ↓
Integration Tests
```

The JOCKY language should not need to change merely because a new operating system is supported.

---

# 74. Backward Compatibility

Compatibility should be considered independently at:

```text
Language level
IR level
Evidence level
API level
Database level
```

Breaking changes should be versioned and documented.

---

# 75. Observability

The system should allow developers and investigators to understand:

```text
What operation ran?
Which capability was required?
Which agent executed it?
What evidence was generated?
Which detection rule matched?
Why was a finding created?
How was risk calculated?
```

This is essential for debugging and trustworthy investigations.

---

# 76. Auditability

Security-sensitive actions should generate audit events where required.

Examples:

```text
Agent registration
Policy changes
Evidence submission
Evidence access
Case modification
Report generation
Capability denial
Authentication failure
```

---

# 77. User Experience Principle

The system should expose complexity progressively.

An investigator should primarily see:

```text
Case
Evidence
Finding
Timeline
Graph
Risk
Report
```

while developers can inspect:

```text
AST
IR
capabilities
runtime logs
adapter diagnostics
```

---

# 78. Debugging Modes

Development builds may expose additional diagnostics.

Examples:

```text
AST dump
IR dump
capability trace
runtime trace
evidence normalization trace
```

Production behavior should not expose sensitive internal information unnecessarily.

---

# 79. Performance Design

Performance optimization should occur only after measuring the bottleneck.

Priority should be:

```text
Correctness
Security
Determinism
Maintainability
Performance
```

Performance must not justify bypassing validation or security boundaries.

---

# 80. Failure Recovery

Subsystem failures should be isolated where possible.

Example:

```text
Detection failure
      ↓
Investigation remains available
```

rather than:

```text
Detection failure
      ↓
Entire backend becomes unusable
```

The exact recovery behavior depends on subsystem criticality.

---

# 81. Graceful Degradation

When an optional feature fails, the system should communicate the limitation explicitly.

Example:

```text
Memory analysis unavailable on this platform.
```

It must not fabricate evidence.

---

# 82. Data Quality Principle

The system must distinguish:

```text
Observed
Inferred
Correlated
Unknown
Unavailable
```

A detection engine should not represent an inference as direct observation.

---

# 83. Report Design

Reports should be generated from canonical backend data.

```text
Database
   ↓
Investigation Model
   ↓
Report Generator
   ↓
PDF/Export
```

The report generator should not independently recollect endpoint information.

---

# 84. Report Reproducibility

A report should reference:

```text
case
evidence IDs
finding IDs
hashes
generation metadata
```

This allows investigators to trace conclusions back to source evidence.

---

# 85. Design Review Checklist

Before accepting a new component, ask:

```text
Does it have one clear responsibility?

Does it cross an existing security boundary?

Does it validate its input?

Does it have a defined interface?

Can it be tested independently?

Does it preserve provenance?

Does it introduce arbitrary execution capability?

Does it work with the existing IR/evidence contracts?

Does it require documentation changes?

Does it require security tests?
```

---

# 86. Feature Review Checklist

Every feature should answer:

```text
What problem does this solve?

Where does it belong?

What input does it accept?

What output does it produce?

What capability does it require?

What can go wrong?

How is failure represented?

How is it tested?

How is it audited?

How does it affect Windows/Linux?

```

---

# 87. Deliberately Rejected Design Choices

The following approaches should not be introduced merely for convenience:

```text
Arbitrary shell execution
Unrestricted native function invocation
Implicit privilege escalation
Client-side security decisions
Direct frontend-to-database access
Unvalidated IR execution
Untracked evidence modification
Platform-specific semantics inside the language
```

These choices conflict with the project's security and maintainability goals.

---

# 88. Evolution Strategy

JOCKY should evolve through additive changes wherever possible.

Preferred:

```text
Existing Interface
      +
New Capability
      +
Backward-Compatible Version
```

rather than repeatedly redesigning the entire pipeline.

---

# 89. Documentation as a Contract

Documentation is not secondary to implementation.

The specifications define expected behavior.

If implementation intentionally diverges:

```text
Implementation
      ↓
Review
      ↓
Specification Update
      ↓
Tests Updated
```

Do not silently allow documentation and implementation to drift apart.

---

# 90. Final Design

The essential JOCKY design is:

```text
                 JOCKY LANGUAGE
                       │
                       ▼
                 SAFE COMPILER
                       │
                       ▼
                    VALID IR
                       │
                       ▼
              CAPABILITY POLICY
                       │
                       ▼
                    AGENT
                       │
                       ▼
             FORENSIC ADAPTERS
                       │
                       ▼
              CANONICAL EVIDENCE
                       │
                       ▼
                   BACKEND
                       │
             ┌─────────┴─────────┐
             ▼                   ▼
         DETECTION          INVESTIGATION
             │                   │
             └─────────┬─────────┘
                       ▼
                   DASHBOARD
                       │
                       ▼
                    REPORT
```

The design intentionally separates:

```text
Intent
Execution
Evidence
Detection
Presentation
```

This separation is the foundation that allows JOCKY to evolve from a prototype into a maintainable forensic platform without turning the language, endpoint agent, or dashboard into an unrestricted execution mechanism.

---

# 91. Engineering North Star

When a design decision is unclear, prefer the option that maximizes:

```text
Explicitness
+
Least Privilege
+
Testability
+
Determinism
+
Auditability
+
Platform Independence
```

while minimizing:

```text
Implicit Behavior
+
Privilege
+
Coupling
+
Unvalidated Input
+
Hidden State
```

The system should remain understandable enough that another engineer can trace:

```text
JOCKY statement
      ↓
AST
      ↓
IR
      ↓
Capability
      ↓
Runtime operation
      ↓
Evidence
      ↓
Detection
      ↓
Finding
      ↓
Report
```

without relying on undocumented behavior.
