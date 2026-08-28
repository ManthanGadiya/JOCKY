# JOCKY — System Architecture

**Document:** `docs/ARCHITECHTURE.md`
**Project:** JOCKY
**Version:** 1.0
**Status:** Architecture Definition
**Last Updated:** 2026-08-28

---

## 1. Overview

JOCKY is a domain-specific forensic investigation platform designed to allow an investigator to describe security investigations using a dedicated language, execute those investigations through authorized endpoint agents, collect and normalize forensic evidence, analyze that evidence using detection and correlation engines, and present the resulting investigation through a centralized dashboard.

The system is designed around the following principle:

> **Write an investigation once, execute it across supported environments, normalize the resulting evidence, correlate observations, and produce an explainable forensic result.**

JOCKY separates the investigation language from operating-system-specific collection mechanisms.

The high-level architecture is:

```text
                         ┌─────────────────────────┐
                         │       Investigator      │
                         │                         │
                         │  Browser / JOCKY IDE    │
                         └────────────┬────────────┘
                                      │
                                      │ HTTPS / API
                                      ▼
                         ┌─────────────────────────┐
                         │      JOCKY Dashboard    │
                         │        (React)          │
                         └────────────┬────────────┘
                                      │
                                      ▼
                         ┌─────────────────────────┐
                         │       API Gateway       │
                         │         (Nginx)         │
                         └────────────┬────────────┘
                                      │
                                      ▼
                  ┌───────────────────────────────────────┐
                  │             JOCKY Backend              │
                  │              (FastAPI)                 │
                  └───────────────┬───────────────────────┘
                                  │
              ┌───────────────────┼───────────────────┐
              │                   │                   │
              ▼                   ▼                   ▼
        PostgreSQL              Redis               MinIO
        Case metadata         Jobs / Queue       Evidence / Artifacts
              │                   │                   │
              └───────────────────┼───────────────────┘
                                  │
                                  ▼
                       ┌─────────────────────┐
                       │ Investigation       │
                       │ Controller          │
                       └──────────┬──────────┘
                                  │
                       Investigation Plan
                                  │
                    ┌─────────────┴─────────────┐
                    │                           │
                    ▼                           ▼
          ┌──────────────────┐        ┌──────────────────┐
          │ Windows Agent    │        │ Linux Agent      │
          │                  │        │                  │
          │ Windows Provider │        │ Linux Provider   │
          └────────┬─────────┘        └────────┬─────────┘
                   │                           │
                   └────────────┬──────────────┘
                                │
                                ▼
                       Normalized Evidence
                                │
                                ▼
                     ┌─────────────────────┐
                     │ Detection Engine    │
                     │                     │
                     │ YARA / Sigma /      │
                     │ JOCKY Detection     │
                     └──────────┬──────────┘
                                │
                                ▼
                     ┌─────────────────────┐
                     │ Correlation Engine  │
                     │                     │
                     │ Timeline / Graph /  │
                     │ Risk Analysis       │
                     └──────────┬──────────┘
                                │
                                ▼
                       Findings / Incidents
                                │
                                ▼
                         JOCKY Dashboard
                                │
                         ┌──────┴──────┐
                         ▼             ▼
                      Graph         Report
                     Timeline        PDF
```

---

# 2. Architectural Principles

JOCKY follows several architectural principles.

## 2.1 Separation of Concerns

Each major responsibility belongs to a separate subsystem.

```text
Language
   ↓
Compiler
   ↓
Runtime
   ↓
Agent
   ↓
Evidence
   ↓
Detection
   ↓
Correlation
   ↓
Presentation
```

A change to the dashboard should not require changes to the JOCKY language.

Likewise, adding a Linux collection provider should not require changing the language syntax.

---

## 2.2 Cross-Platform Abstraction

JOCKY programs describe **what should be investigated**, not how a particular operating system performs the collection.

For example:

```text
process.list();
```

represents the investigation operation.

The runtime resolves that operation to an appropriate platform provider.

```text
                 process.list()
                       │
              ┌────────┴────────┐
              ▼                 ▼
          Windows             Linux
          Provider            Provider
              │                 │
          Windows APIs       Linux APIs
              │                 │
              └────────┬────────┘
                       ▼
                Common Evidence
                    Schema
```

This allows a single investigation to be expressed independently of the endpoint operating system.

---

## 2.3 Evidence First

The system should preserve the distinction between:

```text
Observation
    ↓
Indicator
    ↓
Finding
    ↓
Incident
```

Raw observations must not be silently replaced by conclusions.

For example:

```text
Raw process observation
        ↓
Process relationship analysis
        ↓
Suspicious relationship indicator
        ↓
Detection rule
        ↓
Finding
```

This makes findings explainable and auditable.

---

## 2.4 Reproducibility

Investigations should be reproducible.

An investigation should retain:

* JOCKY source
* compiler version
* runtime version
* investigation identifier
* target host identifiers
* evidence identifiers
* evidence hashes
* detection-rule versions
* timestamps
* generated findings
* report metadata

The objective is to allow an investigator to understand how a result was produced.

---

## 2.5 Safe Research Architecture

JOCKY may model behaviors associated with advanced security incidents, but the platform is designed around **authorized forensic collection and controlled/synthetic laboratory evidence**.

The architecture must not depend on:

* disabling endpoint security controls
* exploiting vulnerable kernel drivers
* covert command-and-control mechanisms
* credential theft
* real process-injection payloads
* security-control bypass mechanisms

When such behaviors are required for demonstrations, they are represented through controlled laboratory evidence and detection scenarios rather than implemented as operational offensive capabilities.

---

# 3. Major Components

JOCKY consists of the following major components.

```text
1. JOCKY Language
2. JOCKY Compiler
3. JOCKY IR
4. JOCKY Runtime
5. Endpoint Agent
6. Investigation Controller
7. Evidence Store
8. Backend API
9. Detection Engine
10. Correlation Engine
11. Dashboard
12. Report Generator
13. Controlled Laboratory
```

---

# 4. JOCKY Language

The JOCKY language is the investigator-facing domain-specific language.

Its purpose is to describe forensic operations at a higher level than operating-system APIs.

Example:

```text
system.info();

process.list();

network.connections();

file.hash("/evidence/sample");

report.generate();
```

The language should eventually support:

* declarations
* variables
* expressions
* function calls
* control flow
* investigation blocks
* evidence operations
* filtering
* correlation
* reporting

The language specification is defined separately in:

```text
docs/LANGUAGE_SPEC.md
```

---

# 5. JOCKY Compiler

The compiler converts JOCKY source code into an executable investigation representation.

The intended compiler pipeline is:

```text
JOCKY Source
     │
     ▼
Lexer
     │
     ▼
Parser
     │
     ▼
AST
     │
     ▼
Semantic Analysis
     │
     ▼
JOCKY IR
     │
     ▼
LLVM IR / Backend
     │
     ▼
Runtime-compatible Output
```

### 5.1 Lexer

The lexer converts source text into tokens.

Example:

```text
process.list();
```

may become conceptually:

```text
IDENTIFIER(process)
DOT
IDENTIFIER(list)
LPAREN
RPAREN
SEMICOLON
```

---

### 5.2 Parser

The parser converts the token stream into a structured representation of the program.

The parser is responsible for syntactic correctness.

For example:

```text
process.list();
```

is valid if supported by the grammar.

An invalid statement should produce an actionable compiler error.

---

### 5.3 AST

The Abstract Syntax Tree represents the structure of the JOCKY program.

Example:

```text
CallExpression
├── Object: process
├── Method: list
└── Arguments: []
```

The AST provides a structured representation that later compiler stages can consume.

---

### 5.4 Semantic Analysis

Semantic analysis validates meaning rather than merely syntax.

Examples include:

* unknown operations
* invalid arguments
* incompatible types
* invalid variable references
* unsupported operations
* invalid investigation constructs

---

### 5.5 JOCKY IR

JOCKY IR represents an investigation independently of the final execution backend.

Example:

```text
SYSTEM_INFO
PROCESS_LIST
NETWORK_CONNECTIONS
FILE_HASH
REPORT_GENERATE
```

The IR provides a stable boundary between the language and runtime.

---

# 6. Runtime

The JOCKY runtime provides the implementation of investigation operations.

The compiler should not need to know how Windows or Linux internally obtains a particular observation.

Instead:

```text
JOCKY Operation
      ↓
Runtime API
      ↓
Platform Provider
      ↓
Operating System
```

For example:

```text
process.list()
```

becomes:

```text
Runtime.processList()
```

and the runtime dispatches to the appropriate provider.

---

# 7. Endpoint Agent

The JOCKY agent executes authorized investigation tasks on endpoints.

The agent is responsible for:

1. receiving an investigation task
2. validating the task
3. executing supported collection operations
4. normalizing observations
5. calculating evidence metadata
6. transmitting evidence securely
7. reporting execution status

The agent should not contain investigation-specific detection logic whenever that logic can be centralized.

Conceptually:

```text
Controller
     │
     ▼
Investigation Task
     │
     ▼
Agent
     │
     ├── System Provider
     ├── Process Provider
     ├── File Provider
     ├── Network Provider
     └── Other Providers
     │
     ▼
Normalized Evidence
```

---

# 8. Platform Providers

JOCKY uses platform-specific providers behind a common interface.

```text
                 Provider Interface
                       │
             ┌─────────┴─────────┐
             ▼                   ▼
     Windows Provider       Linux Provider
             │                   │
      Windows mechanisms     Linux mechanisms
```

This design allows additional platforms to be introduced without changing the JOCKY language.

Potential future providers may include:

```text
macOS Provider
Cloud Provider
Container Provider
```

---

# 9. Evidence Model

All collected observations should be converted into a common evidence representation.

Conceptually:

```text
Evidence
├── Evidence ID
├── Case ID
├── Host ID
├── Timestamp
├── Evidence Type
├── Source
├── Platform
├── Data
├── Integrity Metadata
└── Collection Metadata
```

Possible evidence types include:

```text
PROCESS
FILE
NETWORK
MODULE
DRIVER
MEMORY
SYSTEM
TIMELINE
```

The detailed schema belongs in:

```text
docs/FORENSICS_SPEC.md
```

---

# 10. Backend API

The backend provides the central control plane.

It is responsible for:

* authentication
* case management
* investigation management
* agent registration
* task management
* evidence ingestion
* evidence retrieval
* finding management
* report generation
* dashboard APIs

Conceptually:

```text
Dashboard
    │
    ▼
Nginx
    │
    ▼
FastAPI
    │
    ├── Cases
    ├── Investigations
    ├── Agents
    ├── Evidence
    ├── Findings
    └── Reports
```

---

# 11. Data Storage

JOCKY separates structured metadata from large evidence artifacts.

## PostgreSQL

Stores structured information such as:

```text
Cases
Investigations
Hosts
Agents
Evidence metadata
Findings
Rules
Reports
```

## MinIO

Stores larger evidence artifacts such as:

```text
Memory images
Collected files
JSON evidence
PCAP-like laboratory artifacts
Generated reports
```

## Redis

Provides infrastructure for:

```text
Job queues
Task coordination
Caching
Transient state
```

---

# 12. Investigation Controller

The controller coordinates execution of investigations.

Its responsibility is to translate an investigation into endpoint tasks.

```text
JOCKY Investigation
        │
        ▼
 Investigation Plan
        │
        ├─────────────┐
        ▼             ▼
     PC-01          PC-02
    Windows          Linux
        │             │
        ▼             ▼
      Agent         Agent
```

The controller should track:

```text
Queued
Running
Completed
Failed
Partial
Cancelled
```

for each investigation.

---

# 13. Detection Engine

The detection engine converts evidence into indicators and findings.

The conceptual pipeline is:

```text
Evidence
   ↓
Normalization
   ↓
Feature Extraction
   ↓
Detection Rules
   ↓
Indicators
   ↓
Findings
```

Possible detection technologies include:

* YARA
* Sigma
* JOCKY-native detection rules
* structured behavioral rules

Detection rules should produce explainable results.

A finding should contain enough information to answer:

```text
What was detected?
Why was it detected?
Which evidence supports it?
Which rule produced it?
How confident is the detection?
```

---

# 14. Correlation Engine

Detection identifies individual indicators.

Correlation connects related indicators.

Example:

```text
File Event
     │
     ▼
Process Event
     │
     ▼
Memory Indicator
     │
     ▼
Network Event
     │
     ▼
Driver Event
```

The correlation engine may construct:

### Timeline

```text
10:01  File event
10:02  Process event
10:03  Memory indicator
10:04  Network event
10:05  Driver event
```

### Investigation Graph

```text
File
 │
 ▼
Process
 ├────────► Memory
 │
 └────────► Network
 │
 └────────► Driver
```

The graph represents relationships between evidence and findings.

---

# 15. Risk Engine

The risk engine converts correlated findings into an overall investigation risk assessment.

Conceptually:

```text
Individual Findings
        │
        ▼
Severity
Confidence
Correlation
Evidence Quality
        │
        ▼
Risk Calculation
        │
        ▼
Overall Risk
```

The scoring algorithm must be documented and deterministic.

Risk must not be treated as proof of malicious activity.

A high risk score means:

> The available evidence warrants increased investigative attention.

It does not automatically mean:

> The endpoint is compromised.

---

# 16. Dashboard

The dashboard is the primary investigator interface.

The final dashboard should provide:

```text
┌───────────────────────────────────────────┐
│ JOCKY                                     │
├───────────┬───────────────────────────────┤
│ Cases     │ Investigation                 │
│           │                               │
│ PC-01     │ Graph                         │
│ PC-02     │                               │
│           │ Timeline                      │
│           │                               │
│           │ Findings                      │
│           │                               │
│           │ Risk                           │
└───────────┴───────────────────────────────┘
```

The dashboard should eventually provide:

* JOCKY editor
* compilation interface
* investigation execution
* case management
* host management
* evidence explorer
* timeline
* investigation graph
* findings
* risk visualization
* report generation

---

# 17. JOCKY Web Editor

The web editor provides an optional higher-level interface for investigators.

Instead of manually compiling through a terminal:

```text
jockyc investigation.jocky
```

the investigator can write:

```text
process.list();
network.connections();
```

inside the browser.

The flow becomes:

```text
Browser Editor
      │
      ▼
Compile API
      │
      ▼
JOCKY Compiler
      │
      ▼
Compilation Result
      │
      ▼
Run Investigation
```

The command-line compiler remains useful for developers and automated environments.

---

# 18. Controlled Laboratory

JOCKY includes a controlled laboratory for reproducible demonstrations and testing.

The laboratory provides synthetic or otherwise authorized evidence representing investigation scenarios.

Example:

```text
Controlled Scenario
        │
        ▼
Synthetic Evidence
        │
        ▼
Agent / Ingestion
        │
        ▼
Detection Engine
        │
        ▼
Correlation Engine
        │
        ▼
Dashboard
```

Possible laboratory scenarios include:

```text
Process Relationship Anomaly
File Activity
Network Activity
Suspicious Module Observation
Driver Anomaly
Combined Incident
```

The purpose of the laboratory is to test whether JOCKY can:

1. ingest evidence
2. detect indicators
3. correlate events
4. calculate risk
5. explain findings
6. generate reports

without requiring operational offensive behavior.

---

# 19. Report Generation

The report generator converts an investigation into a structured forensic report.

A report should contain:

```text
Case Information
Investigation Information
Target Hosts
Collection Information
Evidence Summary
Timeline
Findings
Correlation Graph
Risk Assessment
Detection Rules
Evidence Integrity
MITRE Mapping
Conclusions
```

Reports should retain references to the evidence supporting each significant conclusion.

---

# 20. End-to-End Data Flow

The complete system flow is:

```text
                    Investigator
                         │
                         ▼
                  JOCKY Web Editor
                         │
                         ▼
                  JOCKY Compiler
                         │
              ┌──────────┴──────────┐
              ▼                     ▼
          Validation            Compilation
              │                     │
              └──────────┬──────────┘
                         ▼
                 Investigation Plan
                         │
                         ▼
                  Controller/API
                         │
              ┌──────────┴──────────┐
              ▼                     ▼
        Windows Agent          Linux Agent
              │                     │
              └──────────┬──────────┘
                         ▼
                 Evidence Ingestion
                         │
                         ▼
                  Evidence Storage
                         │
                         ▼
                  Detection Engine
                         │
                         ▼
                  Correlation Engine
                         │
                         ▼
                   Risk Assessment
                         │
                         ▼
                    Findings
                         │
                         ▼
                     Dashboard
                         │
                  ┌──────┴──────┐
                  ▼             ▼
               Analyst       PDF Report
```

---

# 21. Deployment Architecture

For development and demonstration, JOCKY can run using Docker Compose.

Conceptually:

```text
Docker Host
│
├── jocky-compiler
├── jocky-agent
├── backend
├── frontend
├── nginx
├── postgres
├── redis
├── minio
└── detector
```

The exact number of services is determined by the current `docker-compose.yml`.

The containers communicate over an internal Docker network.

Only the required public interfaces should be exposed to the host.

---

# 22. Security Boundaries

The architecture contains several trust boundaries.

```text
                    INTERNET / USER
                          │
                          ▼
                    Nginx / API
                          │
                    ──────┼──────
                          │
                    Trusted Backend
                          │
              ────────────┼────────────
              │            │           │
              ▼            ▼           ▼
           Database       Queue      Storage
                          │
                          ▼
                       Agents
                          │
                    ENDPOINT HOST
```

Important security requirements include:

* authenticated API access
* authenticated agent identity
* authorization checks
* TLS for network transport
* evidence integrity verification
* audit logging
* least-privilege execution
* input validation
* sandboxed compilation
* resource limits
* explicit laboratory boundaries

---

# 23. Failure Handling

The platform should assume that distributed components can fail.

Examples:

```text
Agent offline
Compiler failure
Invalid JOCKY program
Evidence upload failure
Database unavailable
Detection rule failure
Report generation failure
```

The system should represent these states explicitly.

For example:

```text
Investigation
   │
   ├── PC-01 → COMPLETED
   ├── PC-02 → FAILED
   └── PC-03 → OFFLINE
```

An investigation should not silently appear successful when part of its evidence collection failed.

---

# 24. Observability

Each major subsystem should expose sufficient information for debugging.

At minimum:

```text
Logs
Health status
Component version
Request IDs
Investigation IDs
Agent IDs
Error messages
Execution duration
```

An investigation should have a traceable identifier that can be followed through:

```text
Dashboard
   ↓
API
   ↓
Controller
   ↓
Agent
   ↓
Evidence
   ↓
Detection
   ↓
Finding
```

---

# 25. Development Strategy

JOCKY should be developed through vertical slices rather than implementing all components independently.

The recommended order is:

```text
1. Language
       ↓
2. Compiler
       ↓
3. Runtime
       ↓
4. Synthetic Evidence
       ↓
5. Agent
       ↓
6. Backend
       ↓
7. Detection
       ↓
8. Correlation
       ↓
9. Dashboard
       ↓
10. Reports
```

At each stage, an end-to-end test should prove that the new functionality works.

---

# 26. Definition of a Working System

JOCKY should not be considered fully functional merely because all services start successfully.

The minimum end-to-end definition of success is:

```text
JOCKY Source
      ↓
Successfully Parsed
      ↓
Semantically Validated
      ↓
Compiled
      ↓
Investigation Executed
      ↓
Evidence Produced
      ↓
Evidence Stored
      ↓
Detection Executed
      ↓
Findings Produced
      ↓
Events Correlated
      ↓
Dashboard Updated
      ↓
Report Generated
```

Every transition must be demonstrably testable.

---

# 27. Architectural Goal

The final JOCKY platform should provide a single investigation workflow:

```text
                 WRITE
                   │
                   ▼
                COMPILE
                   │
                   ▼
                  RUN
                   │
                   ▼
                COLLECT
                   │
                   ▼
                NORMALIZE
                   │
                   ▼
                 DETECT
                   │
                   ▼
               CORRELATE
                   │
                   ▼
                EXPLAIN
                   │
                   ▼
                REPORT
```

The central architectural idea is therefore:

> **JOCKY separates the description of a forensic investigation from endpoint-specific collection, while providing a complete pipeline from investigation definition to evidence, detection, correlation, visualization, and reporting.**

---

## Related Documentation

The architecture is supported by the following documents:

```text
docs/
├── ARCHITECTURE.md       ← This document
├── LANGUAGE_SPEC.md      ← JOCKY language definition
├── IR_SPEC.md            ← Intermediate representation
├── FORENSICS_SPEC.md     ← Evidence and forensic model
├── SECURITY_MODEL.md     ← Security boundaries and controls
├── TEST_PLAN.md          ← Verification strategy
├── ROADMAP.md            ← Development milestones
├── DESIGN.md             ← Detailed design decisions
├── STATUS.md             ← Current implementation state
├── TEAMMATES.md          ← Team responsibilities
└── AGENTS.md             ← Coding-agent instructions
```

`ARCHITECTURE.md` describes **what the system is and how its components interact**.

It does not claim that every component described here is already implemented. Current implementation progress is tracked separately in `STATUS.md`.
