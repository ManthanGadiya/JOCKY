# JOCKY — Forensics Specification

**Document:** `docs/FORENSICS_SPEC.md`
**Project:** JOCKY
**Version:** 1.0
**Status:** Forensic Data Contract
**Last Updated:** 2026-08-28

---

# 1. Purpose

This document defines the forensic data model used by JOCKY.

It specifies:

* what constitutes evidence,
* how evidence is represented,
* how evidence is collected,
* how evidence is normalized,
* how evidence provenance is maintained,
* how evidence is correlated,
* how findings are generated,
* how timelines and graphs are constructed,
* how evidence integrity is maintained.

The central principle is:

```text
Collection
    ↓
Evidence
    ↓
Normalization
    ↓
Analysis
    ↓
Correlation
    ↓
Finding
    ↓
Report
```

---

# 2. Forensic Design Goals

The JOCKY forensic subsystem must prioritize:

1. Evidence integrity
2. Provenance
3. Reproducibility
4. Traceability
5. Cross-platform normalization
6. Explicit timestamps
7. Structured data
8. Auditable analysis
9. Controlled execution
10. Separation of observation from interpretation

---

# 3. Evidence Lifecycle

Every evidence object follows a conceptual lifecycle.

```text
                    ┌──────────────┐
                    │   Endpoint   │
                    └──────┬───────┘
                           │
                           ▼
                    ┌──────────────┐
                    │  Collection  │
                    └──────┬───────┘
                           │
                           ▼
                    ┌──────────────┐
                    │   Evidence   │
                    └──────┬───────┘
                           │
                           ▼
                    ┌──────────────┐
                    │ Normalization│
                    └──────┬───────┘
                           │
              ┌────────────┴────────────┐
              ▼                         ▼
       ┌──────────────┐         ┌──────────────┐
       │   Detection  │         │ Correlation  │
       └──────┬───────┘         └──────┬───────┘
              │                         │
              └────────────┬────────────┘
                           ▼
                    ┌──────────────┐
                    │   Findings   │
                    └──────┬───────┘
                           │
                           ▼
                    ┌──────────────┐
                    │    Report    │
                    └──────────────┘
```

---

# 4. Evidence vs Finding

This distinction is fundamental.

## Evidence

Evidence is an observed or collected fact.

Example:

```text
Process:
    PID = 4216
    Name = example.exe
    PPID = 812
```

## Finding

A finding is an analytical conclusion derived from evidence.

Example:

```text
Finding:
    Suspicious parent-child process relationship
```

Therefore:

```text
Evidence ≠ Finding
```

The system must never silently convert an analytical conclusion into an observed fact.

---

# 5. Evidence Object

Every evidence object should have a common envelope.

Conceptual structure:

```text
Evidence
├── id
├── case_id
├── host_id
├── type
├── source
├── collected_at
├── observed_at
├── collector
├── schema_version
├── payload
├── integrity
└── provenance
```

---

# 6. Evidence ID

Every evidence object must have a unique identifier.

Example:

```text
EV-20260828-000001
```

The identifier should be unique within the investigation system.

It must not itself be treated as a cryptographic integrity mechanism.

---

# 7. Case ID

Evidence must belong to an investigation case.

Example:

```text
CASE-2026-00017
```

This allows multiple evidence objects to be grouped.

```text
CASE-2026-00017
│
├── Evidence 001
├── Evidence 002
├── Evidence 003
└── Evidence 004
```

---

# 8. Host ID

Evidence collected from an endpoint must identify the logical host.

Example:

```text
host_id = PC-01
```

The host identifier should be stable within the JOCKY deployment.

---

# 9. Evidence Types

Initial evidence categories are:

```text
system
process
file
network
driver
memory
event
registry
user
service
module
finding
timeline
```

Additional types may be introduced later.

---

# 10. System Evidence

System evidence describes the endpoint environment.

Example:

```json
{
  "type": "system",
  "hostname": "PC-01",
  "os": "Windows",
  "architecture": "x86_64",
  "version": "example"
}
```

Possible fields:

```text
hostname
operating_system
os_version
architecture
kernel_version
boot_time
timezone
```

Platform-specific fields should be normalized where practical.

---

# 11. Process Evidence

Process evidence represents an observed process.

Example:

```json
{
  "type": "process",
  "pid": 4216,
  "ppid": 812,
  "name": "example.exe",
  "path": "C:\\example\\example.exe"
}
```

Possible fields:

```text
pid
ppid
name
path
command_line
user
integrity_level
creation_time
termination_time
architecture
```

Fields unavailable on a particular operating system should be explicitly represented as unavailable rather than fabricated.

---

# 12. Process Relationships

Processes may be represented as nodes in a relationship graph.

Example:

```text
parent.exe
    │
    └── example.exe
```

The relationship may contain:

```text
parent_pid
child_pid
relationship_type
observed_at
```

Example:

```text
PROCESS_PARENT
    parent = 812
    child  = 4216
```

---

# 13. File Evidence

File evidence represents an observed file.

Example:

```json
{
  "type": "file",
  "path": "/evidence/sample.exe",
  "size": 1048576,
  "sha256": "..."
}
```

Possible fields:

```text
path
name
size
creation_time
modification_time
access_time
file_type
permissions
owner
hashes
```

---

# 14. Cryptographic Hashes

JOCKY may calculate cryptographic hashes for evidence integrity and identification.

Supported algorithms should initially include:

```text
SHA-256
SHA-512
```

Additional algorithms may be supported later.

Example:

```text
hashes:
    sha256 = ...
    sha512 = ...
```

Hashes identify content and help detect unexpected modification.

A hash alone does not prove the origin or authenticity of evidence.

---

# 15. Network Evidence

Network evidence represents observed network activity.

Example:

```json
{
  "type": "network_connection",
  "local_address": "192.0.2.10",
  "local_port": 49152,
  "remote_address": "192.0.2.20",
  "remote_port": 443,
  "protocol": "TCP",
  "state": "ESTABLISHED"
}
```

Possible fields:

```text
local_address
local_port
remote_address
remote_port
protocol
state
pid
process_name
observed_at
```

---

# 16. Driver Evidence

Driver evidence represents observed driver information.

Possible fields:

```text
name
path
version
publisher
signature_status
load_time
status
```

Example:

```json
{
  "type": "driver",
  "name": "example.sys",
  "signature_status": "unknown"
}
```

Driver evidence is observational.

The forensic system must not interpret the existence of a driver as proof of malicious activity.

---

# 17. Memory Evidence

Memory evidence represents information extracted from an authorized memory image or approved acquisition mechanism.

Possible fields:

```text
source
offset
process_id
artifact_type
address
size
content_hash
```

Example:

```json
{
  "type": "memory_artifact",
  "source": "memory.dump",
  "process_id": 4216,
  "artifact_type": "module"
}
```

The system should distinguish:

```text
memory acquisition
```

from:

```text
memory analysis
```

---

# 18. Event Evidence

Events represent observations occurring at a particular time.

Example:

```json
{
  "type": "event",
  "event_type": "process_start",
  "timestamp": "2026-08-28T10:02:13Z",
  "pid": 4216
}
```

Possible event types include:

```text
process_start
process_exit
file_create
file_modify
network_connect
network_disconnect
driver_load
service_start
```

---

# 19. Timestamps

JOCKY distinguishes between multiple time concepts.

```text
observed_at
collected_at
created_at
```

## observed_at

When the event or artifact is believed to have occurred.

## collected_at

When JOCKY collected the evidence.

## created_at

When the evidence object itself was created.

These timestamps must not be conflated.

---

# 20. Timestamp Format

Timestamps should use ISO-8601-compatible UTC representation.

Example:

```text
2026-08-28T10:02:13.451Z
```

UTC should be preferred for cross-host correlation.

Original timezone information may be preserved as metadata when available.

---

# 21. Timestamp Reliability

A timestamp should optionally include a confidence or source indicator.

Example:

```text
timestamp:
    value = "2026-08-28T10:02:13Z"
    source = "endpoint_event_log"
```

Possible source categories:

```text
system_clock
event_log
file_metadata
memory_artifact
derived
unknown
```

Derived timestamps must not be presented as directly observed timestamps.

---

# 22. Evidence Source

Every evidence object should identify its source.

Possible sources:

```text
endpoint
memory_image
disk_image
event_log
filesystem
network_observation
laboratory_fixture
imported_dataset
```

Example:

```text
source:
    type = "laboratory_fixture"
    identifier = "process_anomaly.json"
```

---

# 23. Laboratory Evidence

Controlled laboratory scenarios are first-class evidence sources.

Example:

```text
source.type = laboratory_fixture
```

This allows the detection system to test scenarios without requiring the actual execution of dangerous behavior.

Example:

```text
testdata/
├── process_anomaly.json
├── suspicious_driver.json
├── network_anomaly.json
└── timeline_case.json
```

These files represent evidence fixtures.

They do not themselves execute the behaviors they describe.

---

# 24. Evidence Provenance

Evidence provenance answers:

> Where did this evidence come from?

Example:

```text
Evidence
   │
   ├── Case
   ├── Host
   ├── Collector
   ├── Source
   ├── Timestamp
   └── Parent Evidence
```

Provenance should be preserved throughout transformations.

---

# 25. Evidence Lineage

If evidence is derived from other evidence, the relationship must be recorded.

Example:

```text
Process Evidence
       │
       ▼
Correlation
       │
       ▼
Suspicious Relationship
```

The finding should retain references to the original evidence IDs.

Example:

```text
finding.source_evidence:
    EV-001
    EV-004
```

---

# 26. Integrity Metadata

Evidence should include integrity information.

Conceptually:

```text
integrity
├── hash_algorithm
├── content_hash
└── verified
```

Example:

```text
integrity:
    algorithm = SHA-256
    hash = "..."
    verified = true
```

The integrity mechanism must never silently overwrite previously recorded hashes.

---

# 27. Chain of Custody

JOCKY should maintain an auditable evidence history.

Conceptually:

```text
Collection
    ↓
Hash
    ↓
Transfer
    ↓
Storage
    ↓
Analysis
    ↓
Report
```

Each important transition should be logged.

Example:

```text
CHAIN_EVENT
    evidence_id = EV-001
    action = collected
    actor = agent-PC01
    timestamp = ...
```

---

# 28. Chain-of-Custody Events

Initial event types:

```text
collected
hashed
transferred
stored
accessed
analyzed
exported
reported
```

Each event should contain:

```text
event_id
evidence_id
action
actor
timestamp
metadata
```

---

# 29. Normalization

Different operating systems may describe the same concept differently.

JOCKY therefore uses normalized schemas.

Example:

```text
Windows:
    ProcessId
    ParentProcessId

Linux:
    pid
    ppid

             ↓

Normalized:

    pid
    ppid
```

Normalization should preserve original fields when necessary.

---

# 30. Raw vs Normalized Evidence

Where possible, the system should distinguish:

```text
Raw Evidence
      │
      ▼
Normalized Evidence
```

Raw evidence preserves source-specific information.

Normalized evidence provides cross-platform compatibility.

The normalized representation must not falsely claim information that was unavailable in the raw source.

---

# 31. Detection Findings

A finding represents an analytical result.

Conceptual structure:

```text
Finding
├── id
├── type
├── severity
├── confidence
├── description
├── evidence_refs
├── rule_id
├── created_at
└── status
```

---

# 32. Finding Severity

Initial severity levels:

```text
INFO
LOW
MEDIUM
HIGH
CRITICAL
```

Severity describes the potential importance of a finding.

It does not automatically establish malicious intent.

---

# 33. Finding Confidence

Confidence describes how strongly the available evidence supports the finding.

Example:

```text
confidence = 0.85
```

Confidence should be kept separate from severity.

For example:

```text
Severity: HIGH
Confidence: LOW
```

is valid.

---

# 34. Detection Rules

Detection rules consume evidence and produce findings.

Conceptually:

```text
Evidence
   │
   ▼
Detection Rule
   │
   ▼
Finding
```

Example:

```text
PROCESS evidence
       │
       ▼
Parent-child anomaly rule
       │
       ▼
Finding
```

---

# 35. Rule Identification

Every detection rule should have a stable identifier.

Example:

```text
JOCKY-PROC-001
```

A finding should retain the rule ID that generated it.

This enables reproducibility.

---

# 36. Rule Versioning

Rules must be versioned.

Example:

```text
rule_id = JOCKY-PROC-001
rule_version = 1.2
```

A change to detection semantics should increment the rule version.

---

# 37. MITRE ATT&CK Mapping

Findings may optionally contain mappings to external threat-behavior taxonomies such as MITRE ATT&CK.

Example:

```text
technique:
    id = T1055
```

Such mappings describe the behavior represented by the evidence.

They must not be interpreted as proof that the mapped technique was actually executed unless the evidence supports that conclusion.

---

# 38. YARA / Signature Results

Signature-based detection may produce findings.

Conceptual result:

```text
rule:
    JOCKY-DEMO-001

match:
    true

evidence:
    EV-004
```

The system should record:

```text
rule_id
rule_version
match
evidence_refs
timestamp
```

---

# 39. Timeline Model

JOCKY represents events as timeline entries.

Conceptual structure:

```text
TimelineEvent
├── id
├── timestamp
├── type
├── host_id
├── source
├── evidence_refs
└── description
```

Example:

```text
10:01:14
FILE_CREATE
sample.exe

10:02:01
PROCESS_START
sample.exe

10:03:15
NETWORK_CONNECT
192.0.2.20:443
```

---

# 40. Timeline Ordering

Timeline events should be ordered primarily by:

```text
observed_at
```

When timestamps are unavailable or ambiguous, the system should preserve that uncertainty rather than inventing an exact ordering.

---

# 41. Relationship Graph

JOCKY may represent relationships as a graph.

```text
Graph
├── Nodes
└── Edges
```

Nodes may represent:

```text
Host
Process
File
Network endpoint
Driver
User
Service
Finding
```

Edges may represent:

```text
parent_of
executed
opened
connected_to
loaded
created
modified
associated_with
generated
```

---

# 42. Example Investigation Graph

Conceptual graph:

```text
              PC-01
                │
                │ hosts
                ▼
           example.exe
           /          \
       created        connected_to
         │                │
         ▼                ▼
      sample.dll       192.0.2.20
         │
         │ associated_with
         ▼
      Finding-001
```

The graph is an analytical representation derived from evidence.

It must retain references to the evidence supporting each edge.

---

# 43. Correlation

Correlation combines evidence that may represent related activity.

Example:

```text
Process Evidence
       +
Network Evidence
       +
File Evidence
       ↓
Correlation
       ↓
Finding
```

Correlation must preserve the original evidence references.

---

# 44. Correlation Confidence

Correlations may have a confidence value.

Example:

```text
relationship:
    process → network_connection

confidence:
    0.92
```

The confidence represents the strength of the inferred relationship.

---

# 45. Risk Score

The platform may calculate an aggregate risk score.

Example:

```text
risk_score = 85
```

The calculation must be deterministic for a given:

```text
evidence set
rule set
risk model version
```

---

# 46. Risk Is Not Proof

A high risk score means:

```text
The available evidence produces a high analytical risk assessment.
```

It does not mean:

```text
The endpoint is definitely compromised.
```

The dashboard and reports must preserve this distinction.

---

# 47. Evidence Storage

Evidence may be stored in two conceptual layers.

```text
Metadata Store
      │
      ├── IDs
      ├── timestamps
      ├── hashes
      └── relationships

Evidence Store
      │
      └── evidence payload
```

The implementation may use a relational database, object storage, or another persistence mechanism.

---

# 48. Evidence Serialization

Evidence should use a structured representation.

Example:

```json
{
  "id": "EV-001",
  "case_id": "CASE-001",
  "host_id": "PC-01",
  "type": "process",
  "observed_at": "2026-08-28T10:02:13Z",
  "payload": {
    "pid": 4216,
    "ppid": 812,
    "name": "example.exe"
  }
}
```

---

# 49. Schema Versioning

Every evidence type should have a schema version.

Example:

```text
type = process
schema_version = 1
```

Changes that break compatibility require a new major schema version.

---

# 50. Unknown Fields

Consumers should tolerate additional fields where possible.

For example:

```json
{
  "pid": 4216,
  "ppid": 812,
  "name": "example.exe",
  "future_field": "..."
}
```

Older consumers should not fail solely because an additional non-required field exists.

---

# 51. Missing Fields

Unavailable information must be represented explicitly.

Allowed:

```text
command_line = null
```

Not allowed:

```text
command_line = "unknown.exe"
```

when no evidence exists for that value.

The system must never fabricate forensic facts.

---

# 52. Agent Collection

The endpoint agent is responsible for collecting evidence.

Conceptually:

```text
JOCKY Runtime
      │
      ▼
Agent
      │
      ▼
Platform Provider
      │
      ▼
Operating System
```

The agent converts platform-specific observations into the normalized evidence schema.

---

# 53. Agent Responsibilities

The agent should:

```text
Collect
Normalize
Timestamp
Hash where appropriate
Attach provenance
Validate evidence
Transmit evidence
Record collection errors
```

The agent should not silently modify analytical conclusions.

---

# 54. Backend Responsibilities

The backend should:

```text
Authenticate agents
Validate evidence
Store evidence
Track cases
Run detection
Run correlation
Calculate risk
Construct timelines
Construct graphs
Generate reports
```

---

# 55. Dashboard Responsibilities

The dashboard should visualize:

```text
Cases
Hosts
Evidence
Findings
Risk
Timeline
Graph
Detection results
Reports
```

The dashboard is primarily a presentation and investigation interface.

---

# 56. Evidence Transmission

Evidence transmitted from an agent should contain:

```text
case_id
host_id
agent_id
evidence_id
schema_version
timestamp
payload
integrity metadata
```

The backend must validate the envelope before accepting it.

---

# 57. Transmission Failure

If evidence cannot be transmitted, the agent should report a structured error.

Example:

```text
EVIDENCE_TRANSMISSION_ERROR

Evidence:
    EV-004

Destination:
    Backend

Reason:
    Connection unavailable
```

The system should avoid silently dropping evidence.

---

# 58. Partial Collection

Forensic collection may fail partially.

Example:

```text
process.list()
    ├── 150 processes collected
    └── 2 processes inaccessible
```

The result should indicate partial collection.

Example:

```text
collection_status = PARTIAL
```

Possible collection states:

```text
SUCCESS
PARTIAL
FAILED
```

---

# 59. Collection Errors

Collection errors should be represented separately from findings.

Example:

```text
Collection Error:
    Access denied reading process metadata
```

This must not automatically become:

```text
Finding:
    Malicious process
```

---

# 60. Evidence Integrity Failure

If an evidence integrity check fails:

```text
Integrity Status:
    FAILED
```

The evidence must be flagged.

The system must not silently replace the content or hash.

---

# 61. Controlled Test Fixtures

The repository should maintain deterministic forensic fixtures.

Example:

```text
testdata/
├── process/
├── network/
├── file/
├── driver/
├── memory/
├── timelines/
└── combined/
```

These fixtures allow the complete detection pipeline to be tested without relying on a live endpoint.

---

# 62. Example Controlled Scenario

A fixture may contain:

```json
{
  "scenario": "process_anomaly",
  "host_id": "LAB-PC-01",
  "events": [
    {
      "type": "process_start",
      "pid": 4216,
      "ppid": 812
    }
  ]
}
```

The detection engine consumes this as evidence.

Expected output:

```text
Finding:
    process_anomaly

Severity:
    HIGH

Evidence:
    EV-001
```

The fixture does not execute an actual process-manipulation technique.

---

# 63. Reproducibility

A forensic result should be reproducible using:

```text
Case ID
Evidence IDs
Evidence hashes
Rule versions
Compiler version
Runtime version
Risk model version
```

This information should be included in reports.

---

# 64. Report Data

A report should contain:

```text
Case information
Host information
Investigation information
Evidence summary
Timeline
Graph
Findings
Risk assessment
Detection rules
Evidence hashes
Provenance
Collection errors
Software versions
```

---

# 65. Forensic Report Principle

A report should distinguish three layers:

```text
OBSERVED
    ↓
ANALYZED
    ↓
CONCLUDED
```

Example:

```text
Observed:
    Process A connected to endpoint B.

Analyzed:
    The connection matches detection rule JOCKY-NET-001.

Concluded:
    The activity is considered suspicious with HIGH severity.
```

This distinction is essential for trustworthy forensic reporting.

---

# 66. Security Boundary

The forensic subsystem is designed for authorized investigation.

It must not provide capabilities intended to:

```text
disable security software
evade security monitoring
execute arbitrary payloads
exploit vulnerable drivers
establish covert command channels
```

Security-related behaviors are represented as:

```text
evidence
laboratory fixtures
detection scenarios
analytical findings
```

rather than offensive execution primitives.

---

# 67. Cross-Platform Principle

The same conceptual evidence type should have a common schema.

Example:

```text
Windows Process
       │
       ├── Windows-specific fields
       │
       ▼
Normalization
       │
       ▼
Common Process Evidence
       ▲
       │
Linux Process
       │
       └── Linux-specific fields
```

Platform-specific metadata may remain available as extensions.

---

# 68. Extension Mechanism

Future evidence types may be introduced through versioned schemas.

Example:

```text
process/v1
process/v2
network/v1
memory/v1
```

An extension must define:

```text
Schema
Required fields
Optional fields
Validation rules
Normalization rules
Provenance requirements
```

---

# 69. Validation

Evidence validation should occur before persistence.

Validation checks include:

```text
Required fields
Data types
Timestamp format
Schema version
Case association
Host association
Integrity metadata
```

Invalid evidence should produce a structured validation error.

---

# 70. Example Validation Error

```text
EVIDENCE_VALIDATION_ERROR

Evidence:
    EV-007

Field:
    observed_at

Problem:
    Invalid timestamp format
```

---

# 71. Complete Forensic Pipeline

The complete JOCKY forensic flow is:

```text
              JOCKY Program
                    │
                    ▼
              Compiler / IR
                    │
                    ▼
               Agent Task
                    │
                    ▼
             Evidence Collection
                    │
                    ▼
             Raw Evidence
                    │
                    ▼
               Normalize
                    │
                    ▼
            Validate + Hash
                    │
                    ▼
              Evidence Store
                    │
             ┌──────┴──────┐
             ▼             ▼
         Detection     Correlation
             │             │
             └──────┬──────┘
                    ▼
                 Findings
                    │
             ┌──────┴──────┐
             ▼             ▼
          Timeline        Graph
             │             │
             └──────┬──────┘
                    ▼
               Risk Model
                    │
                    ▼
                  Report
                    │
                    ▼
                Dashboard
```

---

# 72. Core Forensic Principle

The fundamental JOCKY forensic principle is:

> **Every analytical conclusion should be traceable back to the evidence that produced it.**

Therefore:

```text
Finding
   ↓
Rule
   ↓
Evidence
   ↓
Source
   ↓
Collector
   ↓
Host
   ↓
Timestamp
```

A user viewing a finding should ultimately be able to determine **why the system produced that finding**.

---

# 73. Relationship to Other Specifications

The forensic specification connects the other project components.

```text
LANGUAGE_SPEC.md
        │
        ▼
     JOCKY Code
        │
        ▼
IR_SPEC.md
        │
        ▼
    JOCKY IR
        │
        ▼
 Runtime / Agent
        │
        ▼
FORENSICS_SPEC.md
        │
        ├── Evidence
        ├── Detection
        ├── Correlation
        ├── Timeline
        └── Findings
                │
                ▼
        SECURITY_MODEL.md
                │
                ▼
          Authorized Use
```

---

# 74. Source of Truth

This document defines the conceptual forensic data contract.

Implementation schemas must remain synchronized with:

```text
src/forensics/
schemas/
tests/
```

Any implementation that changes the evidence model must update:

```text
FORENSICS_SPEC.md
TEST_PLAN.md
STATUS.md
```

as appropriate.

---

# 75. Completion Criteria

The forensic subsystem is considered minimally complete when it can:

```text
✓ Collect evidence
✓ Normalize evidence
✓ Validate evidence
✓ Assign evidence IDs
✓ Associate evidence with cases and hosts
✓ Preserve timestamps
✓ Preserve provenance
✓ Calculate integrity hashes
✓ Store evidence
✓ Run detection
✓ Produce findings
✓ Correlate evidence
✓ Construct timelines
✓ Construct graphs
✓ Calculate risk
✓ Generate an auditable report
```

All of these capabilities must have automated tests before being considered production-ready.

---

# 76. Final Principle

JOCKY is not merely a scanner.

It is an evidence pipeline:

```text
        WHAT HAPPENED?
              │
              ▼
          Evidence
              │
              ▼
        WHAT RELATES?
              │
              ▼
         Correlation
              │
              ▼
        WHAT IS UNUSUAL?
              │
              ▼
          Detection
              │
              ▼
        HOW IMPORTANT?
              │
              ▼
          Risk Model
              │
              ▼
        WHAT CAN WE PROVE?
              │
              ▼
           Report
```

The forensic system must always preserve the distinction between **what was observed**, **what was inferred**, and **what was concluded**.
