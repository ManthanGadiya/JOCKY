# JOCKY — Security Model

**Document:** `docs/SECURITY_MODEL.md`
**Project:** JOCKY
**Version:** 1.0
**Status:** Security Architecture Contract
**Last Updated:** 2026-08-28

---

# 1. Purpose

This document defines the security model for JOCKY.

It establishes:

* trust boundaries,
* security principals,
* capabilities,
* authorization requirements,
* data-protection requirements,
* agent security,
* compiler security,
* runtime security,
* backend security,
* evidence security,
* laboratory isolation,
* prohibited capabilities,
* auditing requirements,
* failure behavior.

The security model exists to ensure that JOCKY remains a **forensic investigation and detection platform**, rather than becoming an unrestricted offensive execution framework.

---

# 2. Security Objective

The primary security objective is:

> **JOCKY must enable authorized evidence collection, forensic analysis, detection, correlation, and reporting without providing mechanisms intended to bypass or disable security controls.**

The architecture therefore separates:

```text
Investigation
     │
     ▼
Evidence Collection
     │
     ▼
Analysis
     │
     ▼
Detection
     │
     ▼
Reporting
```

from capabilities such as:

```text
Security-control evasion
Unauthorized execution
Credential theft
Kernel exploitation
Covert communication
Persistence
```

The second category is outside the JOCKY runtime capability model.

---

# 3. Security Principles

JOCKY follows these principles.

## 3.1 Least Privilege

Every component should receive only the permissions required for its role.

```text
Compiler
    → compile

Backend
    → manage investigations/evidence

Agent
    → authorized collection

Dashboard
    → presentation and investigation

Database
    → persistence
```

No component should receive unnecessary privileges.

---

## 3.2 Explicit Capabilities

Operations require explicit capabilities.

Example:

```text
PROCESS_LIST
    → process.read
```

The absence of a capability means the operation cannot execute.

---

## 3.3 Default Deny

Unsupported capabilities must be denied by default.

Conceptually:

```text
Requested Operation
       │
       ▼
Capability Check
       │
       ├── Allowed → Continue
       │
       └── Denied  → Reject
```

---

## 3.4 Fail Closed

Security failures should result in rejection rather than automatic fallback to a less secure behavior.

---

## 3.5 Auditability

Security-sensitive actions must be logged.

An investigator should be able to determine:

```text
Who
    ↓
requested what
    ↓
against which host
    ↓
when
    ↓
with which authorization
    ↓
and what happened
```

---

## 3.6 Evidence Integrity

Collected evidence must preserve provenance and integrity metadata.

---

## 3.7 Separation of Duties

The compiler, backend, endpoint agent, and dashboard have different responsibilities.

No single component should unnecessarily combine all privileges.

---

# 4. Threat Model

JOCKY considers the following threat categories.

```text
T1  Unauthorized user
T2  Compromised endpoint agent
T3  Malicious JOCKY program
T4  Malicious or compromised backend client
T5  Tampered evidence
T6  Compromised dashboard
T7  Malicious detection rule
T8  Supply-chain compromise
T9  Network attacker
T10 Laboratory escape or cross-contamination
```

The implementation should consider these threats when introducing new functionality.

---

# 5. Assets

Important JOCKY assets include:

```text
JOCKY source code
Compiled IR
Runtime configuration
Agent credentials
Backend credentials
Case metadata
Evidence
Evidence hashes
Detection rules
Investigation reports
Audit logs
Database
Laboratory fixtures
```

---

# 6. Security Boundaries

The architecture contains several trust boundaries.

```text
┌─────────────────────────────┐
│ Investigator Workstation    │
│                             │
│ JOCKY Source / CLI / Editor  │
└──────────────┬──────────────┘
               │
               │ authenticated request
               ▼
┌─────────────────────────────┐
│ Backend                     │
│                             │
│ API / Case / Detection      │
└──────────────┬──────────────┘
               │
               │ authorized task
               ▼
┌─────────────────────────────┐
│ Endpoint Agent              │
│                             │
│ Collection / Normalization  │
└──────────────┬──────────────┘
               │
               ▼
        Operating System
```

Each boundary must validate inputs crossing it.

---

# 7. Security Principals

Initial principals include:

```text
Investigator
Administrator
Endpoint Agent
Backend Service
Detection Engine
Report Generator
```

Each principal should have explicitly defined permissions.

---

# 8. Investigator

The investigator can:

```text
Create cases
Submit investigations
View authorized evidence
Run supported detection
Inspect findings
Generate reports
```

The investigator must not automatically receive administrative privileges over endpoint security mechanisms.

---

# 9. Administrator

The administrator may manage:

```text
Users
Agents
Policies
Detection rules
Cases
System configuration
```

Administrative access must itself be authenticated and audited.

---

# 10. Endpoint Agent

The endpoint agent is a privileged component only where necessary for authorized forensic collection.

Its responsibilities are limited to:

```text
Evidence collection
Evidence normalization
Evidence integrity
Task execution within capability policy
Evidence transmission
Audit logging
```

The agent must not expose arbitrary operating-system command execution through JOCKY.

---

# 11. Compiler Security Model

The compiler is considered an **untrusted-input processor**.

JOCKY source should be treated as potentially malicious input.

The compiler must therefore:

```text
Parse safely
Validate syntax
Validate semantics
Validate capabilities
Reject unsupported operations
Avoid arbitrary native execution
```

Compilation must not execute JOCKY source as host-language code.

---

# 12. Compiler Isolation

Where practical, the compiler should execute inside a constrained environment.

Example:

```text
JOCKY Source
     │
     ▼
Compiler Container
     │
     ├── Lexer
     ├── Parser
     ├── Semantic Analyzer
     └── IR Generator
```

The compiler should not require host-level privileges.

---

# 13. JOCKY IR Security

JOCKY IR is an executable representation and therefore must be treated as untrusted input.

Before execution:

```text
IR
 │
 ▼
Version Validation
 │
 ▼
Structural Validation
 │
 ▼
Type Validation
 │
 ▼
Capability Validation
 │
 ▼
Policy Validation
 │
 ▼
Execution
```

Invalid IR must never reach the execution stage.

---

# 14. Closed Instruction Set

The JOCKY IR instruction set must be closed.

Only registered operations may execute.

Example:

```text
PROCESS_LIST
FILE_HASH
NETWORK_CONNECTIONS
SYSTEM_INFO
```

An unknown opcode must be rejected.

Example:

```text
UNKNOWN_OPCODE
```

Result:

```text
IR_VALIDATION_ERROR
```

---

# 15. No Arbitrary Native Execution

JOCKY must not expose an unrestricted instruction equivalent to:

```text
EXECUTE_NATIVE
EXECUTE_SHELL
RUN_COMMAND
LOAD_ARBITRARY_CODE
```

The runtime should expose explicit forensic operations instead.

Preferred:

```text
process.list();
```

rather than:

```text
execute("some operating-system command");
```

This is a fundamental security boundary.

---

# 16. Capability Model

Every runtime operation maps to a capability.

Example:

| Operation               | Capability          |
| ----------------------- | ------------------- |
| `system.info()`         | `system.read`       |
| `process.list()`        | `process.read`      |
| `file.hash()`           | `file.hash`         |
| `file.analyze()`        | `file.read`         |
| `network.connections()` | `network.read`      |
| `driver.scan()`         | `driver.read`       |
| `memory.analyze()`      | `memory.analyze`    |
| evidence loading        | `evidence.read`     |
| detection               | `detection.execute` |
| reporting               | `report.generate`   |

---

# 17. Capability Policy

Capabilities are granted through policy.

Example:

```text
agent_policy:

    system.read       = allow
    process.read      = allow
    file.read         = allow
    file.hash         = allow
    network.read      = allow
    driver.read       = allow
    memory.analyze    = deny
```

If a program requests:

```text
MEMORY_ANALYZE
```

the agent must reject it.

---

# 18. Capability Escalation

JOCKY programs must not be able to grant themselves additional capabilities.

This is prohibited:

```text
program
   ↓
request capability
   ↓
modify own policy
   ↓
execute
```

The correct model is:

```text
Administrator
      ↓
Policy
      ↓
Agent
      ↓
JOCKY Program
```

---

# 19. Authentication

Components communicating with the backend must authenticate.

At minimum:

```text
Agent → Backend
Investigator → Backend
Administrator → Backend
```

Authentication mechanisms should use established secure protocols.

Credentials must not be hardcoded into source code.

---

# 20. Authorization

Authentication answers:

> Who are you?

Authorization answers:

> Are you allowed to perform this action?

Both are required.

Example:

```text
Authenticated Agent
       +
Missing process.read capability
       ↓
Request rejected
```

---

# 21. Agent Identity

Every agent should have a unique logical identity.

Example:

```text
agent_id = AGENT-PC-01
```

The backend should associate the identity with:

```text
Host
Policy
Status
Last contact
Version
```

---

# 22. Agent Registration

A new agent should require an explicit registration process.

Conceptually:

```text
New Agent
    │
    ▼
Registration
    │
    ▼
Authentication
    │
    ▼
Policy Assignment
    │
    ▼
Authorized
```

Unregistered agents must not submit trusted evidence.

---

# 23. Agent Revocation

An agent identity must be revocable.

Example:

```text
AGENT-PC-01
    ↓
REVOKED
```

The backend should reject future authenticated requests from that identity.

---

# 24. Transport Security

Communication between components should use authenticated encrypted transport where applicable.

Conceptually:

```text
Agent
  │
  │ TLS / authenticated transport
  ▼
Backend
```

Sensitive evidence must not be transmitted in plaintext over untrusted networks.

---

# 25. Input Validation

Every external input must be validated.

Sources include:

```text
JOCKY source
IR
API requests
Agent evidence
Detection rules
Configuration
File paths
Case identifiers
User input
```

Validation should occur at the boundary where input enters the component.

---

# 26. Path Security

File-related operations must validate paths.

The runtime should prevent unauthorized traversal outside configured evidence roots.

Example malicious input:

```text
../../../../sensitive-file
```

must be rejected when it escapes the configured evidence boundary.

---

# 27. Evidence Access Boundary

The agent should use explicit evidence roots.

Example:

```text
/evidence/
```

A JOCKY program should not automatically gain access to the entire filesystem.

---

# 28. Resource Limits

The runtime must protect against resource exhaustion.

Possible limits:

```text
Maximum execution time
Maximum memory
Maximum evidence size
Maximum result count
Maximum file size
Maximum recursion depth
Maximum graph size
```

Example:

```text
MAX_FILE_ANALYSIS_SIZE = configured limit
```

Exceeding a limit should result in a controlled error.

---

# 29. Denial-of-Service Protection

An investigation must not be able to consume unlimited endpoint resources.

The agent should enforce:

```text
CPU limits
Memory limits
I/O limits
Execution timeout
Concurrency limits
```

where practical.

---

# 30. Evidence Security

Evidence should be protected against:

```text
Unauthorized modification
Unauthorized deletion
Unauthorized disclosure
Unexpected replacement
```

Access should be controlled according to case permissions.

---

# 31. Evidence Integrity

Evidence should have cryptographic integrity metadata.

Example:

```text
Evidence
   │
   ├── SHA-256
   ├── Collector
   ├── Timestamp
   └── Provenance
```

Changes should result in an integrity mismatch.

---

# 32. Evidence Immutability

Once evidence is accepted into an investigation record, the original evidence object should be treated as immutable.

Corrections should produce a new version or derived object.

The original record should remain auditable.

---

# 33. Evidence Confidentiality

Forensic evidence may contain sensitive information.

Therefore access should be restricted according to:

```text
Case
User
Role
Permission
```

The dashboard should not expose evidence to unauthorized users.

---

# 34. Logging

Security-relevant events should be logged.

Examples:

```text
User login
Agent registration
Case creation
Investigation submission
Capability denial
Evidence collection
Evidence transfer
Rule execution
Report generation
Policy change
Agent revocation
```

---

# 35. Audit Log Structure

Conceptual structure:

```text
AuditEvent
├── id
├── timestamp
├── actor
├── action
├── target
├── result
└── metadata
```

Example:

```text
actor:
    AGENT-PC-01

action:
    evidence.submit

target:
    CASE-001

result:
    success
```

---

# 36. Audit Log Integrity

Audit logs should be protected against unauthorized modification.

Where practical, append-only storage or integrity mechanisms should be used.

---

# 37. Sensitive Data Handling

The platform should minimize unnecessary collection of sensitive data.

If sensitive information is collected as part of legitimate forensic evidence, access should be restricted and the data should be handled according to the deployment's applicable policies and laws.

---

# 38. Secrets Management

Secrets must not be stored in:

```text
JOCKY source
Git repository
Docker image
frontend JavaScript
public configuration
logs
```

Secrets should be supplied through secure configuration mechanisms.

---

# 39. Dashboard Security

The dashboard is an untrusted client boundary.

The backend must not trust:

```text
Frontend validation
Hidden UI controls
Client-side permissions
```

Authorization must be enforced server-side.

---

# 40. API Security

Every sensitive backend API should perform:

```text
Authentication
Authorization
Input validation
Rate limiting where appropriate
Audit logging
```

Example:

```text
POST /cases
```

must verify that the requesting user is allowed to create cases.

---

# 41. Database Security

The database should not be directly exposed to public clients.

Expected architecture:

```text
Dashboard
    │
    ▼
Backend API
    │
    ▼
Database
```

The frontend should never connect directly to the database.

---

# 42. Database Credentials

Database credentials should be stored in protected configuration.

They must not be committed to source control.

---

# 43. Detection Rule Security

Detection rules are executable analytical logic and must therefore be treated as potentially untrusted.

Rules should be:

```text
Versioned
Validated
Reviewed
Sandboxed where necessary
Audited
```

---

# 44. Rule Isolation

A detection rule should only have access to the evidence provided to it.

It should not automatically gain:

```text
Filesystem access
Network access
Shell execution
Operating-system privileges
```

unless explicitly required by a separately approved mechanism.

---

# 45. Supply-Chain Security

Third-party dependencies should be tracked.

The project should maintain:

```text
Dependency versions
Lock files
Build configuration
Container base versions
Compiler versions
Runtime versions
```

Dependency changes should be reviewed.

---

# 46. Container Security

For local deployment, containers provide process isolation.

Example:

```text
┌───────────────────────────┐
│ Docker Environment        │
│                           │
│ Compiler                  │
│ Backend                   │
│ Database                  │
│ Redis                     │
│ Frontend                  │
└───────────────────────────┘
```

Containers should run with the minimum required privileges.

Privileged containers should not be used unless absolutely necessary and explicitly documented.

---

# 47. Laboratory Security

Controlled laboratory scenarios must be isolated from production systems.

The preferred model is:

```text
Production Environment
        │
        │ isolated
        ▼
Laboratory Environment
```

Laboratory fixtures should preferably be represented as:

```text
JSON
PCAP
Memory images
Disk images
Synthetic event logs
Controlled datasets
```

rather than requiring execution of dangerous real-world techniques.

---

# 48. Laboratory Network Isolation

If live laboratory endpoints are used, they should operate inside an isolated network.

Example:

```text
                 Internet
                    X
                    │
            ┌───────┴───────┐
            │ Isolated Lab  │
            │ Network       │
            └───────┬───────┘
                    │
          ┌─────────┼─────────┐
          ▼         ▼         ▼
       Lab-PC1   Lab-PC2   Analysis
```

No uncontrolled bridge to production infrastructure should exist.

---

# 49. Synthetic Scenario Principle

The preferred testing approach is to represent dangerous behaviors through synthetic evidence.

Example:

```text
testdata/process_hollowing.json
```

may contain:

```text
process relationship
memory anomaly indicator
timeline information
```

The detection engine can process those observations without the system needing to execute the underlying technique.

---

# 50. Security-Sensitive Capability Boundary

The following categories are explicitly outside the JOCKY capability model:

```text
Security-control disabling
EDR/AV bypass
Security monitoring suppression
Credential theft
Unauthorized persistence
Covert command-and-control
Kernel exploitation
Vulnerable-driver exploitation
Arbitrary code injection
Arbitrary shell execution
Unauthorized privilege escalation
```

These are not valid JOCKY runtime capabilities.

---

# 51. Representation vs Execution

JOCKY may represent a security behavior as:

```text
Observed Evidence
Laboratory Fixture
Detection Rule
Finding
Timeline Event
Graph Relationship
```

It must not automatically provide an implementation of the behavior.

For example:

```text
"process hollowing detected"
```

may be valid evidence.

An operation whose purpose is to perform process hollowing is not a JOCKY forensic capability.

---

# 52. Security-Control Interaction

JOCKY should not intentionally bypass:

```text
Antivirus
EDR
Security monitoring
Kernel protections
Application controls
Access controls
```

Authorized deployments should instead use explicit:

```text
Allowlisting
Agent registration
Administrator permissions
Documented exceptions
Security-team approval
```

where required.

---

# 53. Failure Behavior

When a security boundary is violated, JOCKY should fail safely.

Example:

```text
Requested:
    driver.read

Policy:
    denied

Result:
    CAPABILITY_DENIED
```

The runtime must not attempt an alternative mechanism to bypass the policy.

---

# 54. Security Event Severity

Security events may use:

```text
INFO
WARNING
ERROR
CRITICAL
```

Example:

```text
CAPABILITY_DENIED
    severity = WARNING
```

Repeated or suspicious authorization failures may be escalated according to deployment policy.

---

# 55. Security Monitoring

The backend should monitor important events such as:

```text
Repeated capability denials
Invalid IR submissions
Invalid agent authentication
Unexpected agent versions
Evidence integrity failures
Unusual request volumes
Repeated failed authorization
```

---

# 56. Secure Development Requirements

New JOCKY capabilities should undergo a security review.

The review should answer:

```text
What capability is added?
Who can invoke it?
What privileges does it require?
What data can it access?
Can it affect the host?
Can it bypass an existing security boundary?
Can it be abused for arbitrary execution?
How is it audited?
How is it tested?
```

---

# 57. Capability Addition Process

A new capability should follow:

```text
Proposal
   ↓
Threat Analysis
   ↓
Capability Definition
   ↓
Policy Definition
   ↓
Implementation
   ↓
Security Tests
   ↓
Documentation
   ↓
Review
```

It should not be added merely because the underlying operating-system API exists.

---

# 58. Security Testing

Security tests should include:

```text
Malformed JOCKY source
Malformed IR
Unknown opcode
Invalid capability
Unauthorized API access
Path traversal
Oversized evidence
Invalid authentication
Revoked agent
Tampered evidence
Malformed detection rules
Resource exhaustion
```

---

# 59. Example: Unauthorized Operation

Input:

```text
security.disable();
```

Expected behavior:

```text
Compilation Error

Unknown or unsupported capability:
    security.disable
```

No runtime execution should occur.

---

# 60. Example: Capability Denial

Input:

```text
memory.analyze("memory.dump");
```

Agent policy:

```text
memory.analyze = deny
```

Expected result:

```text
Execution rejected.

Reason:
    CAPABILITY_DENIED

Capability:
    memory.analyze
```

No fallback mechanism should be attempted.

---

# 61. Example: Malformed IR

Input:

```text
UNKNOWN_OPCODE
```

Expected result:

```text
IR_VALIDATION_ERROR
```

The runtime must stop processing the module.

---

# 62. Example: Evidence Tampering

If:

```text
expected_hash != calculated_hash
```

the result should be:

```text
INTEGRITY_FAILURE
```

The evidence should be marked accordingly.

---

# 63. Security Context Propagation

Security context should propagate through the execution pipeline.

```text
User
 │
 ▼
Case
 │
 ▼
Investigation
 │
 ▼
IR
 │
 ▼
Capability Policy
 │
 ▼
Agent
 │
 ▼
Evidence
```

Every stage should retain enough context to determine whether the operation is authorized.

---

# 64. Security Context Metadata

An execution may retain:

```text
user_id
case_id
investigation_id
agent_id
policy_version
compiler_version
runtime_version
timestamp
```

This metadata supports auditing and reproducibility.

---

# 65. Incident Response

If the JOCKY infrastructure itself is compromised, administrators should be able to:

```text
Revoke agents
Disable accounts
Rotate credentials
Disable investigations
Preserve audit logs
Preserve evidence
Inspect affected cases
```

The exact operational procedure belongs to deployment documentation.

---

# 66. Recovery Principle

Security recovery must preserve forensic integrity.

Do not:

```text
delete evidence simply to hide an incident
overwrite audit history
silently replace compromised evidence
```

Instead:

```text
Preserve
Annotate
Isolate
Investigate
Recover
```

---

# 67. Security Invariants

The following invariants must always hold.

### Invariant 1

No unvalidated IR reaches execution.

### Invariant 2

No JOCKY program can grant itself capabilities.

### Invariant 3

No arbitrary native execution exists in the standard runtime.

### Invariant 4

Evidence provenance is preserved.

### Invariant 5

Security failures fail closed.

### Invariant 6

Frontend authorization is never trusted as the only authorization layer.

### Invariant 7

Laboratory scenarios remain isolated from production.

### Invariant 8

Analytical findings retain references to supporting evidence.

---

# 68. Security Architecture Summary

The security architecture is:

```text
                 Investigator
                      │
                 Authentication
                      │
                 Authorization
                      │
                      ▼
                JOCKY Compiler
                      │
                IR Validation
                      │
                      ▼
                  JOCKY IR
                      │
             Capability Check
                      │
                      ▼
                 JOCKY Agent
                      │
              Platform Provider
                      │
                      ▼
                Evidence
                      │
          Integrity + Provenance
                      │
                      ▼
                Backend
                 /      \
                /        \
          Detection    Storage
                \        /
                 \      /
                  Findings
                     │
                     ▼
                  Report
```

---

# 69. Security Philosophy

JOCKY follows this rule:

> **If a capability is useful for forensic collection or analysis, expose it explicitly, constrain it with policy, and audit it. If a capability exists primarily to bypass security controls or provide unrestricted execution, it does not belong in the JOCKY runtime.**

This principle should guide all future architecture and implementation decisions.

---

# 70. Relationship to Other Specifications

```text
ARCHITECTURE.md
       │
       ▼
System boundaries
       │
       ├───────────────┐
       ▼               ▼
LANGUAGE_SPEC.md    IR_SPEC.md
       │               │
       └───────┬───────┘
               ▼
       FORENSICS_SPEC.md
               │
               ▼
       SECURITY_MODEL.md
               │
               ▼
       Security constraints
               │
        ┌──────┴───────┐
        ▼              ▼
   TEST_PLAN.md    DESIGN.md
```

The documents have different responsibilities:

| Document            | Responsibility                       |
| ------------------- | ------------------------------------ |
| `ARCHITECTURE.md`   | Overall system structure             |
| `LANGUAGE_SPEC.md`  | Language syntax and semantics        |
| `IR_SPEC.md`        | Compiler intermediate representation |
| `FORENSICS_SPEC.md` | Evidence and forensic semantics      |
| `SECURITY_MODEL.md` | Security boundaries and capabilities |
| `TEST_PLAN.md`      | Security and functional verification |
| `ROADMAP.md`        | Implementation sequence              |
| `DESIGN.md`         | Engineering decisions                |
| `STATUS.md`         | Current implementation state         |
| `TEAMMATES.md`      | Team responsibilities                |
| `AGENTS.md`         | Coding-agent instructions            |

---

# 71. Completion Criteria

The security model is considered implemented when the project can demonstrate:

```text
✓ Authentication
✓ Authorization
✓ Capability enforcement
✓ IR validation
✓ Default-deny behavior
✓ Evidence integrity
✓ Evidence provenance
✓ Audit logging
✓ Resource limits
✓ Input validation
✓ Agent identity
✓ Agent revocation
✓ Laboratory isolation
✓ Security regression tests
```

The exact implementation status must be tracked in:

```text
docs/STATUS.md
```

---

# 72. Final Security Rule

The single most important security rule for JOCKY is:

```text
OBSERVE → ANALYZE → CORRELATE → DETECT → REPORT
```

not:

```text
BYPASS → INJECT → DISABLE → PERSIST → HIDE
```

JOCKY is designed around the first pipeline.
