# JOCKY — Test Plan

**Document:** `docs/TEST_PLAN.md`
**Project:** JOCKY
**Version:** 1.0
**Status:** Testing Contract
**Last Updated:** 2026-08-28

---

# 1. Purpose

This document defines the testing strategy for JOCKY.

The objective is to verify that:

1. JOCKY source is parsed correctly.
2. Semantic validation behaves correctly.
3. JOCKY source produces valid IR.
4. IR validation prevents invalid execution.
5. Forensic operations produce deterministic results.
6. Evidence integrity and provenance are preserved.
7. Capability restrictions are enforced.
8. The backend correctly receives and stores evidence.
9. Detection rules correctly identify supported behaviors.
10. The dashboard correctly represents investigation data.
11. Reports contain correct evidence and findings.
12. Windows and Linux implementations preserve the same JOCKY semantics.
13. Controlled laboratory scenarios can be reproduced safely.
14. Security boundaries cannot be bypassed through malformed input.

---

# 2. Testing Philosophy

Testing follows this principle:

> **Every important architectural guarantee must have a test that can fail if the guarantee is broken.**

The project should not consider a feature complete merely because its implementation compiles.

A feature is complete when:

```text
Implementation
      ↓
Unit Tests
      ↓
Integration Tests
      ↓
Security Tests
      ↓
End-to-End Validation
      ↓
Documented Result
```

---

# 3. Testing Pyramid

JOCKY uses a layered testing model.

```text
                  ┌───────────────┐
                  │   E2E Tests   │
                  └───────┬───────┘
                          │
                 ┌────────┴────────┐
                 │ Integration     │
                 │ Tests           │
                 └────────┬────────┘
                          │
                ┌─────────┴─────────┐
                │ Component Tests    │
                └─────────┬─────────┘
                          │
               ┌──────────┴──────────┐
               │    Unit Tests       │
               └─────────────────────┘
```

Most tests should exist at the lower levels.

---

# 4. Test Categories

The project should maintain these categories:

```text
Unit
Compiler
Language
IR
Runtime
Forensics
Security
Backend
Database
Detection
Agent
Cross-platform
Integration
End-to-end
Laboratory
Performance
Regression
```

---

# 5. Test Environment

The development environment should support:

```text
Linux
Windows
Docker
CI environment
```

The exact versions should be pinned/documented by the project.

---

# 6. Test Data

Test data must be deterministic and reproducible.

Recommended structure:

```text
tests/
├── unit/
├── compiler/
├── ir/
├── runtime/
├── forensics/
├── security/
├── integration/
├── e2e/
├── fixtures/
│   ├── evidence/
│   ├── processes/
│   ├── network/
│   ├── files/
│   ├── drivers/
│   └── timelines/
└── expected/
```

---

# 7. Golden Test Principle

Where output is deterministic, maintain expected output.

Example:

```text
tests/compiler/basic.jocky
```

Expected:

```text
tests/expected/basic.ir
```

Test:

```text
source
   ↓
compiler
   ↓
actual IR
   ↓
compare
   ↓
expected IR
```

This is useful for detecting accidental compiler changes.

---

# 8. Language Lexer Tests

The lexer must be tested independently.

Test cases should include:

```text
Identifiers
Keywords
Numbers
Strings
Booleans
Operators
Parentheses
Braces
Semicolons
Comments
Whitespace
Invalid characters
```

Example:

```text
system.info();
```

should produce the expected token sequence.

---

# 9. Parser Tests

Parser tests should verify valid syntax.

Examples:

```text
system.info();

process.list();

file.hash("sample.exe");

network.connections();
```

The parser should construct the correct AST.

---

# 10. Invalid Syntax Tests

Invalid programs must produce controlled compiler errors.

Examples:

```text
system.info(
```

```text
process.list(
```

```text
file.hash();
```

Expected:

```text
Compilation failed
Syntax error
```

The compiler must not crash.

---

# 11. Semantic Analysis Tests

Semantic tests verify that syntactically valid programs are also semantically valid.

Test:

```text
file.hash("sample.exe");
```

against:

```text
file.hash(1234);
```

The second should fail if the operation expects a string path.

---

# 12. Type Checking

Test:

```text
string
integer
boolean
arrays
objects
return values
function arguments
```

Invalid type combinations must produce deterministic errors.

---

# 13. Capability Analysis Tests

Every JOCKY operation should map to a defined capability.

Example:

```text
process.list();
```

must require:

```text
process.read
```

A missing capability must be detected.

---

# 14. Unsupported Capability Tests

Programs requesting unsupported capabilities must fail.

Example:

```text
security.disable();
```

Expected:

```text
ERROR:
Unsupported capability
```

The compiler must not generate executable behavior for unsupported operations.

---

# 15. Compiler Determinism

Given identical source and compiler configuration:

```text
source + compiler version + configuration
```

should produce semantically equivalent IR.

Where exact binary determinism is required, it should be explicitly tested.

---

# 16. Compiler Error Quality

Compiler errors should provide enough information to locate the problem.

Preferred format:

```text
error[E102]:
unsupported operation 'security.disable'

file: examples/test.jocky
line: 4
column: 1
```

Errors should not expose secrets or internal credentials.

---

# 17. IR Generation Tests

Every supported language construct should have expected IR.

Example:

```text
process.list();
```

should produce the appropriate IR operation.

Example conceptual IR:

```text
CALL PROCESS_LIST
```

---

# 18. IR Validation Tests

The IR validator must reject:

```text
Unknown opcode
Invalid operand
Invalid type
Missing operand
Invalid capability
Invalid version
Malformed structure
```

---

# 19. Unknown Opcode Test

Input:

```text
UNKNOWN_OPCODE
```

Expected:

```text
IR_VALIDATION_ERROR
```

The runtime must stop.

---

# 20. IR Version Tests

Test:

```text
supported version
older version
future version
invalid version
```

Unsupported IR versions should fail safely.

---

# 21. IR Resource Tests

Test limits such as:

```text
maximum instruction count
maximum constant size
maximum nesting depth
maximum module size
```

Exceeding a configured limit should produce a controlled error.

---

# 22. Runtime Unit Tests

Runtime operations should be tested individually.

Examples:

```text
system.info()
process.list()
file.hash()
file.analyze()
network.connections()
driver.scan()
memory.analyze()
```

Each operation should have:

```text
valid input
invalid input
permission denied
resource limit
backend failure
```

tests where applicable.

---

# 23. Deterministic Runtime Tests

For fixture-based tests:

```text
Input Fixture
     ↓
Runtime Operation
     ↓
Normalized Result
```

should produce the same result every time.

---

# 24. Forensic Evidence Tests

Every evidence object should be tested for:

```text
identity
timestamp
source
type
hash
provenance
content
metadata
```

---

# 25. Evidence Hash Tests

Given identical evidence:

```text
hash(A) == hash(A)
```

Given modified evidence:

```text
hash(A) != hash(A_modified)
```

The implementation should use a cryptographically appropriate hash.

---

# 26. Evidence Tampering Test

Procedure:

```text
1. Create evidence.
2. Calculate integrity metadata.
3. Modify evidence.
4. Recalculate integrity.
5. Compare.
```

Expected:

```text
INTEGRITY_FAILURE
```

---

# 27. Provenance Tests

Every accepted evidence object should retain provenance information.

At minimum, test:

```text
source
collector
timestamp
case
agent
```

where those fields are part of the implementation contract.

---

# 28. Agent Tests

The endpoint agent must be tested independently from the backend.

Test:

```text
Agent startup
Configuration
Registration
Authentication
Capability policy
Collection
Normalization
Evidence creation
Transmission
Error handling
Shutdown
```

---

# 29. Agent Authentication Tests

Test:

```text
valid credentials
invalid credentials
expired credentials
revoked agent
unknown agent
```

Expected unauthorized agents must be rejected.

---

# 30. Capability Enforcement Tests

Example:

```text
Policy:
    process.read = allow
    memory.analyze = deny
```

Execution:

```text
process.list()
```

Expected:

```text
SUCCESS
```

Execution:

```text
memory.analyze(...)
```

Expected:

```text
CAPABILITY_DENIED
```

---

# 31. No Fallback Test

When a capability is denied, the runtime must not attempt another mechanism to perform the denied action.

Test:

```text
Denied operation
      ↓
Immediate failure
```

not:

```text
Denied operation
      ↓
Alternative privileged operation
      ↓
Success
```

---

# 32. Path Traversal Tests

Test paths such as:

```text
../file
../../file
absolute paths outside evidence root
symbolic-link escapes
```

where applicable to the platform.

Expected:

```text
PATH_ACCESS_DENIED
```

---

# 33. File Size Tests

Attempt to analyze files larger than the configured limit.

Expected:

```text
RESOURCE_LIMIT_EXCEEDED
```

The agent should remain operational.

---

# 34. Backend API Tests

Every API endpoint should have tests for:

```text
valid request
invalid request
unauthenticated request
unauthorized request
malformed request
missing fields
unexpected fields
resource limits
```

---

# 35. Case Management Tests

Test:

```text
Create case
Read case
Update permitted fields
Close case
List cases
Access unauthorized case
```

---

# 36. Evidence API Tests

Test:

```text
Submit evidence
Retrieve evidence
Verify integrity
Associate evidence with case
Reject malformed evidence
Reject unauthorized submission
```

---

# 37. Database Tests

Database integration tests should verify:

```text
schema
constraints
relationships
transactions
indexes
foreign keys
migration behavior
```

---

# 38. Transaction Tests

A multi-step operation should not leave partially committed state.

Example:

```text
Create Case
     +
Create Investigation
     +
Store Evidence
```

If a required step fails, the system should follow the documented transaction policy.

---

# 39. Detection Engine Tests

Detection rules should be tested against known fixtures.

Example:

```text
Fixture:
    suspicious_process_relationship

Rule:
    PPID anomaly

Expected:
    detection = true
```

---

# 40. Negative Detection Tests

A detection rule must also be tested against benign evidence.

Example:

```text
Benign process relationship
       ↓
PPID anomaly rule
       ↓
Expected: no detection
```

This prevents rules from becoming overly broad.

---

# 41. Detection Severity Tests

For each finding, verify:

```text
rule
severity
confidence
evidence references
timestamp
MITRE mapping
```

where supported by the specification.

---

# 42. Correlation Tests

Multiple related observations should produce the expected correlated finding.

Example:

```text
Process anomaly
      +
Memory anomaly
      +
Suspicious module
      ↓
Correlated finding
```

The system must preserve references to the underlying observations.

---

# 43. Timeline Tests

Given events:

```text
10:01 file event
10:02 process event
10:03 network event
```

the timeline should produce the correct chronological ordering.

---

# 44. Graph Tests

Given:

```text
process → module
process → network endpoint
driver → device
```

the graph representation should contain the correct nodes and relationships.

---

# 45. Risk Scoring Tests

Risk calculations must be deterministic.

Given the same findings:

```text
findings + scoring policy
```

must produce the same score.

Boundary tests should include:

```text
0
minimum
normal
high
maximum
```

---

# 46. Report Tests

Generated reports should contain:

```text
Case information
Evidence identifiers
Hashes
Timeline
Findings
Risk score
Detection results
Provenance
Generation metadata
```

---

# 47. Report Integrity Tests

A report should reference the same underlying evidence identifiers and hashes stored by the backend.

Changing source evidence should not silently change a previously generated report without producing a new version.

---

# 48. Security Test Suite

The security suite must include:

```text
Authentication bypass
Authorization bypass
Capability escalation
Path traversal
Malformed IR
Unknown opcode
Resource exhaustion
Oversized input
Evidence tampering
Agent impersonation
Revoked agent
Malformed API input
Injection attempts
Secret exposure
```

---

# 49. Arbitrary Execution Regression Tests

The project must explicitly test that unsupported arbitrary execution cannot be introduced accidentally.

Examples to test against the compiler/runtime:

```text
shell execution
arbitrary command execution
arbitrary native function invocation
unrestricted dynamic library loading
self-granted capability
```

Expected result:

```text
REJECTED
```

---

# 50. Security-Control Bypass Regression Tests

The test suite must ensure that JOCKY does not expose operations intended to:

```text
disable security monitoring
bypass antivirus
bypass EDR
blind security tooling
disable kernel security mechanisms
```

These should remain outside the runtime capability registry.

---

# 51. Laboratory Scenario Testing

Controlled scenarios should use synthetic evidence whenever possible.

Example:

```text
Scenario:
    Process Hollowing Observation

Input:
    testdata/hollowing.json

Expected:
    process anomaly
    memory anomaly
    timeline event
    appropriate detection
```

The test does not need to execute the underlying offensive technique.

---

# 52. Example Laboratory Scenario

Scenario:

```text
LAB-001
```

Input:

```text
testdata/hollowing.json
```

Expected observations:

```text
process relationship
memory-region anomaly
module relationship
timestamp sequence
```

Expected detection:

```text
Process Hollowing Indicator
```

Expected result:

```text
Finding generated
Evidence references preserved
Risk calculation updated
```

---

# 53. BYOVD Laboratory Scenario

A controlled driver-abuse scenario may represent observations such as:

```text
driver metadata
driver load event
driver hash
driver reputation
unexpected kernel interaction
```

The scenario should use synthetic or pre-collected evidence.

The test should validate **detection and forensic interpretation**, not implement driver exploitation.

---

# 54. Network Scenario

A network fixture may represent:

```text
connection
timestamp
destination
protocol
process association
DNS observation
```

The detection engine should analyze the fixture.

The test does not require implementation of covert communication.

---

# 55. Cross-Platform Tests

The same JOCKY semantics should be tested on:

```text
Windows
Linux
```

where the capability exists on both platforms.

Example:

```text
process.list();
```

should produce platform-appropriate evidence while maintaining the same high-level semantic contract.

---

# 56. Platform Adapter Tests

Platform-specific implementations should be tested separately.

```text
JOCKY Operation
      │
      ├── Windows Adapter
      │
      └── Linux Adapter
```

Each adapter must satisfy the same interface contract.

---

# 57. Cross-Platform Contract Test

Define a common contract:

```text
process.list()
```

Expected conceptual result:

```text
Process {
    pid
    parent_pid
    name
    executable
}
```

The exact OS-specific metadata may differ, but required fields must follow the common contract.

---

# 58. Docker Integration Tests

The complete stack should be testable through Docker Compose.

Expected services may include:

```text
compiler
agent
backend
database
redis
frontend
reverse proxy
```

The exact service names must match the project configuration.

---

# 59. Integration Test

Basic flow:

```text
JOCKY source
     ↓
Compiler
     ↓
IR
     ↓
Agent
     ↓
Evidence
     ↓
Backend
     ↓
Database
     ↓
Detection
     ↓
Dashboard
```

The test passes only if the complete chain succeeds.

---

# 60. End-to-End Test

A complete E2E test should perform:

```text
1. Start services.
2. Create a case.
3. Submit a supported investigation.
4. Compile JOCKY source.
5. Validate IR.
6. Execute against controlled fixture.
7. Produce evidence.
8. Send evidence to backend.
9. Store evidence.
10. Run detection.
11. Generate finding.
12. Calculate risk.
13. Display investigation.
14. Generate report.
15. Verify report integrity.
```

---

# 61. Dashboard Tests

Dashboard tests should verify:

```text
Login
Case list
Case selection
Evidence display
Timeline
Graph
Risk score
Detection findings
Report generation
Error states
Unauthorized access
```

---

# 62. UI/API Consistency

The dashboard should display backend data without changing its semantic meaning.

Example:

```text
Backend:
risk = 85
```

Dashboard:

```text
Risk = 85
```

The frontend must not independently calculate security-sensitive values unless explicitly specified.

---

# 63. Failure Injection

Integration tests should intentionally introduce failures.

Examples:

```text
Database unavailable
Backend unavailable
Agent unavailable
Invalid evidence
Network timeout
Invalid credentials
Malformed IR
Detection rule failure
```

The system should produce controlled errors and recover according to documented behavior.

---

# 64. Recovery Tests

After temporary backend failure:

```text
Agent
  ↓
connection failure
  ↓
retry according to policy
  ↓
backend recovery
  ↓
evidence transmission
```

The system should avoid accidental evidence duplication where the protocol requires idempotency.

---

# 65. Performance Tests

Performance testing should measure:

```text
Compilation time
IR validation time
Evidence processing time
Detection latency
API latency
Database operations
Report generation
```

Performance targets should be established based on actual project requirements rather than arbitrary numbers.

---

# 66. Load Tests

The backend should be tested with:

```text
multiple agents
multiple cases
large evidence sets
concurrent API requests
```

The system should remain stable within documented deployment limits.

---

# 67. Memory Tests

The runtime and backend should be tested against unusually large inputs.

Expected behavior:

```text
Input exceeds limit
       ↓
Controlled rejection
       ↓
Service remains alive
```

---

# 68. Regression Testing

Every fixed bug should result in a regression test where practical.

Workflow:

```text
Bug
 ↓
Fix
 ↓
Regression Test
 ↓
CI
```

The same bug should not silently return later.

---

# 69. Continuous Integration

CI should execute at least:

```text
Formatting
Linting
Unit tests
Compiler tests
IR tests
Security tests
Integration tests
```

Cross-platform jobs should be added where infrastructure permits.

---

# 70. Test Naming

Tests should describe behavior.

Preferred:

```text
reject_unknown_ir_opcode
```

instead of:

```text
test_17
```

Another example:

```text
deny_memory_analysis_without_capability
```

---

# 71. Test Reproducibility

Tests must avoid dependence on:

```text
Current time
Random external network data
User-specific filesystem state
Production services
Uncontrolled internet resources
```

unless the test specifically exists to test those integrations.

---

# 72. Fixture Versioning

Important forensic fixtures should be versioned.

Example:

```text
hollowing-v1.json
hollowing-v2.json
```

Changing a fixture should be treated as a meaningful test change.

---

# 73. Expected Output Versioning

Expected outputs should be updated only when the specification intentionally changes.

Do not update golden files merely to make a failing test pass.

---

# 74. Test Coverage

Coverage should be measured for important components.

Priority areas:

```text
Parser
Semantic analyzer
IR validator
Capability enforcement
Evidence integrity
Agent authentication
Authorization
Detection engine
Backend APIs
```

Coverage percentage alone must not be treated as proof of correctness.

---

# 75. Security Coverage

Security tests must specifically cover the security invariants defined in:

```text
docs/SECURITY_MODEL.md
```

Every security invariant should map to one or more tests.

---

# 76. Security Invariant Matrix

| Security Invariant                | Required Test                |
| --------------------------------- | ---------------------------- |
| Invalid IR never executes         | IR validation test           |
| Capabilities cannot self-escalate | capability test              |
| Arbitrary execution unavailable   | runtime regression test      |
| Evidence integrity preserved      | hash/tamper test             |
| Authorization enforced            | API authorization test       |
| Laboratory isolation              | environment/integration test |
| Security failures fail closed     | denial tests                 |

---

# 77. Test Environment Separation

Tests must not accidentally target production infrastructure.

Test configuration should clearly identify:

```text
development
test
laboratory
production
```

Production credentials must never be used by automated tests.

---

# 78. Secrets in Tests

Never commit:

```text
API keys
passwords
private keys
production tokens
agent credentials
database credentials
```

Use temporary test credentials or mocks.

---

# 79. Test Logging

Tests should provide useful failure information without leaking secrets.

Example:

```text
TEST FAILED

Operation:
    process.list

Expected:
    3 processes

Actual:
    2 processes

Fixture:
    process-set-01
```

---

# 80. Test Result Classification

Use clear statuses:

```text
PASS
FAIL
SKIP
BLOCKED
NOT_APPLICABLE
```

A skipped security test must not silently count as passed.

---

# 81. Definition of Done

A feature is considered complete only when:

```text
✓ Implementation exists
✓ Specification updated
✓ Unit tests exist
✓ Negative tests exist
✓ Security implications reviewed
✓ Integration test exists where applicable
✓ Documentation updated
✓ CI passes
```

---

# 82. Release Gate

A release must not be considered ready when:

```text
Critical security tests fail
IR validation is bypassable
Evidence integrity fails
Authorization is bypassable
Core E2E workflow fails
```

---

# 83. Recommended Test Execution Order

For local development:

```text
1. Format
2. Lint
3. Unit tests
4. Compiler tests
5. IR tests
6. Runtime tests
7. Security tests
8. Backend tests
9. Integration tests
10. E2E tests
```

For CI:

```text
Fast tests
    ↓
Component tests
    ↓
Security tests
    ↓
Integration
    ↓
E2E
```

---

# 84. Developer Workflow

When implementing a feature:

```text
Read specification
      ↓
Write test
      ↓
Implement
      ↓
Run focused test
      ↓
Run related test suite
      ↓
Run security tests
      ↓
Run complete suite
      ↓
Update documentation
      ↓
Commit
```

---

# 85. Controlled-Lab Test Workflow

For a forensic detection scenario:

```text
Select scenario
      ↓
Load synthetic fixture
      ↓
Run supported JOCKY analysis
      ↓
Generate evidence
      ↓
Validate integrity
      ↓
Run detection
      ↓
Inspect finding
      ↓
Verify timeline
      ↓
Verify graph
      ↓
Verify risk
      ↓
Generate report
```

---

# 86. Example Acceptance Test

### Scenario

```text
Detect simulated process hollowing evidence.
```

### Given

```text
testdata/hollowing.json
```

### When

The evidence is processed by the forensic pipeline.

### Then

The system should:

```text
✓ Accept valid evidence
✓ Preserve provenance
✓ Calculate integrity metadata
✓ Identify configured indicators
✓ Create a finding
✓ Associate finding with evidence
✓ Add timeline events
✓ Update investigation risk
✓ Display the finding
✓ Include it in the generated report
```

---

# 87. Example Security Acceptance Test

### Given

A JOCKY program requests an unsupported security-sensitive operation.

### When

The compiler processes the program.

### Then

```text
Compilation fails.
```

And:

```text
✓ No executable operation is generated
✓ No runtime action occurs
✓ An understandable error is returned
✓ The event may be audited where applicable
```

---

# 88. Example Evidence Acceptance Test

### Given

Valid evidence with known content.

### When

It is submitted to the backend.

### Then

```text
✓ Evidence accepted
✓ Hash recorded
✓ Provenance recorded
✓ Case association recorded
✓ Evidence retrievable
```

After modifying the evidence:

```text
✓ Integrity mismatch detected
```

---

# 89. Minimum Viable Test Suite

Before calling the first complete prototype functional, the project must have at least:

```text
5+ lexer tests
5+ parser tests
5+ semantic tests
5+ IR tests
5+ runtime tests
5+ security tests
5+ evidence tests
5+ detection tests
1 cross-platform contract test
1 Docker integration test
1 complete E2E test
```

These numbers are minimums, not targets.

---

# 90. Final Testing Principle

JOCKY should be tested as a security-sensitive system rather than merely as a compiler project.

The central testing chain is:

```text
           SOURCE
              │
              ▼
          COMPILER
              │
              ▼
             IR
              │
        ┌─────┴─────┐
        │ VALIDATE  │
        └─────┬─────┘
              │
       CAPABILITY CHECK
              │
              ▼
           AGENT
              │
              ▼
          EVIDENCE
              │
      INTEGRITY + PROVENANCE
              │
              ▼
          DETECTION
              │
              ▼
          FINDINGS
              │
              ▼
           REPORT
```

Every arrow is a potential failure boundary.

Therefore, every arrow requires tests.

---

# 91. Relationship to Project Documentation

```text
ARCHITECTURE.md
      │
      ├── defines components
      │
LANGUAGE_SPEC.md
      │
      ├── defines language
      │
IR_SPEC.md
      │
      ├── defines IR
      │
FORENSICS_SPEC.md
      │
      ├── defines evidence
      │
SECURITY_MODEL.md
      │
      ├── defines security constraints
      │
TEST_PLAN.md
      │
      └── verifies all of the above
```

Tests must follow the specifications.

When specifications intentionally change, the relevant tests must be updated.

---

# 92. Completion Criteria

The testing system is considered mature when:

```text
✓ Core compiler behavior tested
✓ IR validation tested
✓ Runtime capabilities tested
✓ Security invariants tested
✓ Evidence integrity tested
✓ Detection rules tested
✓ Backend tested
✓ Agent tested
✓ Cross-platform contracts tested
✓ Controlled scenarios reproducible
✓ Complete E2E flow works
✓ CI executes required suites
✓ Regression tests exist for discovered bugs
```

`docs/STATUS.md` must track which of these are currently implemented.
