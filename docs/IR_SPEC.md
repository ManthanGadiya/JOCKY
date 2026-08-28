# JOCKY — Intermediate Representation Specification

**Document:** `docs/IR_SPEC.md`
**Project:** JOCKY
**Version:** 1.0
**Status:** IR Definition
**Last Updated:** 2026-08-28

---

# 1. Purpose

JOCKY IR (Intermediate Representation) is the compiler-level representation between the JOCKY source language and the execution backend.

Its primary purpose is to separate:

```text
JOCKY Language
```

from:

```text
Runtime / LLVM / Platform Implementation
```

The IR provides a stable intermediate contract through which the compiler can transform high-level forensic operations into executable investigation plans.

The intended compilation pipeline is:

```text
┌─────────────────┐
│  JOCKY Source   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│      Lexer      │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│     Parser      │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│      AST        │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Semantic Analysis│
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│    JOCKY IR     │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Backend / LLVM  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ JOCKY Runtime   │
└─────────────────┘
```

---

# 2. IR Design Goals

JOCKY IR must satisfy the following requirements.

## 2.1 Platform Independence

IR should describe the intended investigation operation rather than directly encoding operating-system APIs.

For example:

```text
PROCESS_LIST
```

is preferred over:

```text
Windows.Toolhelp32Snapshot()
```

or:

```text
Linux.procfs.read()
```

Platform-specific behavior belongs to the runtime provider layer.

---

## 2.2 Deterministic Structure

Equivalent JOCKY programs should produce structurally equivalent IR.

For example:

```jocky
process.list();
```

should always produce the same logical IR operation.

---

## 2.3 Explicit Operations

Every IR instruction should represent a well-defined operation.

An instruction should not hide arbitrary host-language execution.

---

## 2.4 Serializable Representation

IR should be representable in a serialized form for:

* debugging
* testing
* caching
* compiler inspection
* investigation reproducibility

A JSON representation may be used for development and testing.

---

## 2.5 Runtime Compatibility

The runtime should be able to consume the IR without requiring the runtime to understand JOCKY source syntax.

---

# 3. IR Layers

JOCKY uses multiple compiler representations.

```text
Source Code
     │
     ▼
Tokens
     │
     ▼
AST
     │
     ▼
Semantic Model
     │
     ▼
JOCKY IR
     │
     ▼
Backend IR / LLVM IR
```

Each representation has a different purpose.

---

# 4. AST vs IR

The AST represents **how the source program is written**.

The IR represents **what the investigation should do**.

Example JOCKY source:

```jocky
process.list();
```

Possible AST:

```text
CallExpression
├── Namespace: process
├── Function: list
└── Arguments: []
```

Possible JOCKY IR:

```text
PROCESS_LIST
```

The IR removes source-language details that are no longer required during execution.

---

# 5. IR Module

The top-level IR object is an `IRModule`.

Conceptually:

```text
IRModule
├── Metadata
├── Version
├── Capabilities
├── Constants
├── Functions
├── Investigations
└── Entry Point
```

Example:

```text
IRModule {
    version: 1,
    entry: "main",
    functions: [...],
    investigations: [...]
}
```

---

# 6. IR Version

Every IR module must contain an IR version.

Example:

```text
IR_VERSION = 1
```

The version exists so that future compiler/runtime versions can determine whether an IR module is compatible.

An incompatible version must produce an explicit error.

Example:

```text
IR Compatibility Error

Required IR version: 2
Runtime supports: 1
```

---

# 7. IR Metadata

An IR module may contain metadata such as:

```text
compiler_version
language_version
source_hash
build_timestamp
module_id
```

Example:

```text
metadata {
    language_version = "1.0";
    compiler_version = "0.1.0";
    source_hash = "...";
}
```

Metadata should not alter the logical semantics of an investigation.

---

# 8. IR Types

The initial IR type system consists of:

```text
void
bool
int
float
string
list
map
evidence
evidence_set
finding
```

---

## 8.1 Void

Represents an operation with no return value.

Example:

```text
REPORT_GENERATE
```

---

## 8.2 Boolean

Represents:

```text
true
false
```

---

## 8.3 Integer

Represents signed integer values.

Example:

```text
123
-5
```

---

## 8.4 Float

Represents floating-point values.

Example:

```text
3.14
```

---

## 8.5 String

Represents textual values.

Example:

```text
"sample.exe"
```

---

## 8.6 List

Represents an ordered collection.

Example:

```text
list<process>
```

---

## 8.7 Map

Represents key-value data.

Example:

```text
map<string, string>
```

---

## 8.8 Evidence

Represents an individual forensic observation or evidence object.

---

## 8.9 Evidence Set

Represents a collection of related evidence objects.

Example:

```text
evidence_set<process>
```

---

## 8.10 Finding

Represents a detection result derived from evidence.

---

# 9. SSA-Inspired Value Model

JOCKY IR should use an SSA-inspired value model where operations produce named values.

Example:

```text
%processes = process.list()
```

Conceptually:

```text
%0 = PROCESS_LIST
```

The result `%0` can then be consumed by another operation.

Example:

```text
%0 = PROCESS_LIST
%1 = FILTER %0
%2 = DETECT %1
```

This makes data dependencies explicit.

---

# 10. Instructions

An IR instruction contains:

```text
opcode
operands
result
type
metadata
```

Conceptual representation:

```text
Instruction {
    opcode
    operands[]
    result
    result_type
    metadata
}
```

Example:

```text
%0 = PROCESS_LIST : evidence_set<process>
```

---

# 11. Core Instruction Categories

JOCKY IR instructions are grouped into:

```text
System Instructions
Process Instructions
File Instructions
Network Instructions
Driver Instructions
Memory Instructions
Evidence Instructions
Detection Instructions
Correlation Instructions
Control-Flow Instructions
Reporting Instructions
```

---

# 12. System Instructions

## 12.1 SYSTEM_INFO

Collects authorized system information.

Syntax:

```text
%0 = SYSTEM_INFO
```

Result:

```text
evidence
```

Possible evidence includes:

```text
Operating system
Hostname
Architecture
Version information
System metadata
```

---

# 13. Process Instructions

## 13.1 PROCESS_LIST

Collects process information.

```text
%0 = PROCESS_LIST
```

Result:

```text
evidence_set<process>
```

---

## 13.2 PROCESS_INSPECT

Inspects a selected process evidence object.

```text
%1 = PROCESS_INSPECT %0
```

The exact supported fields are defined by the forensic specification.

---

# 14. File Instructions

## 14.1 FILE_HASH

Calculates a cryptographic hash for an authorized evidence source.

```text
%0 = FILE_HASH "sample.exe"
```

Result:

```text
string
```

The supported algorithms are defined by the forensic specification.

---

## 14.2 FILE_ANALYZE

Analyzes authorized file evidence.

```text
%0 = FILE_ANALYZE "sample.exe"
```

Result:

```text
evidence
```

---

# 15. Network Instructions

## 15.1 NETWORK_CONNECTIONS

Collects authorized network connection observations.

```text
%0 = NETWORK_CONNECTIONS
```

Result:

```text
evidence_set<network_connection>
```

---

# 16. Driver Instructions

## 16.1 DRIVER_SCAN

Collects driver-related observations.

```text
%0 = DRIVER_SCAN
```

Result:

```text
evidence_set<driver>
```

The operation is observational.

It must not:

* exploit drivers
* load arbitrary drivers
* disable security controls
* modify kernel security mechanisms

---

# 17. Memory Instructions

## 17.1 MEMORY_ANALYZE

Analyzes an authorized memory evidence source.

```text
%0 = MEMORY_ANALYZE "memory.dump"
```

Result:

```text
evidence
```

The operation is intended for forensic analysis of evidence.

It does not represent memory injection or execution.

---

# 18. Evidence Instructions

Evidence instructions operate on previously collected or imported evidence.

---

## 18.1 EVIDENCE_LOAD

Loads controlled or authorized evidence.

```text
%0 = EVIDENCE_LOAD "testdata/process_anomaly.json"
```

Result:

```text
evidence_set
```

---

## 18.2 EVIDENCE_FILTER

Filters evidence.

```text
%1 = EVIDENCE_FILTER %0 %condition
```

Example:

```text
%0 = PROCESS_LIST
%1 = EVIDENCE_FILTER %0 process.name == "example.exe"
```

---

# 19. Detection Instructions

## 19.1 DETECT

Runs supported detection logic against evidence.

```text
%0 = DETECT %evidence
```

Result:

```text
evidence_set<finding>
```

---

## 19.2 DETECT_RULE

Runs a specific detection rule.

```text
%0 = DETECT_RULE %evidence "process_anomaly"
```

The rule identifier must resolve to a registered rule.

Unknown rules must produce an explicit error.

---

# 20. Correlation Instructions

## 20.1 CORRELATE

Correlates related evidence.

```text
%0 = CORRELATE %evidence1 %evidence2
```

Result:

```text
evidence_set
```

---

## 20.2 TIMELINE

Constructs a chronological representation.

```text
%0 = TIMELINE %evidence
```

Result:

```text
timeline
```

---

## 20.3 GRAPH

Constructs a relationship graph.

```text
%0 = GRAPH %evidence
```

Result:

```text
graph
```

---

# 21. Risk Instructions

## 21.1 RISK_SCORE

Calculates an investigation risk score from findings.

```text
%0 = RISK_SCORE %findings
```

Result:

```text
float
```

The risk score represents an analytical assessment.

It must not be interpreted as proof of compromise.

---

# 22. Reporting Instructions

## 22.1 REPORT_GENERATE

Generates a report from investigation results.

```text
REPORT_GENERATE %investigation
```

Result:

```text
void
```

---

# 23. Control Flow

JOCKY IR may represent control flow using basic blocks.

Example:

```text
entry:
    %0 = PROCESS_LIST
    %1 = COUNT %0
    BRANCH %1 > 0, investigate, finish

investigate:
    %2 = DETECT %0
    JUMP finish

finish:
    REPORT_GENERATE
```

---

# 24. Basic Blocks

A basic block contains a sequence of instructions with:

* one entry point
* one terminating control-flow instruction

Example:

```text
entry:
    %0 = SYSTEM_INFO
    %1 = PROCESS_LIST
    JUMP analyze

analyze:
    %2 = DETECT %1
    JUMP report

report:
    REPORT_GENERATE
    RETURN
```

---

# 25. Functions

IR functions provide reusable executable units.

Conceptual representation:

```text
function @collect_host() {

entry:
    %0 = SYSTEM_INFO
    %1 = PROCESS_LIST
    %2 = NETWORK_CONNECTIONS
    RETURN

}
```

---

# 26. Entry Point

An IR module should have a defined entry point.

Example:

```text
entry = "main"
```

The entry function begins execution of the investigation.

---

# 27. Investigation Representation

An investigation can be represented as a specialized IR function with investigation metadata.

Example:

```text
investigation @endpoint_scan {

entry:
    %0 = SYSTEM_INFO
    %1 = PROCESS_LIST
    %2 = NETWORK_CONNECTIONS
    %3 = CORRELATE %1 %2
    %4 = DETECT %3
    REPORT_GENERATE %4
    RETURN

}
```

---

# 28. Capabilities

Every investigation operation should map to an explicit capability.

Example:

```text
SYSTEM_INFO          → system.read
PROCESS_LIST         → process.read
FILE_HASH            → file.hash
NETWORK_CONNECTIONS  → network.read
DRIVER_SCAN          → driver.read
MEMORY_ANALYZE       → memory.analyze
```

Capabilities provide a security boundary between the compiler, runtime, and endpoint agent.

An operation requiring an unavailable capability must fail safely.

---

# 29. Capability Validation

Before execution, the runtime should validate:

```text
Requested Operation
        │
        ▼
Required Capability
        │
        ▼
Agent Policy
        │
        ├── Allowed → Execute
        │
        └── Denied  → Reject
```

Example:

```text
Operation:
    DRIVER_SCAN

Required capability:
    driver.read

Agent policy:
    denied

Result:
    EXECUTION_REJECTED
```

---

# 30. Source Mapping

IR instructions should optionally retain source-location metadata.

Example:

```text
%0 = PROCESS_LIST
    source_file = "investigation.jocky"
    line = 5
    column = 5
```

This allows runtime errors to be mapped back to JOCKY source.

Example:

```text
Runtime Error

Operation:
    process.list()

Source:
    investigation.jocky:5:5
```

---

# 31. Evidence Provenance

Evidence-producing IR instructions should preserve provenance information.

Conceptually:

```text
IR Instruction
      │
      ▼
Runtime Operation
      │
      ▼
Evidence
      │
      ├── Investigation ID
      ├── Host ID
      ├── Operation
      ├── Timestamp
      └── Source IR instruction
```

This allows findings to be traced back to their originating investigation operation.

---

# 32. IR Serialization

A JSON representation may be used for debugging.

Example:

```json
{
  "version": 1,
  "entry": "main",
  "instructions": [
    {
      "opcode": "PROCESS_LIST",
      "result": "%0",
      "type": "evidence_set<process>"
    },
    {
      "opcode": "NETWORK_CONNECTIONS",
      "result": "%1",
      "type": "evidence_set<network_connection>"
    }
  ]
}
```

The JSON representation is primarily intended for:

* testing
* debugging
* inspection
* tooling

It does not necessarily define the binary execution format.

---

# 33. IR Validation

Before an IR module reaches the backend, it should pass validation.

The validator should check:

```text
IR version
Instruction validity
Operand count
Operand types
Result types
Referenced values
Control-flow correctness
Capability declarations
Entry point
```

Invalid IR must not be executed.

Example:

```text
IR VALIDATION ERROR

Instruction:
    FILE_HASH

Expected operand:
    string

Received:
    evidence_set<process>
```

---

# 34. IR Optimization

Optimization should occur only after semantic correctness is established.

Potential safe optimizations include:

```text
Constant folding
Dead instruction elimination
Duplicate metadata elimination
Common subexpression elimination
Redundant operation elimination
```

Forensic semantics must never be changed by optimization.

For example, an optimization must not remove an evidence-collection operation merely because its result is not used if collection itself is considered an auditable investigation action.

---

# 35. Backend Lowering

JOCKY IR is lowered into the execution backend.

Conceptually:

```text
JOCKY IR
   │
   ▼
Lowering
   │
   ▼
Runtime Calls / LLVM IR
   │
   ▼
Executable Investigation
```

Example:

```text
JOCKY IR:

%0 = PROCESS_LIST
```

may lower conceptually to:

```text
call @jocky_runtime_process_list()
```

The actual runtime ABI is defined by the implementation.

---

# 36. Runtime ABI Boundary

The IR should communicate with the runtime through a defined ABI/interface.

Conceptually:

```text
Compiler
   │
   │ JOCKY IR / lowered representation
   ▼
Runtime ABI
   │
   ▼
Runtime
   │
   ▼
Platform Provider
```

The runtime ABI should expose only supported forensic capabilities.

It should not expose arbitrary native execution.

---

# 37. Error Model

IR-related failures should be categorized.

```text
IR_PARSE_ERROR
IR_VALIDATION_ERROR
IR_TYPE_ERROR
IR_VERSION_ERROR
IR_CAPABILITY_ERROR
IR_LOWERING_ERROR
RUNTIME_EXECUTION_ERROR
```

Errors should contain enough metadata for debugging.

---

# 38. Security Constraints

JOCKY IR must not provide unrestricted native execution.

The IR instruction set is intentionally closed.

Only registered opcodes may be executed.

Unknown instructions must be rejected.

For example:

```text
UNKNOWN_OPCODE "EXECUTE_NATIVE"
```

must result in:

```text
IR_VALIDATION_ERROR
```

The runtime must not interpret arbitrary strings as executable machine code.

---

# 39. Controlled Laboratory Support

The IR supports controlled laboratory investigations through evidence-loading instructions.

Example:

```text
%0 = EVIDENCE_LOAD "testdata/hollowing.json"
%1 = DETECT %0
%2 = CORRELATE %1
REPORT_GENERATE %2
```

The laboratory evidence represents observations for testing detection and correlation.

The IR does not need to implement the underlying offensive technique that the evidence represents.

---

# 40. Example: Simple Investigation

JOCKY source:

```jocky
system.info();

process.list();
```

Conceptual AST:

```text
Call(system.info)
Call(process.list)
```

JOCKY IR:

```text
function @main {

entry:
    %0 = SYSTEM_INFO
    %1 = PROCESS_LIST
    RETURN
}
```

---

# 41. Example: Evidence Pipeline

Source:

```jocky
processes = process.list();

findings = detect(processes);

report.generate();
```

IR:

```text
function @main {

entry:
    %0 = PROCESS_LIST
    %1 = DETECT %0
    REPORT_GENERATE %1
    RETURN
}
```

Data flow:

```text
PROCESS_LIST
     │
     ▼
    %0
     │
     ▼
   DETECT
     │
     ▼
    %1
     │
     ▼
REPORT_GENERATE
```

---

# 42. Example: Controlled Laboratory

Source:

```jocky
evidence = evidence.load(
    "testdata/process_anomaly.json"
);

findings = detect(evidence);

timeline = timeline(findings);

report.generate(findings);
```

Conceptual IR:

```text
function @main {

entry:
    %0 = EVIDENCE_LOAD "testdata/process_anomaly.json"
    %1 = DETECT %0
    %2 = TIMELINE %1
    REPORT_GENERATE %1
    RETURN
}
```

---

# 43. IR Execution Model

The runtime executes IR according to data dependencies.

Conceptually:

```text
             IR Module
                 │
                 ▼
          Validate IR
                 │
                 ▼
          Check Capabilities
                 │
                 ▼
          Execute Instructions
                 │
                 ▼
         Platform Providers
                 │
                 ▼
             Evidence
                 │
                 ▼
        Detection/Correlation
```

---

# 44. IR Immutability

Once an investigation begins execution, the submitted IR should be treated as immutable.

Any generated results should be stored separately.

```text
Investigation
├── Source
├── IR
├── Execution
│   ├── Evidence
│   ├── Findings
│   └── Logs
└── Report
```

This improves reproducibility and auditability.

---

# 45. Reproducibility Metadata

An executed investigation should retain:

```text
JOCKY source hash
IR hash
Compiler version
IR version
Runtime version
Agent version
Rule versions
Configuration
Execution timestamp
Target host
```

This metadata allows investigators to understand the exact software state that produced a result.

---

# 46. IR Testing

Every IR instruction must have tests covering:

```text
Valid construction
Invalid operands
Invalid types
Invalid capabilities
Serialization
Deserialization
Validation
Lowering
Runtime behavior
Error handling
```

A new instruction should not be considered complete until its corresponding tests exist.

---

# 47. Implementation Source of Truth

The following files should remain synchronized:

```text
Language grammar
      ↕
AST definitions
      ↕
Semantic analyzer
      ↕
IR definitions
      ↕
IR validator
      ↕
Backend
      ↕
Runtime ABI
      ↕
Tests
```

This document describes the intended IR contract.

The actual implementation source of truth is the compiler's IR definitions and validator.

---

# 48. Relationship to Other Specifications

```text
ARCHITECTURE.md
        │
        ▼
Overall system
        │
        ├───────────────┐
        ▼               ▼
LANGUAGE_SPEC.md    IR_SPEC.md
        │               │
        ▼               ▼
Source language      Compiler IR
        │               │
        └───────┬───────┘
                ▼
        FORENSICS_SPEC.md
                │
                ▼
        Evidence semantics
```

The documents have distinct responsibilities:

| Document            | Responsibility                       |
| ------------------- | ------------------------------------ |
| `ARCHITECTURE.md`   | System architecture                  |
| `LANGUAGE_SPEC.md`  | JOCKY syntax and semantics           |
| `IR_SPEC.md`        | Compiler intermediate representation |
| `FORENSICS_SPEC.md` | Evidence and forensic semantics      |
| `SECURITY_MODEL.md` | Security boundaries                  |
| `TEST_PLAN.md`      | Verification strategy                |
| `ROADMAP.md`        | Development sequence                 |
| `DESIGN.md`         | Detailed engineering decisions       |
| `STATUS.md`         | Current implementation state         |
| `TEAMMATES.md`      | Team responsibilities                |
| `AGENTS.md`         | Coding-agent operating instructions  |

---

# 49. Core Principle

The most important IR design principle is:

> **JOCKY IR represents an authorized forensic investigation as a typed, validated, capability-aware sequence of operations that can be lowered to the runtime without exposing arbitrary native execution.**

The resulting compiler architecture is:

```text
                JOCKY
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
        ┌─────────┴─────────┐
        ▼                   ▼
     Validator          Debug/JSON
        │
        ▼
     Lowering
        │
        ▼
    Runtime ABI
        │
        ▼
 Platform Provider
        │
        ▼
     Evidence
```

This IR boundary is the foundation that allows the language, compiler, runtime, and endpoint agents to evolve independently.
