# JOCKY — Language Specification

**Document:** `docs/LANGUAGE_SPEC.md`
**Project:** JOCKY
**Version:** 1.0
**Status:** Language Definition
**Last Updated:** 2026-08-28

---

# 1. Introduction

JOCKY is a domain-specific language (DSL) for describing authorized computer and network forensic investigations.

The language is designed to allow an investigator to express **what evidence should be collected and analyzed** without requiring the investigator to directly interact with operating-system-specific APIs.

For example:

```jocky
system.info();

process.list();

network.connections();

file.hash("/evidence/sample.exe");
```

The JOCKY compiler converts these statements into an intermediate investigation representation that can eventually be executed by the JOCKY runtime and endpoint agents.

The language therefore acts as the investigator-facing layer of the JOCKY platform.

---

# 2. Design Goals

JOCKY is designed around the following goals.

## 2.1 Simplicity

Common forensic operations should require simple statements.

Instead of writing operating-system-specific code:

```text
Windows API
Linux /proc
WMI
kernel interfaces
etc.
```

the investigator writes:

```jocky
process.list();
```

---

## 2.2 Cross-Platform Semantics

A JOCKY program describes an investigation independently of the endpoint operating system.

The same operation:

```jocky
process.list();
```

may be executed through different platform providers.

```text
                 process.list()
                       │
             ┌─────────┴─────────┐
             ▼                   ▼
        Windows Provider    Linux Provider
             │                   │
             ▼                   ▼
        Windows data        Linux data
             │                   │
             └─────────┬─────────┘
                       ▼
                Common Evidence
```

---

## 2.3 Explainability

JOCKY operations should produce traceable evidence.

An investigator should be able to determine:

```text
JOCKY statement
      ↓
Runtime operation
      ↓
Evidence
      ↓
Detection
      ↓
Finding
```

---

## 2.4 Deterministic Execution

Given the same:

* JOCKY program
* compiler version
* runtime version
* evidence
* configuration

the investigation should produce reproducible results, subject to explicitly documented nondeterministic sources such as timestamps or live endpoint state.

---

## 2.5 Safety

JOCKY is intended for authorized forensic investigation and controlled security research.

The language must not provide operational primitives whose purpose is to:

* disable security controls
* evade endpoint security
* steal credentials
* exploit vulnerable drivers
* establish covert command-and-control
* perform unauthorized persistence
* execute offensive payloads

Security-relevant behaviors may be represented as **evidence, observations, or controlled laboratory scenarios** for detection and analysis.

---

# 3. Program Structure

A JOCKY program consists of one or more statements.

The simplest valid program is:

```jocky
system.info();
```

A program may contain multiple operations:

```jocky
system.info();

process.list();

network.connections();

file.hash("/evidence/sample.exe");
```

Statements are normally terminated by a semicolon.

---

# 4. Comments

JOCKY supports single-line comments.

```jocky
// Collect process information
process.list();
```

Comments are ignored by the compiler.

Future versions may introduce block comments:

```jocky
/*
    Investigation notes
*/
```

but block comments are not part of the initial required language unless explicitly implemented by the grammar.

---

# 5. Identifiers

Identifiers are names used for variables, functions, investigations, and other language constructs.

A valid identifier begins with a letter or underscore and may contain letters, numbers, and underscores.

Examples:

```jocky
processes
network_events
host_info
case_id
```

Invalid examples:

```jocky
123process
network-events
```

Identifiers are case-sensitive.

Therefore:

```jocky
Process
process
PROCESS
```

are different identifiers.

---

# 6. Literals

JOCKY supports the following basic literal types.

## 6.1 Integer

```jocky
123
0
-42
```

---

## 6.2 Floating Point

```jocky
3.14
0.5
```

---

## 6.3 String

Strings are enclosed in double quotes.

```jocky
"C:\\Evidence\\sample.exe"
```

Strings may contain escaped characters.

Common escapes include:

```text
\n
\t
\\
\"
```

---

## 6.4 Boolean

```jocky
true
false
```

---

# 7. Variables

Variables allow results to be referenced later.

Example:

```jocky
processes = process.list();
```

The value returned by `process.list()` is stored in `processes`.

A later operation may use the result:

```jocky
processes = process.list();

filter(processes);
```

The exact type system and supported collection types are defined by the compiler implementation and IR specification.

---

# 8. Statements

JOCKY initially supports the following categories of statements:

```text
Expression statements
Variable assignment
Function calls
Conditional statements
Loop statements
Investigation declarations
Return statements
```

---

# 9. Function Calls

The primary mechanism for invoking forensic operations is the function/member-call syntax.

Example:

```jocky
process.list();
```

Conceptually:

```text
object.method(arguments)
```

The object represents a forensic subsystem.

Examples:

```jocky
process.list();

network.connections();

system.info();
```

---

# 10. Core Forensic Operations

The initial JOCKY language defines several conceptual operation groups.

---

## 10.1 System Operations

System information can be requested using:

```jocky
system.info();
```

Possible evidence includes:

```text
Operating system
Hostname
Architecture
Kernel/version information
Runtime information
System identifiers
```

The exact fields are defined by the forensic evidence specification.

---

## 10.2 Process Operations

Process information can be requested using:

```jocky
process.list();
```

Possible observations include:

```text
Process ID
Parent Process ID
Process name
Executable path
Creation time
User/context information where authorized
```

Additional process analysis operations may be introduced later.

---

## 10.3 File Operations

File analysis can be requested using:

```jocky
file.analyze("/evidence/sample.exe");
```

Hashing can be requested using:

```jocky
file.hash("/evidence/sample.exe");
```

Possible outputs include:

```text
File metadata
Size
Modification timestamps
Cryptographic hashes
File type
Collection metadata
```

---

## 10.4 Network Operations

Network observations can be requested using:

```jocky
network.connections();
```

Possible observations include:

```text
Local address
Remote address
Port
Protocol
Process association where available
Connection state
Timestamp
```

---

## 10.5 Driver Operations

Driver information may be requested using:

```jocky
driver.scan();
```

or an implementation-defined argument form.

The operation is intended to **observe and analyze installed/loaded driver information**.

It must not perform exploitation of vulnerable drivers.

---

## 10.6 Memory Operations

Memory analysis may be requested using a controlled evidence source:

```jocky
memory.analyze("evidence/memory.dump");
```

The operation analyzes available evidence.

It does not imply that JOCKY performs memory-injection or memory-evasion operations.

---

# 11. Investigation Blocks

A complete investigation can group related operations.

Example:

```jocky
investigation "host_scan" {

    system.info();

    process.list();

    network.connections();

}
```

An investigation block provides a logical unit of execution.

It may later be associated with:

```text
Case
Target hosts
Execution policy
Evidence set
Detection configuration
Report
```

---

# 12. Filtering

Investigations often require filtering large evidence sets.

Conceptually:

```jocky
processes = process.list();

filtered = filter(
    processes,
    process.name == "example.exe"
);
```

The exact syntax may evolve as the language specification becomes more mature.

Filtering should ideally be represented in the IR rather than implemented as arbitrary host-language code.

---

# 13. Conditions

JOCKY supports conditional execution.

Example:

```jocky
if (processes.count > 0) {

    report.generate();

}
```

Conditions allow an investigation to react to collected evidence.

---

# 14. Loops

Loops may be used when an operation needs to be applied to multiple evidence objects.

Conceptual example:

```jocky
for (process in processes) {

    process.inspect(process);

}
```

The exact iteration syntax must be defined by the grammar and semantic analyzer before being considered part of the stable language.

---

# 15. Correlation

JOCKY should eventually support explicit correlation operations.

Example:

```jocky
processes = process.list();

connections = network.connections();

correlate(processes, connections);
```

Correlation connects observations that may belong to the same investigation event or incident.

The correlation engine is responsible for producing relationships and findings.

---

# 16. Detection

Detection rules may be applied to collected evidence.

Conceptually:

```jocky
findings = detect(evidence);
```

or:

```jocky
findings = detect(
    evidence,
    "process_anomaly"
);
```

The exact detection-rule language and APIs are specified separately in the forensic and detection architecture.

---

# 17. Reporting

An investigation can request report generation.

Example:

```jocky
report.generate();
```

A report may contain:

```text
Investigation information
Host information
Evidence summary
Timeline
Findings
Correlations
Risk assessment
Evidence integrity information
Detection information
```

---

# 18. Imports

JOCKY may support imports for reusable investigation modules.

Conceptual syntax:

```jocky
import forensic.process;
import forensic.network;
```

Imports should allow investigators to organize larger programs into reusable components.

The compiler must validate that imported modules exist and are compatible with the current language/compiler version.

---

# 19. Functions

JOCKY may support user-defined functions.

Example:

```jocky
function collect_host() {

    system.info();

    process.list();

    network.connections();

}
```

The function can then be invoked:

```jocky
collect_host();
```

Functions should remain deterministic and subject to the same security restrictions as built-in operations.

---

# 20. Types

The language should provide a small type system appropriate for forensic data.

Initial conceptual types include:

```text
int
float
string
bool
list
map
evidence
finding
```

Example:

```jocky
host = system.info();

processes = process.list();

connections = network.connections();
```

The compiler's semantic-analysis stage is responsible for checking type compatibility.

---

# 21. Error Handling

Compiler errors should be clear and actionable.

For example:

```text
ERROR

File: investigation.jocky
Line: 7
Column: 12

Unknown operation:
    process.lsit();

Did you mean:
    process.list();
```

Runtime errors should also contain useful information.

Example:

```text
RUNTIME ERROR

Operation:
    file.hash()

Reason:
    Evidence source unavailable

Host:
    PC-02

Evidence:
    /evidence/sample.exe
```

The system should distinguish:

```text
Syntax Error
Semantic Error
Compilation Error
Runtime Error
Collection Error
Evidence Error
Network Error
```

---

# 22. Compilation Model

The intended JOCKY compilation pipeline is:

```text
JOCKY Source
     │
     ▼
Lexical Analysis
     │
     ▼
Parsing
     │
     ▼
Abstract Syntax Tree
     │
     ▼
Semantic Analysis
     │
     ▼
JOCKY IR
     │
     ▼
Backend / LLVM
     │
     ▼
Runtime-compatible Output
```

Each stage has a distinct responsibility.

---

# 23. Lexical Grammar

At a high level, JOCKY source consists of:

```text
program
statement*
```

A simplified conceptual grammar is:

```text
program
    : statement*
    ;

statement
    : expression_statement
    | assignment
    | investigation
    | if_statement
    | loop_statement
    | return_statement
    ;

expression_statement
    : expression ';'
    ;

assignment
    : IDENTIFIER '=' expression ';'
    ;

expression
    : literal
    | identifier
    | function_call
    | member_call
    | binary_expression
    ;
```

The authoritative machine-readable grammar is:

```text
grammar/jocky.g4
```

The grammar file and this document must remain synchronized.

---

# 24. Reserved Words

The following words are reserved or may become reserved as the language evolves:

```text
if
else
for
while
function
return
import
investigation
true
false
```

Reserved words cannot normally be used as ordinary identifiers.

---

# 25. Built-in Namespaces

The initial language uses namespaces to organize forensic capabilities.

```text
system
process
file
network
driver
memory
report
```

The namespace design prevents unrelated operations from being mixed into one global function namespace.

For example:

```jocky
process.list();
network.connections();
file.hash("sample.exe");
```

is preferable to:

```jocky
list_processes();
get_connections();
hash_file();
```

because the former makes the forensic domain explicit.

---

# 26. Evidence-Oriented Semantics

A key property of JOCKY is that forensic operations return **evidence or evidence references**, not merely console output.

For example:

```jocky
processes = process.list();
```

should conceptually produce:

```text
Evidence Collection
       │
       ├── Process #1
       ├── Process #2
       ├── Process #3
       └── ...
```

The evidence is then available to later operations.

This enables:

```text
Collection
   ↓
Filtering
   ↓
Analysis
   ↓
Correlation
   ↓
Detection
   ↓
Reporting
```

---

# 27. Platform Independence

The JOCKY language must not expose operating-system-specific implementation details unless explicitly required for an investigation.

Preferred:

```jocky
process.list();
```

Avoid language-level dependencies such as:

```jocky
windows.toolhelp32.processes();
```

or:

```jocky
linux.procfs.processes();
```

Those implementation details belong inside platform providers.

---

# 28. Controlled Laboratory Semantics

JOCKY supports controlled laboratory scenarios through evidence sources.

For example:

```jocky
evidence.load("lab/process_anomaly.json");
```

The laboratory can provide synthetic observations representing security scenarios.

These observations are then treated like ordinary forensic evidence:

```text
Lab Evidence
     ↓
Normalization
     ↓
Detection
     ↓
Correlation
     ↓
Finding
```

The language does not require the corresponding offensive behavior to be executed.

---

# 29. Compiler Security Restrictions

The compiler and runtime should enforce a capability model.

A JOCKY program should only be able to invoke operations explicitly supported by the runtime.

Unknown or unsupported operations must fail during compilation or execution.

For example:

```jocky
edr.disable();
```

must not become a valid built-in operation.

Likewise, unsupported operations must not be dynamically introduced through arbitrary native code execution.

---

# 30. Versioning

JOCKY programs should be versionable.

Future programs may begin with:

```jocky
version 1;
```

The compiler can then determine which language features and semantics apply.

Language changes should follow:

```text
Major version
    → breaking language changes

Minor version
    → compatible features

Patch version
    → corrections/clarifications
```

---

# 31. Compatibility

JOCKY compatibility consists of three layers.

```text
Language Compatibility
        │
        ▼
Compiler Compatibility
        │
        ▼
Runtime Compatibility
```

A program is considered compatible when:

1. its syntax is accepted by the compiler,
2. its semantics are supported by the compiler version,
3. the required runtime capabilities exist on the target environment.

---

# 32. Example Investigation

A conceptual investigation may look like:

```jocky
investigation "endpoint_baseline" {

    system.info();

    processes = process.list();

    connections = network.connections();

    correlate(
        processes,
        connections
    );

    report.generate();

}
```

The resulting execution flow is:

```text
JOCKY Program
      │
      ▼
Compiler
      │
      ▼
Investigation Plan
      │
      ▼
Endpoint Agent
      │
      ▼
Evidence
      │
      ▼
Detection
      │
      ▼
Correlation
      │
      ▼
Findings
      │
      ▼
Report
```

---

# 33. Example Controlled Investigation

A controlled laboratory investigation could use:

```jocky
investigation "lab_process_anomaly" {

    evidence.load(
        "testdata/process_anomaly.json"
    );

    findings = detect();

    correlate(findings);

    report.generate();

}
```

The evidence source represents the laboratory scenario.

The resulting findings should identify the relevant indicators without requiring the system to execute an offensive technique.

---

# 34. Language Design Rule

The following distinction is fundamental:

```text
JOCKY describes an investigation.
JOCKY Runtime performs authorized collection.
Detection analyzes evidence.
Correlation connects evidence.
Dashboard presents results.
```

JOCKY itself is **not intended to be a general-purpose operating-system control language**.

---

# 35. Implementation Status Boundary

This document defines the **target language contract**.

It does not imply that every feature described here has already been implemented.

Implementation status must be tracked separately in:

```text
docs/STATUS.md
```

The machine-readable grammar must be treated as the implementation source of truth for currently supported syntax.

When a feature is documented here but not yet implemented, it must be marked as planned in `STATUS.md`.

---

# 36. Language Evolution

Language evolution should follow this order:

```text
Grammar
   ↓
Parser
   ↓
AST
   ↓
Semantic Rules
   ↓
IR Representation
   ↓
Runtime Capability
   ↓
Tests
   ↓
Documentation
```

A new language feature should not be considered complete until all applicable layers support it.

---

# 37. Design Philosophy

JOCKY follows a simple philosophy:

> **Investigators should describe the evidence they need, not the operating-system mechanisms required to obtain it.**

Therefore:

```text
Investigator
     │
     │ "What do I want to investigate?"
     ▼
    JOCKY
     │
     │ "How is this collected here?"
     ▼
   Runtime
     │
     ▼
 Platform Provider
     │
     ▼
 Operating System
```

This separation is the foundation of JOCKY's portability, extensibility, and maintainability.
