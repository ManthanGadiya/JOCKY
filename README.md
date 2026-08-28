# JOCKY

### A Defensive Forensic Investigation & Analysis Platform

> **JOCKY** is a controlled, defensive security research platform for collecting, normalizing, analyzing, correlating, and visualizing endpoint forensic evidence through a purpose-built domain-specific language (DSL).

---

## ⚠️ Project Scope

JOCKY is designed for:

* Digital forensics
* Endpoint investigation
* Security research
* Threat detection
* Evidence analysis
* Controlled security laboratories
* Reproducible forensic experiments
* Defensive security education

JOCKY is **not intended to be an operational malware framework**.

The project deliberately avoids implementing functionality whose primary purpose is:

* EDR/AV evasion
* Security-control disabling
* Credential theft
* Persistence
* Covert command-and-control
* Privilege escalation
* Kernel security bypass
* Malware deployment
* Real-world exploit delivery

Security behaviors that need to be studied are represented through **synthetic telemetry, benign fixtures, controlled simulations, and replayable laboratory scenarios**.

---

# 🎯 Problem

Modern endpoint investigations generate enormous amounts of heterogeneous evidence.

An investigation may involve:

```text
Processes
Files
Network connections
Memory-related observations
Drivers
System information
Execution events
Parent/child relationships
Hashes
Timestamps
Security findings
```

The challenge is not simply collecting this information.

The difficult part is:

```text
Collect
   ↓
Normalize
   ↓
Preserve integrity
   ↓
Correlate
   ↓
Detect
   ↓
Investigate
   ↓
Explain
   ↓
Report
```

JOCKY aims to provide a unified platform for this workflow.

---

# 💡 What Makes JOCKY Different?

JOCKY combines several concepts into one system:

### 1. Forensic DSL

Investigators can express collection and analysis workflows using a purpose-built language:

```jocky
system.info();

process.list();

file.hash("sample.exe");

network.connections();
```

The goal is to provide a higher-level forensic interface instead of requiring investigators to directly implement platform-specific collection logic.

---

### 2. Compiler Architecture

JOCKY programs are processed through a compiler pipeline:

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
Runtime
```

This allows language-level security policies and validation to be enforced before execution.

---

### 3. Capability-Based Execution

JOCKY operations are explicitly associated with capabilities.

The runtime should not simply execute arbitrary instructions supplied by a script.

Instead:

```text
JOCKY Program
      ↓
Requested Capability
      ↓
Validation
      ↓
Authorized Operation
      ↓
Forensic Result
```

Unknown or unauthorized operations should fail closed.

---

### 4. Canonical Evidence

Evidence from different sources is normalized into a common representation.

Conceptually:

```text
Windows Adapter ─┐
                 │
Linux Adapter ───┼──→ Evidence Model
                 │
Synthetic Data ──┘
```

This allows downstream detection and investigation logic to operate on a consistent data model.

---

### 5. Investigation-Centric UI

The dashboard is intended to transform raw evidence into an investigation view:

```text
Evidence
   │
   ├── Timeline
   │
   ├── Process Relationships
   │
   ├── Findings
   │
   ├── Risk
   │
   └── Investigation Graph
```

The objective is to help an investigator understand **what happened**, rather than simply displaying raw logs.

---

# 🏗️ Architecture

High-level architecture:

```text
                       ┌──────────────────────┐
                       │     JOCKY Script     │
                       │       (.jocky)       │
                       └──────────┬───────────┘
                                  │
                                  ▼
                       ┌──────────────────────┐
                       │       Compiler       │
                       │ Lexer / Parser / AST │
                       │ Semantic Validation  │
                       └──────────┬───────────┘
                                  │
                                  ▼
                       ┌──────────────────────┐
                       │     JOCKY IR         │
                       │ Validated + Versioned│
                       └──────────┬───────────┘
                                  │
                                  ▼
                       ┌──────────────────────┐
                       │       Runtime        │
                       │ Capability Enforcement│
                       └──────────┬───────────┘
                                  │
                                  ▼
                       ┌──────────────────────┐
                       │    Forensic Agent    │
                       └──────────┬───────────┘
                                  │
                    ┌─────────────┴─────────────┐
                    ▼                           ▼
             Platform Adapter            Synthetic Fixture
                    │                           │
                    └─────────────┬─────────────┘
                                  ▼
                       ┌──────────────────────┐
                       │  Evidence Pipeline   │
                       │ Normalize + Integrity│
                       └──────────┬───────────┘
                                  │
                                  ▼
                       ┌──────────────────────┐
                       │       Backend        │
                       │ API / Cases / Storage │
                       └──────────┬───────────┘
                                  │
                     ┌────────────┴────────────┐
                     ▼                         ▼
              Detection Engine           Evidence Store
                     │
                     ▼
              ┌───────────────┐
              │ Investigation │
              │ Graph/Timeline│
              │ Risk/Findings │
              └───────┬───────┘
                      │
                      ▼
              ┌───────────────┐
              │   Dashboard   │
              └───────────────┘
```

For the detailed architecture, see:

* [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
* [`docs/DESIGN.md`](docs/DESIGN.md)

---

# 🧩 Project Components

| Component         | Responsibility                        |
| ----------------- | ------------------------------------- |
| JOCKY Language    | Forensic investigation DSL            |
| Compiler          | Source → AST → validated IR           |
| IR                | Contract between compiler and runtime |
| Runtime           | Executes authorized operations        |
| Agent             | Endpoint/fixture evidence collection  |
| Forensic Adapters | Platform-specific evidence providers  |
| Evidence Pipeline | Normalization and integrity           |
| Backend           | Cases, evidence, APIs and persistence |
| Detection Engine  | Rules, correlation and findings       |
| Dashboard         | Investigation visualization           |
| Report Engine     | Investigation reporting               |
| Controlled Lab    | Reproducible security scenarios       |

---

# 📁 Repository Structure

```text
JOCKY/
│
├── AGENTS.md
├── README.md
├── CHANGELOG.md
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
│   └── TEAMMATES.md
│
├── compiler/
│   └── ...
│
├── runtime/
│   └── ...
│
├── agent/
│   └── ...
│
├── backend/
│   └── ...
│
├── frontend/
│   └── ...
│
├── testdata/
│   └── ...
│
├── tests/
│   └── ...
│
└── docker-compose.yml
```

The exact source tree may evolve during development.

---

# 📝 JOCKY Language

A JOCKY program describes authorized forensic operations.

Example:

```jocky
system.info();

process.list();

file.hash("sample.exe");

network.connections();
```

The language is intentionally designed around **forensic intent**, rather than unrestricted system execution.

Detailed syntax and semantics are defined in:

[`docs/LANGUAGE_SPEC.md`](docs/LANGUAGE_SPEC.md)

---

# 🔐 Security Model

Security is a core architectural requirement.

JOCKY follows a fail-closed model:

```text
Input
  ↓
Parse
  ↓
Validate
  ↓
Authorize
  ↓
Execute
```

Malformed or unauthorized input should not silently continue to execution.

The security model covers:

* Capability boundaries
* Input validation
* IR validation
* Runtime authorization
* Evidence integrity
* Authentication
* Authorization
* Auditability
* Controlled laboratory operation

See:

[`docs/SECURITY_MODEL.md`](docs/SECURITY_MODEL.md)

---

# 🔬 Controlled Laboratory

JOCKY can use deterministic forensic fixtures to reproduce investigation scenarios.

Example:

```text
Synthetic Event
      ↓
Agent
      ↓
Evidence
      ↓
Detection
      ↓
Finding
      ↓
Dashboard
```

A laboratory fixture might represent:

```text
Process relationship anomaly
Driver-load observation
Suspicious file activity
Network connection anomaly
Timeline correlation
```

without requiring the project to implement real malware behavior.

This makes experiments:

* Reproducible
* Safe
* Testable
* Demonstrable
* Suitable for development

---

# 🚀 Quick Start

> **Current Status:** Audit complete 2026-08-28. Host compiler and backend API are **verified** without Docker. Docker stack and platform support are **not yet verified** on this host. Treat `docs/STATUS.md` as the authoritative source.

## Prerequisites

Recommended development environment:

```text
Git
Docker + Docker Compose (for full stack — LLVM/ANTLR run inside image, no host install)
WSL2 + Ubuntu-24.04 (Windows) or Linux host
Python 3.11+ (for host-verified fallback paths: tools/jockyc.py + backend TestClient)
VS Code
```

Verify (host, no Docker needed for core checks):

```bash
python --version          # 3.11+
python -c "import fastapi; print(fastapi.__version__)"
git --version
# Docker is optional for host-verified path; required for full stack:
docker --version
docker compose version
```

---

## 1. Clone the Repository

```bash
git clone <repository-url>
cd JOCKY   # on this machine: D:\SIH
```

---

## 2a. Host-Verified Path (No Docker — Proves Point 1+2)

Same IR logic as `jocky/src/IRGen.cpp`, no LLVM install needed:

```bash
python tools/jockyc.py examples/test.jocky -o build/a.ll --seed 1
python tools/jockyc.py examples/test.jocky --polymorphic -o build/b.ll --seed 2
python tools/jockyc.py examples/test.jocky --polymorphic -o build/c.ll --seed 3
# Windows: certutil -hashfile build\a.ll SHA256  (3 hashes must differ)
# Linux:   sha256sum build/*.ll
python -m pytest  # (once tests exist — currently 0; backend checked via TestClient in audit)
```

Expected: 3 distinct SHA256, each file contains `JOCKY_DEMO_MARKER`, `EntryPoint`, `bb.poly.*` blocks when `--polymorphic`.

## 2b. Full Stack via Docker (Point 1+2 Inside Image — NOT VERIFIED in audit)

The first build pulls `clang/llvm-dev/cmake/ninja/openjdk-17/antlr4` **inside** the image — no host LLVM required:

```bash
docker compose build          # ~10 min first time
docker compose run --rm jocky bash -c "jockyc examples/test.jocky -o /tmp/a.ll --seed 1 && jockyc examples/test.jocky --polymorphic -o /tmp/b.ll --seed 2 && jockyc examples/test.jocky --polymorphic -o /tmp/c.ll --seed 3 && sha256sum /tmp/*.ll"
# Must show 3 different hashes → Point 1+2 proven inside Docker as well
```

---

## 3. Start the Platform (Docker)

```bash
docker compose up
```

Keep this terminal running. In another terminal:

```bash
docker compose ps   # expect 9 services: jocky, agent, backend, frontend, db, redis, minio, nginx, detector
curl http://localhost:8000/health          # → {"status":"ok"}
curl http://localhost:8000/api/cases       # → {"cases":[],"count":0}
```

If Docker is not available, the backend can still be exercised via TestClient (see `docs/STATUS.md §6`) and the compiler via host Python.

---

## 4. Open the Dashboard

* Docker: `http://localhost:3000` (frontend — currently static demo data; live wiring is next milestone)
* Backend docs: `http://localhost:8000/docs`
* Nginx proxy: `http://localhost:80` → `cdn.jocky.local` (logical CDN front inside `jocky-net`)

> The dashboard currently shows hardcoded Graph/Timeline/Risk 85 (see `docs/STATUS.md §3` lines 19–22). The "Run JOCKY query from dashboard" flow is the **next milestone** — not yet available. For now use host compiler + `curl POST /api/evidence` as in `DEMO_SCRIPT.md`.

---

# ✍️ Writing a JOCKY Program

JOCKY programs are ordinary text files with the `.jocky` extension.

For example:

```text
examples/
└── investigation.jocky
```

Example:

```jocky
system.info();

process.list();

network.connections();
```

You can create and edit these files using:

* VS Code
* Vim
* Neovim
* Notepad
* Any text editor

The dashboard is primarily an **investigation and visualization interface** unless an editor is explicitly implemented in the current version.

---

# 🔧 Compiling a JOCKY Program

The exact CLI syntax is defined by the currently implemented compiler.

Conceptually:

```text
investigation.jocky
        ↓
      jockyc
        ↓
     JOCKY IR
```

Example:

```bash
jockyc examples/investigation.jocky
```

If the compiler is running inside Docker, invoke it through the project container according to the current development setup.

Do not assume a host-installed compiler is required.

---

# 🧪 Running Tests

Run the project's test suite using the build system currently configured in the repository.

Typical development flow:

```text
Build
  ↓
Unit Tests
  ↓
Integration Tests
  ↓
Controlled Lab Tests
```

See:

[`docs/TEST_PLAN.md`](docs/TEST_PLAN.md)

for the authoritative testing strategy.

---

# 🖥️ Windows and Linux

JOCKY is designed around platform abstractions.

Conceptually:

```text
             JOCKY API
                 │
        ┌────────┴────────┐
        ▼                 ▼
   Windows Adapter    Linux Adapter
        │                 │
   Windows APIs       Linux APIs
```

The same JOCKY program should be able to express the same forensic intent while platform-specific adapters handle implementation details.

However:

> **Cross-platform support must be verified, not assumed.**

A successful Linux/Docker build does not prove that the native Windows agent works.

Current platform support is tracked in:

[`docs/STATUS.md`](docs/STATUS.md)

---

# 📊 Investigation Workflow

Once evidence is available, the intended workflow is:

```text
1. Create / select case
          ↓
2. Collect evidence
          ↓
3. Normalize evidence
          ↓
4. Verify evidence integrity
          ↓
5. Run detection
          ↓
6. Generate findings
          ↓
7. Investigate timeline
          ↓
8. Investigate relationships
          ↓
9. Review risk
          ↓
10. Generate report
```

---

# 🧠 Example Investigation

Imagine a controlled laboratory fixture contains:

```text
10:01 — File observed
10:02 — Suspicious process relationship
10:03 — Driver-load observation
10:04 — Network anomaly
```

JOCKY processes the evidence:

```text
Raw Evidence
     ↓
Normalization
     ↓
Correlation
     ↓
Detection
     ↓
Findings
```

The dashboard can then present:

```text
Timeline
────────────────────────────
10:01  File observed
10:02  Process anomaly
10:03  Driver observation
10:04  Network anomaly
```

and an investigation relationship graph:

```text
Process
   │
   ├── File
   │
   ├── Driver observation
   │
   └── Network observation
```

The important point is that these scenarios should be reproducible through controlled fixtures rather than requiring operational malicious software.

---

# 📄 Documentation

The project documentation is divided by responsibility.

### Architecture

[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)

System components and relationships.

### Language

[`docs/LANGUAGE_SPEC.md`](docs/LANGUAGE_SPEC.md)

JOCKY syntax and semantics.

### IR

[`docs/IR_SPEC.md`](docs/IR_SPEC.md)

Intermediate representation contract.

### Forensics

[`docs/FORENSICS_SPEC.md`](docs/FORENSICS_SPEC.md)

Evidence model and forensic pipeline.

### Security

[`docs/SECURITY_MODEL.md`](docs/SECURITY_MODEL.md)

Security boundaries and threat model.

### Testing

[`docs/TEST_PLAN.md`](docs/TEST_PLAN.md)

Testing methodology and coverage strategy.

### Roadmap

[`docs/ROADMAP.md`](docs/ROADMAP.md)

Planned development stages.

### Design

[`docs/DESIGN.md`](docs/DESIGN.md)

Important engineering decisions and their rationale.

### Status

[`docs/STATUS.md`](docs/STATUS.md)

Current implementation state.

### Team

[`docs/TEAMMATES.md`](docs/TEAMMATES.md)

Ownership and collaboration.

### AI Agents

[`AGENTS.md`](AGENTS.md)

Instructions for AI coding agents contributing to the repository.

---

# 📈 Current Status

> This section is intentionally kept short. `docs/STATUS.md` contains the detailed implementation audit with evidence.

**Phase:** Foundation / Core Platform — Audit Complete (2026-08-28)

**Audit Verdict:** Scaffolded platform with **verified host compiler polymorphism** and **verified backend API**, but **end-to-end pipeline not yet connected**. Docker and platform support are **not verified** on audit host.

### Verified on Host (evidence in `docs/STATUS.md §6`)

* 🟢 `tools/jockyc.py` → `build/a.ll` / `b.ll` / `c.ll` produce **3 distinct SHA256** (polymorphism with seeds 1/2/3) containing `JOCKY_DEMO_MARKER`, `EntryPoint`, shuffled imports, `bb.poly.*` blocks.
* 🟢 FastAPI backend (`backend/app/main.py`) via TestClient: `GET /health`, `POST /api/evidence` (hollowing **risk 90 CRITICAL**, byovd **risk 40**), `GET /api/cases/1/risk|timeline|graph`, `POST /api/detect` with YARA hits.

### Partially Implemented

* 🟡 Compiler/IR (textual IR, 12 ops) — no IR validation, no capability enforcement, no AST.
* 🟡 Backend uses in-memory store (Postgres/Redis/MinIO declared in `docker-compose.yml` but not wired).
* 🟡 Detection `yara/rules.yar` + `sigma/rules.yml` exist; Python layer is string-contains, not YARA binary.
* 🟡 Dashboard `frontend/` (React 18 + Vite + ReactFlow + Tailwind) renders static Graph/Timeline/RiskGauge; **no JOCKY editor, no Run button**, live data fetch stubs with hardcoded fallback.
* 🟡 Controlled lab `testdata/*.json` fixtures (6 synthetic scenarios, safely labeled) exist but not wired via `evidence.load()`.

### Not Connected / Not Verified

* 🔴 Lexer/Parser/AST — stubs (Parser.cpp 3 lines, `*.ast` stub files); unknown ops like `unknown.op()` currently **not rejected**.
* 🔴 Runtime `runtime/` — 13-line hardcoded provider; not dispatched from IR.
* 🔴 Agent `agent/src/agent.cpp` — 18-line stub prints "Would POST" but does not POST; no auth, no provider.
* 🔴 Evidence normalization / canonical envelope per `FORENSICS_SPEC.md` — not implemented.
* 🔴 Report generation, agent→backend WSS, hardening.
* 🔴 Docker `docker compose build` / `up` — **NOT VERIFIED** (Windows host, daemon not exercised in audit).
* 🔴 Automated tests — `tests/` does not exist; CI `.github/workflows/build.yml` exists but not run here.
* 🔴 Windows/Linux platform providers — no native API code, no platform validation.

**Next Milestone:** `system.info();` end-to-end — see `docs/STATUS.md §8` for exit criteria (IR version + capability check + evidence envelope + live dashboard fetch + integration test).

The status above must be updated when the actual implementation changes.

---

# 🗺️ Roadmap

The broad development sequence is:

```text
Phase 1
Project Foundation
       ↓
Phase 2
JOCKY Language
       ↓
Phase 3
Compiler + IR
       ↓
Phase 4
Runtime + Capabilities
       ↓
Phase 5
Forensic Evidence
       ↓
Phase 6
Agent
       ↓
Phase 7
Backend
       ↓
Phase 8
Detection
       ↓
Phase 9
Dashboard
       ↓
Phase 10
Controlled Laboratory
       ↓
Phase 11
End-to-End Validation
       ↓
Phase 12
Hardening + Documentation
```

See [`docs/ROADMAP.md`](docs/ROADMAP.md) for detailed milestones.

---

# 🤝 Development

Development should follow:

```text
Issue / Requirement
        ↓
Understand Specification
        ↓
Plan
        ↓
Implement
        ↓
Test
        ↓
Review
        ↓
Document
        ↓
Commit
        ↓
Pull Request
        ↓
Merge
```

Do not commit directly to `main`.

Use feature branches:

```bash
git checkout -b feature/<description>
```

Keep commits small and meaningful.

Examples:

```text
feat: add process listing operation
feat: implement evidence normalization
fix: reject invalid IR capability
test: add malformed evidence cases
docs: update forensic specification
```

See [`AGENTS.md`](AGENTS.md) for the complete AI-assisted development workflow.

---

# 🔒 Responsible Research

JOCKY is intended for:

```text
Authorized systems
Controlled laboratories
Synthetic datasets
Defensive research
Digital forensics
Security education
```

Users are responsible for ensuring that experiments and investigations are authorized.

The project prioritizes **understanding, detecting, and analyzing security-relevant behavior** over developing mechanisms to conceal or deploy that behavior.

---

# 📜 License

License information will be added when the project license is finalized.

---

# 👨‍💻 Project Team

See:

[`docs/TEAMMATES.md`](docs/TEAMMATES.md)

for current ownership and responsibilities.

---

# ⭐ Project Principle

JOCKY is built around one central idea:

> **Make forensic investigation programmable, reproducible, explainable, and secure.**

The goal is not simply to collect more data.

The goal is to turn:

```text
Raw Evidence
     ↓
Structured Evidence
     ↓
Context
     ↓
Correlation
     ↓
Detection
     ↓
Understanding
```

into an investigation workflow that can be reproduced, tested, audited, and improved.
