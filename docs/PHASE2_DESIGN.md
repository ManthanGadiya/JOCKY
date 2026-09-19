# JOCKY Phase 2 — Synthetic Lab Hardening — Design Document

**Document:** docs/PHASE2_DESIGN.md
**Status:** Design Review — Pending Approval Before Code (TODO 0.3)
**Scope:** Compiler-Enforced Defensive Hardening in Controlled Synthetic Lab Only
**Last Updated:** 2026-09-19

## 1. Goal
Make the forensic compiler demonstrably resilient while preserving auditability, using compiler-level IR diversification so the same JOCKY source compiled with different seeds produces distinct IR artifacts that still validate and still detect via the same YARA/Sigma/Behavioral logic.

Demonstration: python tools/jockyc.py examples/test.jocky -o build/a.ll --seed 1 --polymorphic and seed 2 produce distinct SHA256 but POST /api/yara/polymorphic-demo seeds 1,2,3 -> same_yara_cluster true. tools/evaluate.py --n 1000 --seed 42 -> F1 0.97 holds across plain/shuffled/encrypted/flattened stages (mean resilience 80%). All artifacts labeled LAB / SIMULATED / SYNTHETIC per AGENTS.md 47.

## 2. Non-Goals (Explicitly NOT in Phase 2)
- No arbitrary binary packing — transforms apply ONLY to JOCKY IR output from tools/jockyc.py / jocky/src/IRGen.cpp, never to arbitrary *.exe.
- No kernel bypass, no privilege escalation, no persistence, no covert C2.
- No EDR/AV evasion as a feature — hardening is defensive preservation of forensic integrity under synthetic pressure, not stealth.
- No disabling security controls (edr.disable stays 422 fail-closed, memory.analyze stays 403).
- No real malware payload execution — volatile cases remain evidence.load testdata synthetic fixtures.

## 3. Out-of-Scope
- Microservices / message queues / extra DBs — not justified.
- General-purpose LLVM obfuscator — violates least privilege; Phase 2 is JOCKY-IR-only textual transforms with optional LLVM pass behind jocky/transform/ behind --polymorphic opt-in.
- Silent default hardening — would break reproducibility; hardening is explicit opt-in flag only.

## 4. Where Transforms Sit
JOCKY Source -> Lexer (tools/jocky_lexer.py / jocky/src/Lexer.cpp per grammar/jocky.g4) -> Parser (MemberCall / Investigation / Imports / Funcs) -> AST -> Semantic Analysis + Capability Validation (OP_CAPS whitelist, fail-closed 422/403) -> IR Generation (IRGen.cpp generateIRWithValidation + tools/jockyc.py generate_ir) -> IR Validation (IR_SPEC 33, validate_ir_json) -> TRANSFORMS (Phase 2, opt-in --polymorphic only, deterministic per seed, LAB-labeled) -> Runtime (platform factory ISystem/IProcess/IFile/INetwork) -> Evidence (canonical SHA256+provenance+chain) -> Backend Detection (YARA 5 + Sigma 2 + Behavioral 13) -> Timeline/Graph/Risk -> Dashboard -> Report

Transforms run after validation, before emission, and are auditable — build/a.ll diff shows markers; reversibility via seed logged in IR metadata.module_id.

## 5. Determinism Contract
- Deterministic: same source + same seed -> same IR bytes + same .ll.json module_id (seed via random.Random(seed) / mt19937(seed)).
- Reversible for debug: xor key and shuffle order recoverable from header comments + module_id; --polymorphic absent -> plain IR (default for CI/host tests).
- Opt-in only: --polymorphic flag required; without it, IR is unmodified.
- Labeled: Every hardened IR header contains ; -- polymorphic transforms applied -- + LAB / SIMULATED in report footer.

## 6. What Changes
- tools/jockyc.py: expand generate_ir hardening: real shuffle, real xor arrays, real dispatcher with seed determinism
- jocky/src/IRGen.cpp: mirror Python logic deterministically in C++ path
- jocky/transform/*.cpp: replace stubs with documented lab transforms (textual IR)
- tests/test_hardening_phase2.py: new deterministic + YARA cluster tests
- docs/ARCHITECTURE.md section 5: update pipeline diagram to include TRANSFORMS stage
- docs/DESIGN.md section 7: update compiler design with transform contracts
- tools/evaluate.py: later 4.1 add 4-stage sweep
- docker-compose.yml / DEMO_SCRIPT.md: later 5.2 30-sec before/after diff

## 7. Security Tests (Fail-Closed)
Unknown op -> 422, memory.analyze -> 403, path traversal -> 400, malformed IR version mismatch -> 422, oversized IR -> 413. All 163 existing tests green in plain mode.

## 8. Approval Gate (TODO 0.3)
This doc must be reviewed and marked Approved before merging feature/phase2-synthetic-hardening. Approval criteria: non-goals acknowledged, transforms scoped to JOCKY IR only, deterministic + LAB-labeled.
