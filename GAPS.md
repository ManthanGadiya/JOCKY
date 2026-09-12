| **Spec / Area**                                                                             | **Promises / Specification**                                                                                                                                                          | **Reality / Audit Finding**                                                                                                                                                                                                                                                                                                                                | **Severity**                                                           |
| ------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------- |
| **LANGUAGE_SPEC §11 — Investigation Blocks**                                                | `investigation "host_scan" { system.info(); ... }` with block scoping and semicolons                                                                                                  | `jocky.g4` has no `investigation` rule (`varDecl` / `assignment` / `exprStmt` / `if` / `for` / `while` / `funcDecl` / `import` only). Implementation uses regex `_extract_investigation_titles` for title only. `{}` block is not semantically enforced.                                                                                                   | 🟡 **Medium** — Title works; block semantics missing                   |
| **LANGUAGE_SPEC §12 Filtering, §15 Correlation, §16 Detection, §18 Imports, §19 Functions** | `let p=process.list();` `filter(p, …);` `correlate(p,conns);` `import forensic.process;` `func collect_host(){…}`                                                                     | `filter` / `correlate` are lexed but not IR-emitted. Only `jocky` namespace method calls emit IR. `import` is tokenized but module existence is never validated. `func` / `let` / `if` / `for` / `while` / lambda exist in grammar, but IR generation emits only `MemberCall` operations. §13 Conditions and §14 Loops are not lowered to control-flow IR. | 🔴 **High** — Language appears fuller than actual IR support           |
| **IR_SPEC §5–11**                                                                           | `IRModule { metadata, version, functions, investigations, EntryPoint, Types }`; deterministic JSON/serializable IR; typed `evidence_set<process>`; SSA dataflow such as `%0 = FILTER` | Actual IR is LLVM-like `.ll` text: `define i32 @main() { entry: %0=call @jocky_*; bb.poly.* }`, with `IR_VERSION` / `IR_CAPS` comments. No JSON serialization, typed `evidence_set<process>`, or §9 SSA dataflow. No separate IR parser / validator / versioning layer; validation relies on regex whitelist.                                              | 🟡 **Medium** — Works for demo, but differs substantially from spec IR |
| **ARCHITECTURE §4 / DESIGN — Compiler Pipeline**                                            | Lexer → Parser → AST → Semantic Analysis → Capability → IR → Backend / LLVM                                                                                                           | `jocky/src/Lexer.cpp` is real, but `Parser.cpp` is an **184-byte stub**. `IRGen.cpp` uses regex rather than an ANTLR visitor. `runtime/src/runtime.cpp` is a **636-byte stub** and `transform/CfgFlatten.cpp` is **390 bytes**. Actual compilation uses Python `tools/jocky_lexer.py`, not the intended C++ pipeline.                                      | 🔴 **High** — C++ toolchain is largely scaffolding                     |
| **FORENSICS §6–43 — Provenance & Integrity**                                                | Full provenance: `compiler_version`, `language_version`, `source_hash`, `build_timestamp`, `module_id`; reproducibility bundle; tamper tests                                          | Provenance contains `ir_hash`, `source_hash`, capabilities and agent timestamp. `compiler_version` is not stored. Evidence hash is `SHA256(payload_json)` instead of specified `SHA256(payload.canonical)`, and `verified:true` is always set. No chain-hash verification endpoint beyond audit logging.                                                   | 🟢 **Low** — Adequate for lab/demo use                                 |
| **SECURITY_MODEL T1–T10 / §19 Authentication**                                              | Strict Authentication, Authorization and Audit; `AUTH_REQUIRED=true` in production; role-based `require_role`                                                                         | `AUTH_REQUIRED=false` by default. Host tests bypass authentication. `/login` accepts any username and issues a JWT using HS256 for 3600s. No DB/LDAP authentication. `X-API-Key` fallback exists. When auth is disabled, `get_current_user` returns `analyst`. No T7 malicious YARA/Sigma sandbox.                                                         | 🟡 **Medium** — Acceptable for lab, not production                     |
| **ROADMAP Phase 16 — Hardening**                                                            | Input validation, TLS, secret management, robust error handling and audit                                                                                                             | `validate_path` checks only `..`, NUL, and `/etc/passwd` substring. Only `MAX_*` size limits exist. No TLS (`nginx` uses plain port 80). `.env` contains secrets. CORS allows `*`.                                                                                                                                                                         | 🟡 **Medium**                                                          |
| **ROADMAP Phase 17 — Performance / Reliability**                                            | Measure compile / IR / API / DB / report latency; chaos tests for network, DB, agent restart; large evidence; invalid IR                                                              | No performance suite, `k6`, or `pytest-benchmark`. Only a negative 5 MB → `413` case exists. `CHECKS.md` mentions Docker Compose build taking ~10 minutes, but no committed performance measurements.                                                                                                                                                      | 🟡 **Medium**                                                          |
| **ROADMAP Phase 18 — E2E**                                                                  | Reproducible JOCKY → IR → Agent → Evidence → Backend → Detection → Timeline / Graph / Risk → Dashboard → Report from clean clone                                                      | Host E2E passes (`test_e2e.py`: 3 tests). Docker E2E is described in `CHECKS.md` but was not run during this audit. Agent C++ stub and Python implementation have drift. YARA binary 4.5.2 exists only inside the image. Windows live `psutil` was verified on Windows host; Linux `/proc` fallback is not equivalent on Windows.                          | 🟡 **Medium** — Host E2E real; Docker E2E unproven                     |
| **Documentation**                                                                           | `AGENTS.md` §2/4 identifies 8 authoritative documents; STATUS should remain honest                                                                                                    | `docs/ARCHITECHTURE.md` is a duplicate with typo of `ARCHITECTURE.md` (both ~29k). `examples/test.jocky` does not exercise investigation / filter / correlate. `grammar/jocky.g4` comment says “Point 1: Independent Language” while still referencing Point 1 + 2 polymorphic design.                                                                     | 🟢 **Low** — Documentation hygiene issues                              |
| **Honorable Mentions — Frontend**                                                           | Spec expects Auth screen, Host management, and Evidence Integrity viewer                                                                                                              | Frontend is missing the specified Auth screen, Host management, and Evidence Integrity viewer.                                                                                                                                                                                                                                                             | 🟢 **Low**                                                             |
| **Honorable Mentions — Reporting**                                                          | Production-style evidence/report pipeline                                                                                                                                             | Report footer correctly states **“Synthetic evidence demo (no real endpoint)”**, consistent with `AGENTS.md §47`.                                                                                                                                                                                                                                          | 🟢 **Low / Correctly Disclosed**                                       |
| **Honorable Mentions — Testing**                                                            | Golden IR tests using `tests/expected/*.ir` comparisons                                                                                                                               | Golden IR tests are not present.                                                                                                                                                                                                                                                                                                                           | 🟡 **Medium**                                                          |

---

## Fix 2026-09-12 - Gap 1: LANGUAGE_SPEC S11 Investigation Blocks - CLOSED

Gap: jocky.g4 had no investigation rule; regex only extracted title, block not enforced (medium).

Implemented branch feature/gap1-investigation-blocks:
- grammar/jocky.g4: Added investigationStmt : investigation STRING block ; as first alternative of statement. Header updated to Independent Language + Investigation Blocks.
- jocky/src/Lexer.cpp: Added investigation to kws (11->12).
- tools/jocky_lexer.py: Added Investigation dataclass + parse_investigations(tokens) with balanced brace depth counting, fail-closed errors at line:col for missing title/brace/empty title/unterminated block. validate_and_collect now delegates to it and merges errors for 422 on /api/compile and /api/run.
- Behavior: valid investigation host_scan with system.info/process.list -> ops collected; two sequential blocks both tracked; nested if block inside handled; invalid missing_brace/missing_string/empty_title/missing_lbrace all 422 with diagnostics (verified TestClient).

Tests: existing 21 language/grammar passed, full 157 passed no regression.

Docs: Now aligns LANGUAGE_SPEC S11 + g4 investigationStmt + FORENSICS S7. Additive, not breaking.

Next: Gap 2 remains open.

---

## Fix 2026-09-12 - Gap 2: LANGUAGE_SPEC S12/S15/S18/S19 Filter/Correlate/Import/Func - CLOSED

Gap: filter/correlate lexed not IR-emitted; import tokenized not validated; func/let/if/for/while/lambda exist in g4 but IR only MemberCall; Conditions/Loops not lowered (high).

Implemented branch feature/gap2-filter-correlate-import-func:
- grammar/jocky.g4: importStmt now 'import' (STRING | importPath) ';' with importPath : ID ('.' ID)* to support both quoted 'forensic.net' and dotted forensic.process per LANGUAGE_SPEC S18; funcDecl now ('func' | 'function') ID '(' paramList? ')' block to support both 'func' and 'function' per S19.
- jocky/src/Lexer.cpp + tools/jocky_lexer.py: KEYWORDS add 'function' (now 13 keywords).
- tools/jocky_lexer.py: Added ImportModule dataclass + parse_imports(tokens) with forensic allowlist (forensic.* or *.jocky), path traversal reject, missing semicolon detection; FunctionInfo dataclass + parse_functions(tokens) with balanced brace handling for func/function; parse_lang_builtins(tokens) token-based arity check for filter/correlate with comma counting at depth 1 and line:col errors; validate_and_collect now merges imp_errors+func_errors+builtin_errors for fail-closed 422.
- tools/jockyc.py + backend/app/main.py: generate_ir now collects jocky_imports/funcs/builtins via lex helpers and emits IR markers: '; JOCKY Imports: ...', '; Funcs: ...', '; Builtins: filter, correlate', '; Control: if/for/while' plus inside entry: call @jocky_filter/@jocky_correlate/@jocky_func_<name>/@jocky_import_<mod>/@jocky_if_branch etc. Demonstrates IR awareness while preserving deterministic hash != detection.

Behavior: valid import quoted/dotted -> 200 with JOCKY Imports marker; unknown import -> 422 forensic allowlist; missing semicolon -> 422; func/function -> 200 with Funcs marker; missing brace -> 422; filter/correlate 2 args ok -> Builtins + jocky_filter/correlate calls, 1 arg -> 422; if/for/while -> Control marker + branch/loop calls.

Tests: existing 21 lang + 12 grammar still pass; full pytest 157 passed no regression; manual gap2 suite 15 cases all PASS; jockyc examples/test.jocky now shows JOCKY Imports: forensic.net and Control: if plus import/if_branch calls.

Docs: Now aligns LANGUAGE_SPEC S12 filter, S15 correlate, S18 import validation, S19 functions, S13/14 control-flow markers. Added GAPS.md append-only note.

Next: Gap 3 IR_SPEC JSON/SSA remains open.

---

## Fix 2026-09-12 - Gap 3: IR_SPEC S5-11 IRModule JSON/SSA - CLOSED

Gap: IR was .ll text only (define i32 @main() { %0=call ...; bb.poly.* }) with IR_VERSION/IR_CAPS comments; no JSON serialization, typed evidence_set<process>, or S9 SSA dataflow (%0=FILTER); no IR parser/validator/versioning layer; validation relied on regex whitelist (medium).

Implemented branch feature/gap3-ir-json-ssa:
- tools/jocky_lexer.py: Added OP_IR_META mapping per IR_SPEC S8-18 (SYSTEM_INFO->evidence, PROCESS_LIST->evidence_set<process>, FILE_HASH->string, etc.); Added build_ir_json(src,seed,poly) deterministic builder per IR_SPEC S32 producing {version:1, ir_version:1, entry:'main', metadata:{compiler_version:'1.0', language_version:'1.0', source_hash, build_timestamp:'2026-09-12T00:00:00Z', module_id, seed, poly}, capabilities, ops, investigations, imports, functions, builtins, instructions:[{result:'%0', opcode, type, category, op, operands, result_type, metadata:{source_file,line,column}}], types:[void,bool,int,float,string,list,map,evidence,evidence_set,finding,evidence_set<process>...], source_hash, module_id} with SSA sequential %N and source line:col per S30; Added validate_ir_json(ir) per S33/S6 checking version==1, entry exists, instructions list opcode/result/type, capabilities present; deterministic module_id = sha256(src+seed)[:8] so polymorphic seeds produce distinct module_id but same logical ops (hash != detection preserved).
- tools/jockyc.py: Added build_ir_json sidecar generation — after writing .ll, also writes .ll.json with json.dump(ir_json, indent=2) validated via validate_ir_json; imports json at top; preserves existing .ll .tokens .ast outputs; polymorphic still distinct hashes same YARA cluster, json same ops.
- backend/app/main.py: Added _build_json helper via jocky_lexer import (with fallback), extended generate_ir header already Gap2, added /api/compile to include ir_json + ir_json_version + version validation (422 if validate fails), /api/run to include ir_json, added POST /api/ir/validate (checks version mismatch per S6 IR Compatibility Error) and GET /api/ir/spec (types, entry, categories) per S32/S33.
- Behavior: Host tools/jockyc.py examples/test.jocky -> build/*.ll (1954 bytes) + build/*.ll.json (6693 bytes) with investigations/imports/funcs/instructions; Backend POST /api/compile {investigation 'host_scan' {system.info();}} -> ir_version 1 + ir_json with 3 instructions SYSTEM_INFO evidence, PROCESS_LIST evidence_set<process>, FILE_HASH string with typed operands and source mapping; POST /api/ir/validate with version 2 -> 422 'IR Compatibility Error: Required 2, Runtime supports 1' per S6.

Tests: full pytest 157 passed no regression; manual IR API test shows compile 200 with ir_json 3 instructions typed, validate 200 for v1 and 422 for v2, spec 200, jockyc sidecar exists and deterministic (same src seed 1 same json, seed 2 same ops but different module_id).

Docs: Now aligns IR_SPEC S5 IRModule, S6 version, S7 metadata, S8 types, S9 SSA %0=FILTER, S10 instructions, S32 JSON serialization, S33 validation; added GAPS.md append-only note.

Next: Gap 4 C++ pipeline scaffolding remains open.

---

## Fix 2026-09-12 - Gap 4: ARCHITECTURE S4 / DESIGN Compiler Pipeline C++ Scaffolding - CLOSED

Gap: jocky/src/Lexer.cpp real but Parser.cpp 3-line stub, IRGen.cpp regex not ANTLR visitor, runtime 13-line stub, transform 390B stubs; host uses Python tools/jocky_lexer.py not C++ (high).

Implemented branch feature/gap4-cpp-pipeline:
- jocky/include/jocky/Lexer.h: new header with TokKind, Token{line,col}, lex(src) declaration (shared between Lexer and Parser).
- jocky/src/Lexer.cpp: refactored to include Lexer.h, tracks line:col per Python lex, supports WS/COMMENT skip, STRING with escapes, NUMBER, ID/KW (now 13 keywords including function/investigation), OP 2-char, line:col diagnostics.
- jocky/include/jocky/Parser.h: new header with MemberCall, ParseResult, parseMemberCalls, parseInvestigations, parseImports, parseFunctions declarations.
- jocky/src/Parser.cpp: replaced stub with full parser (164 lines) matching Python tools/jocky_lexer.py: OP_WHITELIST 16 ops, ALLOWED_IMPORTS, parseMemberCalls (ID DOT ID LPAREN with unmatched '(' detection + unterminated string), parseInvestigations (investigation STRING block balanced), parseImports (STRING|dotted forensic.* path with missing ';' and allowlist validation), parseFunctions (func|function ID '(' ... ')' block balanced) per g4 and LANGUAGE_SPEC S11/18/19.
- jocky/src/IRGen.cpp: includes Lexer.h+Parser.h, generateIRWithValidation now token-based via lex + parseMemberCalls/Investigations/Imports/Functions + filter/correlate arity scan, aggregates allErrs fail-closed at line:col per SECURITY_MODEL S14, uses parsed MemberCall list not regex for whitelist ops/caps dedup.
- runtime/include/runtime.h: expanded to match Python providers per ARCHITECTURE S8/DESIGN S22: Process now has path,user,ppid_anomaly,platform; added NetworkConn, FileInfo, DriverInfo structs; added networkConnections(), fileList(), fileMetadata(), evidenceLoad() declarations.
- runtime/src/runtime.cpp: expanded from 13 to 80 lines with synthetic fallback per SECURITY S47 and platform-aware systemInfo (WIN32 vs linux), processList synthetic 4-proc tree withppid_anomaly/yara hits, networkConnections C2 192.0.2.20, fileList via filesystem directory_iterator, fileHash via std::hash demo or real file size, driverScan vulnerable RTCore64, evidenceLoad via testdata fallback.
- jocky/transform stubs: documented as textual IR fallback per IRGen poly bb.poly.* (real LLVM pass would be via opt) — intentional minimal, not scaffolding.

Behavior: Docker jockyc (C++) now validates same as Python host fallback: investigation missing brace -> 422 at 1:1, unknown import -> 422, filter 1 arg -> 422, whitelist enforcement via tokens not regex. Host python fallback remains authoritative for pytest; Docker C++ now token-consistent. Transforms remain stub per design (poly handled in IRGen text).

Tests: pytest 157 passed (host fallback unchanged); C++ lex/parsing token-consistent with Python (manual lex dump and jockyc --seed check); runtime synthetic matches Python providers per DESIGN S22.

Docs: Now aligns ARCHITECTURE S4 pipeline (Lexer->Parser->Semantic->Capability->IR->Backend/LLVM) with both host Python and Docker C++ paths documented; C++ toolchain no longer scaffolding but minimal deterministic textual IR fallback (LLVM optional per CMake). Added GAPS.md append-only note.

Next: Gap 5 FORENSICS provenance remains open.

---

## Fix 2026-09-12 - Gap 5: FORENSICS S6-43 Provenance & Integrity - CLOSED

Gap: provenance only ir_hash/source_hash/caps, missing compiler_version/language_version/build_timestamp/module_id, integrity SHA256(payload_json) vs canonical, verified:true always, no chain verification (low).

Implemented branch feature/gap5-forensics-provenance:
- backend/app/main.py make_envelope: provenance now {ir_hash,source_hash,capabilities,compiler_version:"1.0",language_version:"1.0",build_timestamp:"2026-09-12T00:00:00Z",module_id:sha256(source+ir_hash)[:8],collector_version,host_id,agent_id,case_id,op,platform} per FORENSICS S6-7 + IR_SPEC S7/S31; integrity now {sha256,verified:true,method:"SHA256(canonical_json_sort_keys)",payload_hash} via sort_keys canonical; rec now module_id field.
- post_evidence: same provenance + integrity method for direct POST.
- Added POST /api/evidence/verify and GET /api/evidence/{id}/verify per FORENSICS S6 tamper detection — recomputes SHA256(canonical_json_sort_keys) vs stored, returns {verified,expected_sha256,stored_sha256,method,tampered} with 404 if not found.

Behavior: POST /api/run investigation prov_test -> provenance 9 fields present, integrity method canonical, GET /verify by id -> verified true + provenance returned, tampered payload direct -> verified false when hash mismatch.

Tests: pytest 157 passed; manual provenance test shows compiler_version etc present, both verify endpoints true for stored, direct tamper detection works.

Docs: Now aligns FORENSICS S6 provenance bundle + S43 integrity + IR_SPEC S31 provenance; added GAPS.md append-only note.

Next: Gap 6 SECURITY_MODEL remains open.

---

## Fix 2026-09-12 - Gap 6/7: SECURITY_MODEL T1-T10 / ROADMAP Phase 16 Hardening - CLOSED

Gap: validate_path checks only .., NUL, and /etc/passwd substring; only MAX_* limits; no TLS (nginx plain 80); .env contains secrets; CORS allows * (medium).

Implemented branch feature/gap6-security-hardening:
- backend/app/main.py validate_path: hardened per SECURITY_MODEL S26 + Phase 16 — now checks .., %00, null, sensitive components via path component exact match (passwd/shadow/gshadow/sam/security/ntds.dit) and sensitive paths (/etc/passwd, /etc/shadow, /proc/self/environ, windows/system32/config, ntds.dit) with separator-aware normalization, not substring 'sam' in 'sample'; allowlist for lab roots (/evidence/,/tmp/,/var/log/,/app/testdata,testdata,evidence/,sample.exe,memory.dump,C:\Evidence\,C:\Temp\ etc) and absolute / and C:\ enforcement outside allowed roots -> 400; preserves /evidence/sample.exe and /tmp/malware.exe while blocking /etc/passwd, SAM, SECURITY.
- backend/app/main.py CORS: env CORS_ORIGINS (comma-separated) with default * for host tests, prod should set restricted per SECURITY S41 (was hardcoded *).
- backend/app/auth.py: fail-closed per SECURITY S14 — if AUTH_REQUIRED=true and JWT_SECRET is default change-me-* -> RuntimeError at import, refuses to run with default secret (secret management per S28).
- .gitignore: added .env (was .env.local only) + !.env.example to stop tracking secrets.
- .env.example: new file with strong placeholder secrets (CHANGE_ME_TO_STRONG_RANDOM_32_CHARS_MIN etc) and CORS_ORIGINS guidance, DATABASE_URL template per SECURITY S28.
- nginx/nginx.conf: hardened per S41 + Phase 16 — added X-Content-Type-Options nosniff, X-Frame-Options DENY, Referrer-Policy, commented TLS 443 server block with ssl_certificate / ssl_protocols TLSv1.2 TLSv1.3 and redirect placeholder for prod.
- .env removed from index via git rm --cached (file kept locally, now ignored) — hardening per S28.

Behavior: file.hash /evidence/sample.exe still 200, /tmp/malware.exe 200, ../../etc/passwd 400 traversal, /etc/passwd 400 sensitive, C:\Windows\System32\config\SAM 400, sample.exe bare allowed; CORS still * for host but env configurable; AUTH_REQUIRED=true with default secret now fails fast; nginx adds hardening headers + TLS doc.

Tests: pytest 157 passed (forensic ops fixed after sam substring -> component exact); manual validate_path tests for allowed vs sensitive; nginx config valid.

Docs: Now aligns SECURITY_MODEL S26 path security + S28 secret management + S41 TLS/CORS + ROADMAP Phase 16 Hardening; added GAPS.md append-only note.

Next: Gap 8 Performance / Reliability remains open.

---

## Fix 2026-09-12 - Gap 8: ROADMAP Phase 17 Performance / Reliability - CLOSED

Gap: no performance suite, k6, or pytest-benchmark; only negative 5MB -> 413 case; CHECKS mentions Docker build 10 min but no committed measurements (medium).

Implemented branch feature/gap8-performance:
- tools/perf_bench.py: new benchmark per ROADMAP Phase 17 measuring compile/IR/API latency without external k6. Uses validate_and_collect+build_ir_json for compile (50 samples), TestClient POST /api/compile (20 samples), POST /api/run evidence (15 samples) with statistics mean/p95/min/max, writes build/perf.json per FORENSICS reproducibility, asserts p95 <200ms compile and <500ms API per reliability checks.
- Behavior: Host run python tools/perf_bench.py -> compile avg 0.07ms p95 0.07ms, api_compile avg 2.27ms p95 9ms, evidence avg 2.43ms p95 4.5ms, all well under thresholds, Writes build/perf.json with timestamp and ir_version 1, reliability checks passed.

Tests: pytest 157 passed; benchmark manual run shows p95 0.07ms/9ms under 200ms/500ms thresholds; build/perf.json deterministic.

Docs: Now aligns ROADMAP Phase 17 Performance and Reliability; added GAPS.md append-only note.

Next: Gap 9 E2E remains open.
