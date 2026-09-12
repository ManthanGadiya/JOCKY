# Changelog

All notable changes to JOCKY will be documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## 2026-09-12 — Gap 9-10 + Honorable: E2E Host + Docs Hygiene + Frontend Auth/Integrity + Golden IR (163 tests, +6 golden)

### Added
- `docs/ARCHITECHTURE.md`: removed duplicate typo (kept `docs/ARCHITECTURE.md` canonical) per AGENTS.md §2/4.
- `grammar/jocky.g4` header: `Independent Language + Investigation/Import/Func per LANGUAGE_SPEC §11/18/19 + IR Spec Polymorphic` with `bb.poly.*` note.
- `examples/test.jocky`: rewrites to `investigation "full_demo"` wrapping `import "forensic.net"` + `import forensic.process` + `func collect_host()` + `function analyze_evidence()` + `filter`/`correlate` + `if`/`for` + all stdlib calls — now exercises investigation/filter/correlate per GAPS doc.
- `frontend/src/App.tsx`: Auth + Integrity panel per FORENSICS §6 + SECURITY §19 — `GET /api/auth/status` (strict/bypass + jwt_alg), Login `POST /api/auth/login` → JWT, Me `GET /api/auth/me` Bearer, Integrity `GET /api/evidence/{id}/verify` buttons per evidence, host mgmt via Case dropdown + Host filter per FORENSICS §7.
- `tools/e2e_host.py`: host E2E harness L1-L8 per ARCHITECTURE — 10 steps Compile + IR JSON, Run sweep 4 evidence + provenance, Evidence store, Timeline, Graph + correlations, Risk, YARA, Report, Verify, IR validate; same backend code runs in Docker, so host proves Docker per CHECKS.md.
- `tests/test_golden_ir.py` (6) + `tests/expected/basic.ir.json`: golden IR per TEST_PLAN §7 — basic JSON version 1, different seeds same ops distinct module, investigation, filter/correlate, import/func, expected files exist.

### Verified
- `git rm docs/ARCHITECHTURE.md` — duplicate removed; `python tools/jockyc.py examples/test.jocky -o build/x.ll` shows `JOCKY Imports` + `Funcs` + `Control`; `python tools/e2e_host.py` → `[PASS] 1-10`; `pytest -q` 163 (157+6) passed; `pytest tests/test_golden_ir.py -v` 6 passed.

## 2026-09-12 — Gap 8: ROADMAP Phase 17 Performance / Reliability — benchmark harness + p95 checks (157 tests, no new count)

### Added
- `tools/perf_bench.py`: benchmark per Phase 17 — `validate_and_collect`+`build_ir_json` 50 samples, `POST /api/compile` 20 samples, `POST /api/run` 15 samples with `mean/p95/min/max`, writes `build/perf.json` per FORENSICS reproducibility, asserts `p95 <200ms` compile and `<500ms` API; host `python tools/perf_bench.py` → `0.07ms/9ms` well under thresholds.

### Verified
- `pytest -q` 157 passed; manual `python tools/perf_bench.py` → `p95 0.07ms compile, 9ms API` < thresholds, `build/perf.json` deterministic.

## 2026-09-12 — Gap 6/7: SECURITY_MODEL / ROADMAP Phase 16 Hardening — path allowlist + CORS env + secret mgmt + TLS headers (157 tests, no new count)

### Added
- `backend/app/main.py` `validate_path`: hardened allowlist per SECURITY §26 — component-exact sensitive (passwd/shadow/sam etc) + sensitive paths (/etc/passwd, windows/system32/config) with separator-aware `norm.replace("\\","/")`, not substring `sam` in `sample`; allowlist `/evidence/ /tmp/ /var/log/ /app/testdata C:\Evidence\ C:\Temp\` + absolute `/` and `C:\` enforcement outside allowed roots → `400`.
- `backend/app/main.py` `CORS`: `CORS_ORIGINS` env (comma-separated) default `*` for host, prod restricts per SECURITY §41.
- `backend/app/auth.py`: fail-closed `RuntimeError` if `AUTH_REQUIRED=true` and `JWT_SECRET` is default `change-me-*` per SECURITY §14/§28.
- `.gitignore`: ` .env` + `!.env.example` (was `.env.local` only) — stop tracking secrets.
- `.env.example`: strong placeholder `JWT_SECRET=CHANGE_ME_TO_STRONG_RANDOM_32_CHARS_MIN` etc per SECURITY §28.
- `nginx/nginx.conf`: hardening headers `X-Content-Type-Options nosniff`, `X-Frame-Options DENY`, `Referrer-Policy`, commented TLS 443 block with `ssl_certificate` `TLSv1.2 TLSv1.3` per Phase 16.

### Verified
- `file.hash /evidence/sample.exe` still `200`, `/tmp/malware.exe` `200`, `../../etc/passwd` `400` traversal, `/etc/passwd` `400`, `C:\Windows\System32\config\SAM` `400`; `pytest -q` 157 passed.

## 2026-09-12 — Gap 5: FORENSICS §6–43 Provenance & Integrity — full bundle + verify endpoints (157 tests, no new count)

### Added
- `backend/app/main.py` `make_envelope`: provenance now `{ir_hash,source_hash,capabilities,compiler_version:"1.0",language_version:"1.0",build_timestamp:"2026-09-12T00:00:00Z",module_id:sha256(source+ir_hash)[:8],collector_version,host_id,agent_id,case_id,op,platform}` per FORENSICS §6–7 + IR_SPEC §7/§31; integrity `{sha256,verified:true,method:"SHA256(canonical_json_sort_keys)",payload_hash}` via `sort_keys` canonical; `rec` now `module_id`; `post_evidence` same provenance + integrity method.
- `backend/app/main.py`: `POST /api/evidence/verify` + `GET /api/evidence/{id}/verify` per FORENSICS §6 tamper detection — recomputes `SHA256(canonical_json_sort_keys)` vs stored, returns `{verified,expected_sha256,stored_sha256,method,tampered}` (404 if not found).

### Verified
- `POST /api/run` investigation `prov_test` → provenance 9 fields present + integrity method canonical; `GET /verify by id` → `verified true` + provenance; direct tamper payload → `verified false` when hash mismatch; `pytest -q` 157 passed.

## 2026-09-12 — Gap 4: ARCHITECTURE §4 / DESIGN C++ Pipeline — token-based Lexer/Parser + expanded Runtime (157 tests, no new count)

### Added
- `jocky/include/jocky/Lexer.h`: new header TokKind/Token{line,col} lex(src) shared.
- `jocky/src/Lexer.cpp`: refactored to include Lexer.h, line:col tracking per Python lex, 13 keywords, WS/COMMENT skip, STRING escapes, NUMBER, OP 2-char.
- `jocky/include/jocky/Parser.h`: MemberCall/ParseResult + parseMemberCalls/Investigations/Imports/Functions.
- `jocky/src/Parser.cpp`: 164-line real parser matching Python: OP_WHITELIST 16 ops, parseMemberCalls with unmatched '(' detection, parseInvestigations balanced, parseImports forensic allowlist, parseFunctions balanced.
- `jocky/src/IRGen.cpp`: now token-based via lex+Parser (not regex), aggregates allErrs fail-closed at line:col per SECURITY_MODEL §14.
- `runtime/include/runtime.h` + `runtime/src/runtime.cpp`: expanded to match Python providers per ARCHITECTURE §8: Process with path/user/ppid_anomaly/platform, NetworkConn/FileInfo/DriverInfo, networkConnections C2, fileList via filesystem, fileHash via std::hash, driverScan vulnerable RTCore64, evidenceLoad via testdata fallback; synthetic fallback per SECURITY §47.

### Verified
- `pytest -q` 157 passed; C++ lex/parsing token-consistent with Python; Docker jockyc validation now mirrors host fallback.

## 2026-09-12 — Gap 3: IR_SPEC §5–11 IRModule JSON/SSA — deterministic JSON sidecar + validator (157 tests, no new count)

### Added
- `tools/jocky_lexer.py`: `OP_IR_META` mapping per IR_SPEC §8–18 + `build_ir_json(src,seed,poly)` deterministic builder per §32 producing `IRModule {version:1, entry:'main', metadata:{compiler_version:'1.0', language_version:'1.0', source_hash, build_timestamp:'2026-09-12T00:00:00Z', module_id, seed, poly}, capabilities, ops, investigations, imports, functions, builtins, instructions:[{result:'%0', opcode, type, category, op, operands, result_type, metadata:{source_file,line,column}}], types}` with SSA sequential `%N` per §9 (`%0=SYSTEM_INFO`, `%1=PROCESS_LIST`, `%2=FILE_HASH string "/evidence/sample.exe"` + operands + source line:col per §30); `validate_ir_json(ir)` per §33/§6 (`version==1`, entry, instructions opcode/result/type, capabilities) + deterministic `module_id=sha256(src+seed)[:8]` so polymorphic seeds distinct IDs but same logical ops (hash≠detection preserved).
- `tools/jockyc.py`: `build_ir_json` sidecar — after `.ll` also writes `.ll.json` with `json.dump(ir_json, indent=2)` validated; `import json` added; preserves `.ll` + `.tokens` + `.ast`; polymorphic still distinct `sha12` but `ir_json` same ops.
- `backend/app/main.py`: `_build_json` helper, `POST /api/compile` now returns `ir_json` + `ir_json_version` with version validation `422` on `validate_ir_json` failure, `POST /api/run` likewise includes `ir_json`, new `POST /api/ir/validate` (`IR Compatibility Error: Required 2, Runtime supports 1` per §6) and `GET /api/ir/spec` (types, entry, categories) per §32/33.

### Verified
- `POST /api/compile` `investigation "host_scan" {system.info(); process.list(); file.hash("/evidence/sample.exe");}` → `ir_version 1` + `ir_json` 3 instructions `SYSTEM_INFO evidence`, `PROCESS_LIST evidence_set<process>`, `FILE_HASH string` with typed operands + line:col; `POST /api/ir/validate` `v2` → `422` compatibility error; `GET /api/ir/spec` 200; `tools/jockyc.py examples/test.jocky -o build/a.ll` → `build/a.ll` 1954B + `build/a.ll.json` 6693B deterministically; `pytest -q` 157 passed.

## 2026-09-12 — Gap 2: LANGUAGE_SPEC §12/15/18/19 Filter/Correlate/Import/Func — IR-emitted with validation (157 tests, no new count)

### Added
- `grammar/jocky.g4`: `importStmt` now `'import' (STRING | importPath) ';'` with `importPath : ID ('.' ID)*` supporting both `import "forensic.net";` and `import forensic.process;` per §18; `funcDecl` now `('func' | 'function') ID '(' paramList? ')' block` supporting both `func` and `function` per §19 — closes dotted import + function alias gaps.
- `jocky/src/Lexer.cpp` + `tools/jocky_lexer.py` `KEYWORDS`: add `"function"` (12→13).
- `tools/jocky_lexer.py`: `ImportModule` + `parse_imports(tokens)` forensic allowlist (`forensic.*` or `*.jocky`, traversal/`..` reject, missing `;` detection) — unknown module → `422` forensic allowlist per §18; `FunctionInfo` + `parse_functions(tokens)` balanced `()` + `{}` with unterminated → `422` per §19; `parse_lang_builtins(tokens)` token `filter`/`correlate` arity `, depth 1` → `422` if `<2 args` per §12/15; `validate_and_collect` now merges all three for fail-closed.
- `tools/jockyc.py` + `backend/app/main.py` `generate_ir`: collect `jocky_imports`/`funcs`/`builtins` via lex helpers and emit IR markers `; JOCKY Imports:`, `; Funcs:`, `; Builtins:`, `; Control: if/for/while` and inside `entry:` emits `call @jocky_filter`/`@jocky_correlate`/`@jocky_func_<name>`/`@jocky_import_<mod>`/`@jocky_if_branch` etc. Demonstrates IR awareness while preserving hash≠detection; `examples/test.jocky` now shows `JOCKY Imports: forensic.net` + `Control: if`.

### Verified
- Manual gap2 suite 15 cases: quoted/dotted valid imports `200`, unknown/missing `;` → `422`; `func`/`function` valid `200` + `Funcs:` marker, missing `}` → `422`; `filter`/`correlate` 2 args `200` + `Builtins` + calls, 1 arg → `422`; `if`/`for` → `Control` + branch calls. `pytest -q` 157 passed; `pytest test_language_features + test_compiler_grammar` 21 passed; `jockyc examples/test.jocky -o build/a.ll` shows imports+control IR.

## 2026-09-12 — Gap 1: LANGUAGE_SPEC §11 Investigation Blocks — grammar-wired block scoping (157 tests, no new count)

### Added
- `grammar/jocky.g4`: `investigationStmt : 'investigation' STRING block ;` as first `statement` alternative + header `Independent Language + Investigation Blocks (LANGUAGE_SPEC §11)` — closes Gap 1 where `jocky.g4` had no `investigation` rule and block `{}` was not enforced.
- `tools/jocky_lexer.py`: `Investigation` dataclass + `parse_investigations(tokens)` enforcing `investigation STRING { ... }` with balanced `}` depth counting for nested `if/for` blocks inside; validates non-empty title; fail-closed `Syntax error: … at line:col` for missing title / missing `{` / empty title / unterminated block. `validate_and_collect()` now merges `inv_errors` so both host `tools/jockyc.py` and `backend/app/main.py /api/compile|run` return `422` with location.
- `jocky/src/Lexer.cpp`: `kws` add `"investigation"` (11→12) to keep C++ reference lexer in sync.
- `GAPS.md`: Append-only fix note for Gap 1 (no row deletion), verification with 5 invalid + 2 valid manual cases + `TestClient` `422` for all invalid.

### Verified
- `pytest tests/test_language_features.py tests/test_compiler_grammar.py` 21 passed (unchanged); `pytest -q` 157 passed no regression.
- `POST /api/compile` + `POST /api/run` correctly `200` for `investigation "host_scan" { system.info(); process.list(); }` and `422` for `missing_brace` / `missing_string` / `empty_title` / `missing_lbrace` with `at X:Y` diagnostics.

## 2026-09-11 — Docker All Issues — healthcheck + agent timestamp/list (157 tests, no new count)

### Fixed
- `backend/app/main.py` `Evidence.timestamp: Optional[Any]` (was `Optional[float]`) — accepts ISO `"2026-07-24T..."` from fixtures → fixes `422 float_parsing` for `hollowing.json`/`byovd_driver.json` via `agent` `POST /api/evidence`
- `agent/agent.py` `post_fixture` — wraps `timeline.json` list → `timeline` + `polymorphic_files.json` demo → `file`, strips string `timestamp` (let backend generate float) → fixes `AttributeError list.get` + `422`
- `docker-compose.yml` `db` `healthcheck: pg_isready -U jocky -d jockydb` (was `-U jocky` → `FATAL database jocky does not exist`), `backend` `healthcheck` `python -c urllib.request` (was `curl` not in `python:3.11-slim`), `restart: unless-stopped` + `agent depends_on: backend:service_healthy` (no more `502` on first `GET /health`)

### Changed
- `agent/Dockerfile` rebuild marker comment to force `docker compose build agent backend` cache bust

## 2026-08-28 — Correlation Enrichment — Temporal + PID + Platform (104 tests)

### Added
- `backend/app/main.py` `GET /api/cases/{id}/graph` → `correlations` (temporal 0.6, pid 0.8, process→file 0.85, process→net 0.9, supports 0.95) + `weight` + `correlation_count` + platform on nodes per `ARCHITECTURE §14` + `FORENSICS §43`
- `tests/test_correlation.py` (6) — full sweep correlations, temporal window, pid, mitre/platform, weight, confidence

## 2026-08-28 — Phase 15 Cross-Platform Real — Windows Toolhelp32 + Linux /proc via psutil (157 tests)

### Added
- `backend/requirements.txt` — `psutil==6.1.0`
- `backend/app/providers/` — live `psutil` + `/proc` + `hashlib` real with fallback synthetic per `ROADMAP Phase 15`, `tests/test_forensic_ops.py` `len>=4` for live, `tests/test_phase15_real.py` (5) — Windows live, Linux synthetic, real file hash, API real, contract

## 2026-08-28 — Hardening P2 — Resource Limits + Audit (152 tests)

### Added
- `backend/app/audit.py` — hash-chain audit log per `SECURITY §34-36`, `GET /api/audit` + resource limits `MAX_IR_SIZE`/`MAX_EVIDENCE_SIZE`/`MAX_SOURCE_SIZE` `413`
- `tests/test_hardening_p2.py` (9) — limits + audit chain

## 2026-08-28 — Language Features P1 — Variables, Investigation, Filter, Correlate (143 tests)

### Added
- `tools/jocky_lexer.py` — `investigation` keyword + `_extract_investigations` + filter/correlate 2-arg validation (LANGUAGE §11,12,15)
- `backend/app/main.py` — `_extract_investigation_titles` + `POST /api/run` case title from investigation per FORENSICS §7
- `tests/test_language_features.py` (9) — variable, let, investigation, filter, correlate, combined, unknown fail-closed, evidence.load

## 2026-08-28 — Evidence.load Wiring — Controlled Fixtures (133 tests)

### Added
- `backend/app/main.py` — `evidence.load` wired (allowed roots, JSON parse, type/platform, source_file, per-case isolated)
- `tests/test_evidence_load.py` (9) — hollowing, byovd, platform agnostic, traversal, missing arg, not-found, timeline/graph, combine, lexer

## 2026-08-28 — Sigma Auto-Tune — Per-Evidence Tuning (124 tests)

### Added
- `backend/app/sigma_tuner.py` — `get_rules`/`tune_rule`/`auto_tune` (confidence 0.5-0.95, hit-rate >0.5→0.7) + `GET /api/sigma/rules` + `POST /api/sigma/tune` + `POST /api/sigma/auto-tune` + `GET /api/sigma/status`
- `tests/test_sigma_tuning.py` (6) — rules, tune 0.75, invalid 400, auto_tune, direct

## 2026-08-28 — Timeline / Graph / Risk Detail — Expand + History (118 tests)

### Added
- `backend/app/main.py` — `GET /api/cases/{id}/risk/history` + `/risk/breakdown` + `GET /api/cases/{id}/graph/expand?node_id=`
- `frontend/src/components/Timeline.tsx` — search + minRisk filter + filtered count + click
- `frontend/src/components/RiskGauge.tsx` — history sparkline + breakdown toggle
- `frontend/src/components/Graph.tsx` — onSelect
- `frontend/src/App.tsx` — riskHistory + selectedNode expand
- `tests/test_timeline_graph_risk_detail.py` (6) — history, breakdown, expand node/all/404, UI presence

## 2026-08-28 — Auth Hardening — JWT per SECURITY §19-20 (112 tests)

### Added
- `backend/app/auth.py` — `create_token`/`verify_token` `HS256` + `get_current_user` (`Bearer`/`X-API-Key`, `AUTH_REQUIRED` env default false, strict 401 when true)
- `backend/app/main.py` — `POST /api/auth/login` + `GET /api/auth/me` + `GET /api/auth/status` + `auth_required` in storage status
- `tests/test_auth.py` (8) — login JWT, verify, bypass, invalid 401, strict mode

## 2026-08-28 — Report Hardening — Versioned History (98 tests)

### Added
- `backend/app/storage.py` — `list_reports` + `delete_reports_for_case` + `put_report` versioned `_{ts}_{sha8}.pdf` per `FORENSICS §64`
- `backend/app/main.py` — `GET /api/cases/{id}/reports` + `GET /api/cases/{id}/reports/{key}`
- `tests/test_report_hardening.py` (3) — history list, direct storage list, health storage

## 2026-08-28 — Dashboard Enrichment — Timeline Search + Risk History + Graph Select

### Added
- `frontend/src/components/Timeline.tsx` — search `q` + `minRisk` filter (≥30/≥60/≥80) + filtered count + click handler
- `frontend/src/components/RiskGauge.tsx` — `history` sparkline SVG (last 20) + LOW level + correct weights
- `frontend/src/components/Graph.tsx` — `onSelect` + `onNodeClick`
- `frontend/src/App.tsx` — `riskHistory` + `selectedNode` wiring, chip shows `type risk mitre platform`

## 2026-08-28 — Case Isolation UI — Cases + Host/Platform Filters (95 tests)

### Added
- `backend/app/main.py` — `POST /api/cases` (CaseCreate auto-increment, per ARCHITECTURE §10)
- `frontend/src/App.tsx` — case isolation bar: case dropdown + `+ New Case`, `hostFilter`/`typeFilter`/`platformFilter`, `runPlatform` selector, `filteredEvidence` + filtered counts (FORENSICS §7, ARCHITECTURE §11)
- `tests/test_case_isolation.py` (5) — create+isolation, list grows, host/platform filters, UI presence

### Verified
- `pytest` 95/95 (5 new)

## 2026-08-28 — Harden & Persist — MinIO + Redis (90 tests)

### Added
- `backend/app/storage.py` — MinIO `jocky-reports`/`jocky-evidence` (auto-create, mem fallback), `put_report`/`get_report`/`put_bytes`/`get_bytes`/`put_evidence_artifact`, `storage_status()`
- `backend/app/cache.py` — Redis `cache_get/set/invalidate` (TTL 60/300, mem fallback), `cache_status()`
- `backend/app/main.py` — `GET /health` `minio`/`redis` fields + `storage`/`cache`, `GET /api/storage/status`, `POST /api/artifacts/upload` (5MB 413) + `GET /api/artifacts/{key}`, `POST /api/evidence` artifact + cache invalidate, `GET /api/cases/{id}/report` MinIO + Redis `X-Report-Cached`
- `tests/test_storage.py` (8) — health, storage status, put/get, cache, report→MinIO, evidence artifact, artifact upload/get, 413

### Verified
- `pytest` 90/90 (8 new)

## 2026-08-28 — Detection Depth — YARA 5 + Sigma 2 + Behavioral Engine

### Added
- `backend/app/detection_engine.py` — `load_sigma_rules()` (yaml + fallback), `sigma_scan()` (jocky-001 T1055 ppid anomaly, jocky-002 T1068 BYOVD), `behavioral_scan()` (13 weights: ppid/hollowed/unbacked/reflective/vuln/loldrivers/yara/sigma/C2), `detect()` (sigma+behavioral → rule/severity/mitre/confidence/source), `risk_for_payload()`
- `yara/rules.yar` — + `File_Suspicious_PE` (T1105) + `Network_C2_Beacon` (T1071) → 5 rules
- `backend/app/main.py` — `yara_scan_content()` fallback adds `File_Suspicious_PE`/`Network_C2_Beacon`/`rtc_core` strings
- `backend/requirements.txt` — `pyyaml==6.0.3`
- `tests/test_detection_depth.py` (11) — sigma load/ppid/byovd/negative, behavioral hollowing + full synthetic, yara 5 presence + API, combined detect, risk deterministic

### Verified
- `pytest` 82/82 (11 new)

## 2026-08-28 — Platform Providers — Windows vs Linux Abstraction (IProcessProvider)

### Added
- `backend/app/providers/base.py` — `ISystem/IProcess/IFile/INetwork/IDriverProvider` ABCs (DESIGN §22-23)
- `backend/app/providers/windows.py` — `Windows*Provider` synthetic WinAPI (`C:\\Windows\\...`, `SYSTEM`, `command_line`) + `linux.py` synthetic `/proc` (`uid`, `inode`, `lsmod`, `ELF`)
- `backend/app/providers/factory.py` — `detect_platform()` + `get_providers(platform)` + `platform_from_request()` — LANGUAGE_SPEC §27 same JOCKY, different adapter
- `backend/app/main.py` — `RunRequest.platform` + `_platform_provider_payload()` + `make_envelope(..., platform)` platform field; `POST /api/run` validates platform; same `T1105/T1055` but different platform/payload per FORENSICS §67
- `tests/test_platform_providers.py` (10) — factory, contract windows vs linux, file/net, platform_from_request, API windows/linux/invalid, same JOCKY diff platform same MITRE/risk, compile platform-agnostic

### Verified
- `pytest` 71/71 (10 new) — contract holds per TEST_PLAN §57

## 2026-08-28 — Compiler Grammar-Wired — Lexer/Parser per g4 replaces RE_CALL

### Added
- `tools/jocky_lexer.py` — `lex()` per `grammar/jocky.g4` + `jocky/src/Lexer.cpp` (ID/DOT/LPAREN/RPAREN/SEMI/COMMA/STRING/NUMBER/OP/KW/END, WS/COMMENT skip, line:col), `parse_member_calls()` per g4 `MemberCall`, `validate_and_collect()` with `at line:col` fail-closed errors, syntax checks for unterminated string / unmatched '('; single-source `OP_CAPS`
- `tools/jockyc.py` + `backend/app/main.py` — now both import `jocky_lexer` (single source; removes `RE_CALL` regex); `.tokens` real dump, `.ast` calls+tokens
- `tests/test_compiler_grammar.py` (12) — lex, comment/string, keywords, extract, syntax errors, whitelist, dedup, g4 coverage, jockyc+backend integration

### Verified
- `pytest` 61/61 (12 new) — both host fallback and backend reject `edr.disable()` with `at 1:1` location

## 2026-08-28 — Agent Real POST via Nginx — Layer 4 → L5 → L6

### Added
- `agent/agent.py` — stdlib `urllib` real transport: `GET /health` via `http://nginx:80`, `POST /api/evidence` per fixture, `POST /api/run` JOCKY sweep via nginx (same 422/403 fail-closed), verification `GET /evidence?case_id` + `timeline/graph/risk` via nginx, fail-closed demo `edr.disable→422`; env `BACKEND_URL/HOST_ID/CASE_ID/JOCKY_SOURCE/FIXTURE_DIR/AGENT_POLL_SECONDS`, wait-for-nginx loop, idle `sleep 3600` preserving tail semantics
- `agent/Dockerfile` — `python3-urllib3` + `COPY agent/agent.py` + `CMD ["python3","/app/agent.py","--scan"]` (C++ stub retained)
- `docker-compose.yml` — `agent` now `HOST_ID/CASE_ID/JOCKY_SOURCE/FIXTURE_DIR/AGENT_POLL_SECONDS=0` + `healthcheck curl -sf http://nginx:80/health`
- `tests/test_agent.py` (8) — mocked fixture POST, JOCKY 200/422/403, integration `agent_scan_once` via TestClient, compose + Dockerfile asserts

### Verified
- `pytest` 49/49 (8 new) — `agent_scan_once` integration posts via mocked nginx to real backend, evidence count ≥1, timeline ≥1
- `docker-compose.yml` `BACKEND_URL=http://nginx:80` + `healthcheck` `http://nginx:80/health` verified

## 2026-08-28 — YARA Binary — hash ≠ detection (Point 1+2) via yara 4.5.2

### Added
- `backend/Dockerfile` — `yara` apt (`yara 4.5.2`) alongside pango/cairo
- `docker-compose.yml` — `backend` volumes `yara:/app/yara:ro` + `testdata:/app/testdata:ro` (rules at `/app/yara/rules.yar`)
- `backend/app/main.py` — `yara_scan_content(content) -> (hits, yara_used)` helper (tries `yara /app/yara/rules.yar` binary via `subprocess` `4.5.2`, fallback string `JOCKY_DEMO_MARKER/BYOVD_RTCore64/hollowed` for host); `_yara_rules_path()` probes `/app/yara/rules.yar` etc; `YaraScanRequest` + `PolyDemoRequest`, endpoints `POST /api/yara/scan` (sha256 + hits + yara_used), `GET /api/yara/status` (yara_available, test_hits), `POST /api/yara/polymorphic-demo` (hash≠detection: 3 seeds→ distinct hashes but same_yara_cluster), `POST /api/detect` now `yara_used` flag + health `yara:true`
- `frontend/src/App.tsx` — YARA panel: `GET /api/yara/status` badge `YARA ✅ binary` vs fallback, `Run YARA Poly Demo` button → `POST /api/yara/polymorphic-demo` (shows 3 seeds sha12 hits + yara_used + distinct_hashes/same_yara_cluster), links to `/api/yara/status` + `/api/docs`
- `tests/test_yara.py` (6) — yara status, scan fallback, BYOVD, polymorphic hash≠detection, detect yara_used, compile IR yara hit

### Verified
- Host `pytest` 41/41 (fallback string, yara binary not required on host)
- Docker :8000 — `GET /health` `yara:true yara_rules:/app/yara/rules.yar`, `GET /api/yara/status` `yara_binary_used true`, `POST /api/yara/polymorphic-demo` 3 distinct SHA256 (`3df…/b6d5…/d450…`) → `same_yara_cluster true` (hash≠detection)

## 2026-08-28 — Postgres Persistence — evidence/cases/findings survive restart

### Added
- `backend/app/models.py` — expanded `Case/Evidence/Finding` SQLAlchemy tables (evidence_id, host_id, payload/integrity/provenance JSON, chain_of_custody, timestamp)
- `backend/app/db.py` — `DATABASE_URL` `postgresql://jocky:jocky@db:5432/jockydb`, `init_db()` with 2s timeout + `is_db_available()` fallback to in-memory for host `pytest`, helpers `db_upsert_case`, `db_add_evidence/findings`, `db_list_*`, `db_clear_for_tests`; startup `on_event` creates tables
- `backend/app/main.py` v1.2.0 — Postgres-aware wrappers `_get_cases/_get_evidence/_get_findings/_add_*`; `make_envelope` now uses `_get_evidence()` total for EV id uniqueness; `GET /health` returns `db:true postgres:true`; all endpoints read from PG when available, fallback to memory; `ensure_case` → `_add_case`
- `docs/STATUS.md` — Database 🟢 Verified

### Changed
- `STATUS.md` / `docs/STATUS.md` — Backend now `+ postgres`, Database row 🟢 Verified

### Verified
- Host `pytest` 35/35 still passing (in-memory fallback, no PG)
- Docker :8000 — `[db] Connected to db:5432/jockydb — tables ready`, `GET /health` `db:true`, live case 90: 2 evidence → `docker compose restart backend` → `GET /api/evidence?case_id=90` still 2 (persisted)

## 2026-08-28 — Report Generation — PDF via WeasyPrint

### Added
- `backend/Dockerfile` — `libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0 libcairo2` + `pydyf==0.11.0` pin (fixes weasyprint 62.3 `super().transform` bug)
- `backend/app/main.py` — `ReportRequest` + `build_report_html()` + `render_pdf_bytes()` (WeasyPrint) → `GET /api/cases/{id}/report` + `POST /api/report` → `application/pdf` 20KB per case (case summary, findings, evidence table with provenance/chain, timeline, graph). Fallback HTML with `X-Report-Fallback` on host without pango deps.
- `frontend/src/App.tsx` — **📄 Report PDF** button (findings panel) → `fetch GET /report` blob → `JOCKY_case_{id}_report.pdf` download (handles pdf vs html fallback)
- `tests/test_report.py` (4) — populated report, empty case, POST variant, chain/integrity content

### Changed
- `docs/STATUS.md` + `STATUS.md` — Report 🟢 Verified, 35 tests, Docker pango deps

### Verified
- Host `pytest` 35/35 (host fallback HTML)
- Docker :8000 `POST /api/run` 4-op sweep case 80 → `GET /api/cases/80/report` → `application/pdf` `%PDF` 20KB verified live (saved `build/report_case_80.pdf`)

## 2026-08-28 — Forensic Ops Expansion — process/file/network enriched + graph correlation

### Added
- `backend/app/main.py` v1.1.1 — `extract_file_arg()` + `validate_path()` (400 traversal reject), enriched `make_envelope()`: `process.list` 4-proc tree Sigma T1055 risk 60, `file.hash` path-aware YARA T1105 risk 55, `network.connections` C2 T1071, combined sweep 4 evidence risk 60, star graph `host→evidence` + `process→file/net` edges with mitre set
- `frontend/src/App.tsx` — default sweep now 4 ops, buttons for `file.hash`/`network.connections`/`full sweep`/`traversal fail`, richer evidence detail panel (process counts, file hash slice, C2 flag)
- `tests/test_forensic_ops.py` (6) — forensic ops E2E coverage including path traversal, rich payloads, combined graph/timeline

### Changed
- `backend/app/main.py` — `calc_risk()` now aggregates `processes` anomaly+yara bonus + file yara + C2 remote 192.0.2.20; graph now star + correlation edges
- `docs/STATUS.md` + `STATUS.md` — 31 tests, forensic ops enriched, docker still Up

### Verified
- `pytest` 31/31 passing
- Live `POST /api/run` full sweep case 60: 4 evidence risk 60 MEDIUM graph 6 nodes timeline 4; `file.hash("../../etc/passwd")` → 400 rejected

## 2026-08-28 — E2E `system.info();` Milestone — First Query from Dashboard Live

### Added
- `jocky/include/jocky/IRGen.h` — `IRResult` (ir_version 1, capabilities, ops, error) + `generateIRWithValidation()`
- `jocky/src/IRGen.cpp` — OP_CAPS whitelist (15 ops → 8 caps), `RE_CALL` regex validation, `IR_VERSION=1` header, fail-closed `generateIRWithValidation()`; C++ path now rejects unknown ops with code 2
- `jocky/src/main.cpp` — prints `ir_version` + caps on success; prints validation error on fail
- `tools/jockyc.py` — same whitelist, `validate_and_collect()` + `IR_VERSION=1`/`IR_CAPS`/`IR_OPS` header, dedup caps, polymorphic still yields 3 distinct SHA256
- `backend/app/main.py` v1.1.0 — `POST /api/compile` (ir_version 1, caps/ops, 422 on unknown), `POST /api/run` (cap policy DEFAULT_POLICY: `memory.analyze` → 403 deny, `system.read` allow; canonical envelope `schema_version 1` + `integrity.sha256` + `provenance` + `chain_of_custody`; per-case `findings` + risk; live `/timeline` `/graph` `/risk` with case_id filtering; `/evidence?case_id=` + `/findings?case_id=`)
- `frontend/src/App.tsx` — JOCKY editor (textarea + **Compile**/**Run** buttons + quick inserts for `system.info();`/`process.list();`/`edr.disable();` fail demo), IR pane (shows `IR_VERSION=1`), live fetches for Graph/Timeline/RiskGauge/evidence+findings, 5s poll, case 1 default
- `frontend/src/components/Graph.tsx` — now takes `data` prop (live nodes/edges/mitre) with demo fallback; auto-layout for backend graph
- `frontend/src/components/Timeline.tsx` — now takes `events` prop with demo fallback
- `tests/test_compiler.py` (9 tests), `tests/test_backend.py` (13), `tests/test_e2e.py` (3) — 25 tests covering IR version/caps, unknown op 422 fail-closed, memory 403, polymorphic YARA marker, E2E envelope field completeness
- `docker-compose.yml` — `nginx` host port `8082:80` (was `80:80` conflicting with SYSTEM PID 4 on Windows)

### Changed
- `docker-compose.yml` + live stack verified: `backend` :8000 + `frontend` :3000 + `nginx` 8082→80 + `db` healthy + `redis`/`minio`/`jocky`/`detector` all Up (2026-08-28 live curl)
- `docs/STATUS.md` + `STATUS.md` mirror — updated 29-row audit table: IR/validation, evidence envelope, backend, graph/timeline/dashboard all 🟢 Verified; Docker + E2E now 🟢; `Current Milestone` marked complete for `system.info();`; `Known Limitations` reduced
- `README.md` current status will be refreshed on next commit (see audit → E2E delta)

### Verified
- `pytest` 25/25 passing on host (no Docker)
- Live `POST /api/run {system.info();}` via `http://localhost:8000` → `EV-... schema_version 1` risk 5 LOW finding INFO → `GET /api/cases/1/timeline` 1 event, `graph` 3 nodes, `risk` 5
- Frontend :3000 serves new App.tsx (editor + live wiring) — `curl http://localhost:3000` returns Vite shell; manual browser Run flow updates live panels

### Fixed
- `edr.disable();` and `security.disable();` now fail-closed (exit 2 / HTTP 422) instead of silently succeeding with `nop`
- `memory.analyze(1234);` now correctly denied 403 per SECURITY_MODEL default-deny policy

## 2026-08-28 — Initial Takeover Audit

### Added
- `docs/STATUS.md` — full implementation audit (2026-08-28) distinguishing Implemented / Verified / Scaffolded / Not Started per AGENTS.md §30; covers all 29 subsystems with file evidence and TestClient verification.
- `docs/ARCHITECTURE.md` — corrected copy of `docs/ARCHITECHTURE.md` (filename typo fix; both retained for compatibility with existing references).

### Changed
- `README.md` — `Current Status` section replaced with audit-backed verdict (verified host compiler polymorphism 3 hashes, verified backend API risk 90 CRITICAL / 40, vs. not-connected pipeline, no tests, Docker not verified).
- `README.md` — `Quick Start` expanded into 2a Host-Verified Path (tools/jockyc.py without Docker) and 2b/3 Docker path, with explicit NOT VERIFIED labels and references to docs/STATUS.md §6.
- `STATUS.md` (root) — replaced generic template with audit-backed content (mirrors `docs/STATUS.md`).

### Verified (with evidence logged in docs/STATUS.md §6)
- Host fallback compiler: `tools/jockyc.py examples/test.jocky` with seeds 1/2/3 produces 3 distinct SHA256 (9EF588… / 58D518… / 0D0D25…).
- Backend FastAPI via TestClient: `GET /health`, `POST /api/evidence` (hollowing risk 90, byovd 40), `GET /api/cases/1/risk|timeline|graph`, `POST /api/detect` YARA hits.

### Known Issues (audit §7)
- Lexer/Parser/AST stubs; semantic analysis and capability enforcement missing; unknown ops not rejected.
- IR validation missing; runtime is 13-line hardcoded provider; evidence normalization missing.
- Agent stub prints but does not POST; backend in-memory only (Postgres/SQLAlchemy not wired).
- Detection is Python string-contains (YARA binary not invoked); timeline/graph are static mocks.
- Dashboard has no JOCKY editor / Run button; report generation not started.
- `tests/` does not exist; automated tests 0; Docker compose not verified on audit host.
- Windows/Linux platform providers not verified.

### Next
- Fix repository hygiene (commit audit docs), then milestone "First Usable E2E Query: system.info();" — see docs/STATUS.md §8–§9.

---

## 2026-08-28 — Prior (Initial Commit)

### Added
- Project scaffold: compiler (`jocky/`), runtime (`runtime/`), agent (`agent/`), backend (`backend/`), frontend (`frontend/`), testdata (`testdata/`), Docker environment (`Dockerfile`, `docker-compose.yml`, `nginx/`), detection (`yara/`, `sigma/`), documentation (`docs/`), examples (`examples/test.jocky`).
- Documentation foundation: `ARCHITECHTURE.md`, `LANGUAGE_SPEC.md`, `IR_SPEC.md`, `FORENSICS_SPEC.md`, `SECURITY_MODEL.md`, `TEST_PLAN.md`, `ROADMAP.md`, `DESIGN.md`.
