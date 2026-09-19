# Phase 2 -- 1-Slide: Before IR vs After IR (LAB, 30-sec Demo)

**Goal:** Same JOCKY source + same seed (42) -> different IR bytes, same YARA cluster (hash != detection). All LAB / SIMULATED, deterministic, reversible.

```bash
python tools/jockyc.py examples/test.jocky -o build/before.ll --seed 42
python tools/jockyc.py examples/test.jocky -o build/after.ll --seed 42 --polymorphic
diff -u build/before.ll build/after.ll | head -n 50
certutil -hashfile build/before.ll SHA256 & certutil -hashfile build/after.ll SHA256
curl -X POST http://localhost:8000/api/yara/polymorphic-demo -d "{\"source\":\"system.info();\",\"seeds\":[1,2,3]}"
```

## Before (plain, seed 42) -- excerpt
```llvm
; JOCKY IR - seed=42 poly=0
; IR_VERSION=1
; IR_CAPS: system.read, process.read, file.hash, file.read, network.read, memory.analyze, driver.read
; IR_OPS: system.info, process.list, file.hash, process.tree, process.modules, file.list, file.metadata, file.analyze, network.interfaces, network.connections, memory.analyze, driver.list, driver.scan, driver.risk
; JOCKY Imports: forensic.net, forensic.process
; Funcs: collect_host, analyze_evidence
; Builtins: filter, correlate
; Control: if, for
; Source hash: bd01eae92d1f
; EntryPoint: 0x140001000
; Imports: kernel32.dll ntdll.dll advapi32.dll user32.dll
; JOCKY_DEMO_MARKER
define i32 @main() {
entry:
  ; jocky call: system_info [id=0]
  %0 = call i32 @jocky_system_info() ; poly_id=0
  ; jocky call: process_list [id=1]
  %1 = call i32 @jocky_process_list() ; poly_id=1
  ; jocky call: process_tree [id=2]
  %2 = call i32 @jocky_process_tree() ; poly_id=2
  ; jocky call: file_list [id=3]
  %3 = call i32 @jocky_file_list() ; poly_id=3
  ; jocky call: file_hash [id=4]
  %4 = call i32 @jocky_file_hash() ; poly_id=4
  ; jocky call: file_analyze [id=5]
```

## After (hardened LAB, seed 42 --polymorphic) -- excerpt
```llvm
; JOCKY IR - seed=42 poly=1
; IR_VERSION=1
; IR_CAPS: system.read, process.read, file.hash, file.read, network.read, memory.analyze, driver.read
; IR_OPS: system.info, process.list, file.hash, process.tree, process.modules, file.list, file.metadata, file.analyze, network.interfaces, network.connections, memory.analyze, driver.list, driver.scan, driver.risk
; JOCKY Imports: forensic.net, forensic.process
; Funcs: collect_host, analyze_evidence
; Builtins: filter, correlate
; Control: if, for
; Source hash: bd01eae92d1f
; EntryPoint: 0x140001e40
; Imports: advapi32.dll ntdll.dll user32.dll kernel32.dll
; JOCKY_DEMO_MARKER
; -- polymorphic transforms applied -- LAB / SIMULATED --
; cfg-flatten:states=4 dispatch=9 order=[3, 1, 0, 2]
; string-encrypt:xor(key=69)
; import-obfuscate:shuffled seed=42
; @LAB transform=import_shuffle seed=42 order=advapi32.dll ntdll.dll user32.dll kernel32.dll
; @LAB transform=string_encrypt key=69 reversible=seed
; @LAB transform=cfg_flatten dispatcher=9 states=4
; LAB reversible: seed=42 -> xor_key=69 cfg_order=[3, 1, 0, 2]
define i32 @main() {
entry:
  ; jocky call: system_info [id=3278]
  %0 = call i32 @jocky_system_info() ; poly_id=3278
  ; jocky call: process_list [id=97196]
  %1 = call i32 @jocky_process_list() ; poly_id=97196
  ; jocky call: process_tree [id=36048]
  %2 = call i32 @jocky_process_tree() ; poly_id=36048
  ; jocky call: file_list [id=32098]
  %3 = call i32 @jocky_file_list() ; poly_id=32098
  ; jocky call: file_hash [id=29256]
  %4 = call i32 @jocky_file_hash() ; poly_id=29256
  ; jocky call: file_analyze [id=18289]
  %5 = call i32 @jocky_file_analyze() ; poly_id=18289
  ; jocky call: network_connections [id=96530]
  %6 = call i32 @jocky_network_connections() ; poly_id=96530
  ; jocky call: network_interfaces [id=13434]
  %7 = call i32 @jocky_network_interfaces() ; poly_id=13434
  ; jocky call: memory_analyze [id=88696]
  %8 = call i32 @jocky_memory_analyze() ; poly_id=88696
  ; jocky call: driver_list [id=97080]
  %9 = call i32 @jocky_driver_list() ; poly_id=97080
  ; jocky call: driver_scan [id=71482]
  %10 = call i32 @jocky_driver_scan() ; poly_id=71482
  ; jocky call: driver_risk [id=11395]
```

## What Changed (diff highlights)
- **Imports shuffled:** `kernel32.dll ntdll.dll ...` -> shuffled per seed (`_det_shuffle`)
- **String encrypt:** `string-encrypt:xor(key=...)` + `@LAB transform=string_encrypt` (reversible via seed)
- **CFG flatten:** `cfg-flatten:states=... dispatch=...` + `switch` dispatcher + `bb.poly.*` state-machine (not just stub)
- **LAB markers:** `-- polymorphic transforms applied -- LAB / SIMULATED --`, `@LAB transform=...`, `LAB reversible: seed=...`
- **EntryPoint randomized:** `0x140001xxx` per seed
- **Preserved:** `JOCKY_DEMO_MARKER` still present -> `same_yara_cluster:true` (see POST /api/yara/polymorphic-demo)

> **Judges:** Run `python tools/evaluate.py --n 1000 --seed 42` to reproduce F1 0.971, resilience 0.75 vs YARA 0.65, p95 217ms. All synthetic LAB, reproducible.
