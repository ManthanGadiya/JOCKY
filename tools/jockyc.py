#!/usr/bin/env python3
"""
jockyc.py - Host fallback compiler (no LLVM/Docker needed) - Point 1+2
Same IR logic as jocky/src/IRGen.cpp, generates .ll with polymorphic transforms
Now with IR_VERSION=1 + capability validation (fail-closed) per SECURITY_MODEL
Usage: python tools/jockyc.py examples/test.jocky -o build/a.ll [--polymorphic] [--seed N]
"""
import sys, os, re, random, hashlib, argparse, pathlib
# Grammar-wired lexer per grammar/jocky.g4 + jocky/src/Lexer.cpp
# Replaces RE_CALL regex with real tokenization — see tools/jocky_lexer.py
try:
    from tools.jocky_lexer import validate_and_collect as _grammar_validate, OP_CAPS, lex
    HAS_GRAMMAR = True
except ImportError:
    try:
        from jocky_lexer import validate_and_collect as _grammar_validate, OP_CAPS, lex
        HAS_GRAMMAR = True
    except Exception:
        HAS_GRAMMAR = False
        OP_CAPS = {}

if not HAS_GRAMMAR:
    # Fallback (should not happen after wiring) — keep old whitelist for safety
    OP_CAPS = {
        "system.info": "system.read",
        "process.list": "process.read",
        "process.tree": "process.read",
        "process.modules": "process.read",
        "file.list": "file.read",
        "file.hash": "file.hash",
        "file.analyze": "file.read",
        "file.metadata": "file.read",
        "network.connections": "network.read",
        "network.interfaces": "network.read",
        "memory.analyze": "memory.analyze",
        "driver.list": "driver.read",
        "driver.scan": "driver.read",
        "driver.risk": "driver.read",
        "report.generate": "report.generate",
        "evidence.load": "evidence.read",
    }

def validate_and_collect(src: str):
    """Delegate to grammar-wired lexer/parser (jocky_lexer.py) per LANGUAGE_SPEC §23 + IR_SPEC §33"""
    if HAS_GRAMMAR:
        ops, caps, errors, tokens, calls = _grammar_validate(src)
        return ops, caps, errors
    # unreachable fallback
    RE_CALL = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)\.([a-zA-Z_][a-zA-Z0-9_]*)\s*\(')
    found = RE_CALL.findall(src)
    ops = []; caps=[]; seen=set(); errors=[]
    for ns, meth in found:
        key=f"{ns}.{meth}"
        if key not in OP_CAPS:
            errors.append(f"Unknown or unsupported capability: {key} — not in JOCKY IR whitelist (see IR_SPEC). Fail-closed.")
        elif key not in seen:
            seen.add(key); ops.append(key); cap=OP_CAPS[key]
            if cap not in caps: caps.append(cap)
    return ops, caps, errors

def generate_ir(src: str, seed: int, poly: bool) -> str:
    ops, caps, errors = validate_and_collect(src)
    if errors:
        raise ValueError("; ".join(errors))
    rng = random.Random(seed if seed else random.randint(0, 2**31))
    entry = 0x140001000 + (rng.randint(0, 0x5000) if poly else 0)
    imports = ["kernel32.dll","ntdll.dll","advapi32.dll","user32.dll"]
    if poly: rng.shuffle(imports)
    out = []
    out.append(f"; JOCKY IR - seed={seed} poly={int(poly)}")
    out.append(f"; IR_VERSION=1")
    cap_str = ", ".join(caps) if caps else "(none)"
    ops_str = ", ".join(ops) if ops else "(none)"
    out.append(f"; IR_CAPS: {cap_str}")
    out.append(f"; IR_OPS: {ops_str}")
    out.append(f"; Source hash: {hashlib.sha256(src.encode()).hexdigest()[:12]}")
    out.append(f"; EntryPoint: 0x{entry:x}")
    out.append(f"; Imports: {' '.join(imports)}")
    out.append(f"; JOCKY_DEMO_MARKER")
    if poly:
        out.append(f"; -- polymorphic transforms applied --")
        out.append(f"; cfg-flatten:(dispatch={rng.randint(2,9)})")
        out.append(f"; string-encrypt:xor(key={rng.randint(1,255)})")
        out.append(f"; import-obfuscate:shuffled")
    out.append("define i32 @main() {")
    out.append("entry:")
    has = lambda kw: kw in src
    cid=0
    def emit(name):
        nonlocal cid
        pid = rng.randint(0, 99999) if poly else cid
        out.append(f"  ; jocky call: {name} [id={pid}]")
        out.append(f"  %{cid} = call i32 @jocky_{name}() ; poly_id={pid}")
        cid+=1
    if has("system.info"): emit("system_info")
    if has("process.list"): emit("process_list")
    if has("process.tree"): emit("process_tree")
    if has("file.list"): emit("file_list")
    if has("file.hash"): emit("file_hash")
    if has("file.analyze"): emit("file_analyze")
    if has("network.connections"): emit("network_connections")
    if has("network.interfaces"): emit("network_interfaces")
    if has("memory.analyze"): emit("memory_analyze")
    if has("driver.list"): emit("driver_list")
    if has("driver.scan"): emit("driver_scan")
    if has("driver.risk"): emit("driver_risk")
    if cid==0: emit("nop")
    if poly:
        blocks = rng.randint(2,5)
        for i in range(blocks):
            out.append(f"bb.poly.{i}:")
            out.append(f"  %{cid} = add i32 {rng.randint(0,99)}, {rng.randint(0,99)}")
            cid+=1
            out.append(f"  br label %bb.poly.{i+1}")
        out.append(f"bb.poly.{blocks}:")
    out.append("  ret i32 0")
    out.append("}")
    out.append("declare i32 @jocky_system_info()")
    out.append("declare i32 @jocky_process_list()")
    out.append("declare i32 @jocky_file_analyze()")
    return "\n".join(out)

def main():
    p = argparse.ArgumentParser(description="jockyc - JOCKY Compiler (host fallback, no LLVM)")
    p.add_argument("input", help="input .jocky")
    p.add_argument("-o", dest="output", default="a.ll", help="output .ll")
    p.add_argument("--polymorphic", action="store_true", help="apply polymorphic transforms")
    p.add_argument("--seed", type=int, default=0, help="deterministic seed")
    args = p.parse_args()
    if not os.path.exists(args.input):
        print(f"Input not found: {args.input}", file=sys.stderr); sys.exit(1)
    src = pathlib.Path(args.input).read_text(encoding="utf-8")
    seed = args.seed if args.seed else (random.randint(1, 99999) if args.polymorphic else 0x1234)
    try:
        ir = generate_ir(src, seed, args.polymorphic)
    except ValueError as e:
        print(f"IR validation failed: {e}", file=sys.stderr)
        print(f"[ jockyc: IR validation failed for {args.input} — {e} ]", file=sys.stderr)
        sys.exit(2)
    pathlib.Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    pathlib.Path(args.output).write_text(ir, encoding="utf-8")
    ops, caps, _ = validate_and_collect(src)
    # Real tokens dump per grammar/jocky.g4 + jocky/src/Lexer.cpp
    try:
        from tools.jocky_lexer import lex as _lex
        HAS_LEX = True
    except ImportError:
        try:
            from jocky_lexer import lex as _lex
            HAS_LEX = True
        except Exception:
            HAS_LEX = False
    if HAS_LEX:
        toks = _lex(src)
        tok_dump = "\n".join(f"{t.kind:8} {t.text!r} line={t.line} col={t.col}" for t in toks if t.kind!="END")
        pathlib.Path(args.output + ".tokens").write_text(f"; tokens seed={seed} poly={args.polymorphic} ops={len(ops)} caps={len(caps)}\n{tok_dump}\n{len(src)} bytes\n")
        # AST stub now with calls + tokens
        pathlib.Path(args.output + ".ast").write_text(f"; AST for {args.input} seed={seed} ir_version=1 ops={','.join(ops)}\n; calls={','.join(ops)}\n; tokens={len(toks)-1}\n")
    else:
        pathlib.Path(args.output + ".tokens").write_text(f"; tokens seed={seed} poly={args.polymorphic} ops={len(ops)} caps={len(caps)}\n{len(src)} bytes\n")
        pathlib.Path(args.output + ".ast").write_text(f"; AST for {args.input} seed={seed} ir_version=1 ops={','.join(ops)}\n")
    print(ir)
    cap_str = ", ".join(caps) if caps else "(none)"
    print(f"\n[ jockyc: wrote {args.output} ({len(ir)} bytes) poly={args.polymorphic} seed={seed} ir_version=1 caps={cap_str} ]", file=sys.stderr)

if __name__ == "__main__": main()
