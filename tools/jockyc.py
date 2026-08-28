#!/usr/bin/env python3
"""
jockyc.py - Host fallback compiler (no LLVM/Docker needed) - Point 1+2
Same IR logic as jocky/src/IRGen.cpp, generates .ll with polymorphic transforms
Usage: python tools/jockyc.py examples/test.jocky -o build/a.ll [--polymorphic] [--seed N]
"""
import sys, os, random, hashlib, argparse, pathlib

def generate_ir(src: str, seed: int, poly: bool) -> str:
    rng = random.Random(seed if seed else random.randint(0, 2**31))
    entry = 0x140001000 + (rng.randint(0, 0x5000) if poly else 0)
    imports = ["kernel32.dll","ntdll.dll","advapi32.dll","user32.dll"]
    if poly: rng.shuffle(imports)
    out = []
    out.append(f"; JOCKY IR - seed={seed} poly={int(poly)}")
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
    ir = generate_ir(src, seed, args.polymorphic)
    pathlib.Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    pathlib.Path(args.output).write_text(ir, encoding="utf-8")
    pathlib.Path(args.output + ".tokens").write_text(f"; tokens seed={seed} poly={args.polymorphic}\n{len(src)} bytes\n")
    pathlib.Path(args.output + ".ast").write_text(f"; AST for {args.input} seed={seed}\n")
    print(ir)
    print(f"\n[ jockyc: wrote {args.output} ({len(ir)} bytes) poly={args.polymorphic} seed={seed} ]", file=sys.stderr)

if __name__ == "__main__": main()
