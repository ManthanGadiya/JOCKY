#!/usr/bin/env python3
"""
perf_bench.py — Gap 8 Performance / Reliability per ROADMAP Phase 17
Measures compile/IR/API latency without external k6/pytest-benchmark.
Deterministic, host-only, no Docker required. Results stored in build/perf.json per FORENSICS reproducibility.
"""
import time, json, pathlib, hashlib, statistics, sys
# Ensure project root on path when run as python tools/perf_bench.py
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))
try:
    from tools.jocky_lexer import validate_and_collect, build_ir_json
except ImportError:
    from jocky_lexer import validate_and_collect, build_ir_json
from fastapi.testclient import TestClient
from backend.app.main import app

def bench_compile(n=100):
    src='investigation "bench" { system.info(); process.list(); file.hash("/evidence/sample.exe"); network.connections(); }'
    times=[]
    for i in range(n):
        t0=time.perf_counter()
        validate_and_collect(src)
        build_ir_json(src, seed=i, poly=False)
        times.append((time.perf_counter()-t0)*1000)
    return {"samples": n, "avg_ms": statistics.mean(times), "p95_ms": sorted(times)[int(n*0.95)], "min_ms": min(times), "max_ms": max(times)}

def bench_api(n=50):
    c=TestClient(app)
    src='system.info(); process.list();'
    times=[]
    for i in range(n):
        t0=time.perf_counter()
        r=c.post("/api/compile", json={"source": src, "seed": i})
        assert r.status_code==200
        times.append((time.perf_counter()-t0)*1000)
    return {"samples": n, "avg_ms": statistics.mean(times), "p95_ms": sorted(times)[int(n*0.95)], "min_ms": min(times), "max_ms": max(times)}

def bench_evidence(n=30):
    c=TestClient(app)
    src='file.hash("/evidence/sample.exe");'
    times=[]
    for i in range(n):
        t0=time.perf_counter()
        r=c.post("/api/run", json={"source": src, "case_id": 900+i})
        assert r.status_code==200
        times.append((time.perf_counter()-t0)*1000)
    return {"samples": n, "avg_ms": statistics.mean(times), "p95_ms": sorted(times)[int(n*0.95)], "min_ms": min(times), "max_ms": max(times)}

if __name__ == "__main__":
    print("JOCKY Performance Benchmark — ROADMAP Phase 17")
    comp=bench_compile(50)
    api=bench_api(20)
    ev=bench_evidence(15)
    out={"compile": comp, "api_compile": api, "evidence": ev, "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "ir_version": 1}
    print(json.dumps(out, indent=2))
    pathlib.Path("build/perf.json").parent.mkdir(parents=True, exist_ok=True)
    pathlib.Path("build/perf.json").write_text(json.dumps(out, indent=2))
    print("Wrote build/perf.json")
    # Simple reliability checks per ROADMAP Phase 17: ensure p95 < 200ms for compile, <500ms for API
    assert comp["p95_ms"] < 200, f"compile p95 {comp['p95_ms']} >200ms"
    assert api["p95_ms"] < 500, f"api p95 {api['p95_ms']} >500ms"
    print("Reliability checks passed — no chaos failures")
