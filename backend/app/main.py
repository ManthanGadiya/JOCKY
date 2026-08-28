from fastapi import FastAPI, WebSocket, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
import hashlib, time, json, re, random, uuid, datetime

app = FastAPI(title="JOCKY Backend - Central Forensics (L5+L6+ E2E)", version="1.1.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# In-memory stores (mirrors Postgres/Redis/MinIO when Docker wired)
cases: List[Dict[str, Any]] = []
evidence_store: List[Dict[str, Any]] = []
findings: List[Dict[str, Any]] = []

# Whitelist per SECURITY_MODEL.md §16 + tools/jockyc.py
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
# Agent policy: which caps are allowed (deny-by-default per SECURITY_MODEL.md §17)
DEFAULT_POLICY = {
    "system.read": True,
    "process.read": True,
    "file.read": True,
    "file.hash": True,
    "network.read": True,
    "driver.read": True,
    "memory.analyze": False,  # deny by default — sensitive
    "evidence.read": True,
    "report.generate": True,
}
RE_CALL = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)\.([a-zA-Z_][a-zA-Z0-9_]*)\s*\(')

def validate_and_collect(source: str):
    found = RE_CALL.findall(source)
    ops, caps, seen = [], [], set()
    errors = []
    for ns, meth in found:
        key = f"{ns}.{meth}"
        if key not in OP_CAPS:
            errors.append(f"Unknown or unsupported capability: {key} — not in JOCKY IR whitelist. Fail-closed.")
        elif key not in seen:
            seen.add(key)
            ops.append(key)
            cap = OP_CAPS[key]
            if cap not in caps:
                caps.append(cap)
    return ops, caps, errors

def sha12(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()[:12]

def generate_ir(source: str, seed: int, poly: bool):
    ops, caps, errors = validate_and_collect(source)
    if errors:
        raise ValueError("; ".join(errors))
    rng = random.Random(seed if seed else random.randint(0, 2**31))
    entry = 0x140001000 + (rng.randint(0, 0x5000) if poly else 0)
    imports = ["kernel32.dll","ntdll.dll","advapi32.dll","user32.dll"]
    if poly:
        rng.shuffle(imports)
    lines = []
    lines.append(f"; JOCKY IR - seed={seed} poly={int(poly)}")
    lines.append(f"; IR_VERSION=1")
    cap_str = ", ".join(caps) if caps else "(none)"
    ops_str = ", ".join(ops) if ops else "(none)"
    lines.append(f"; IR_CAPS: {cap_str}")
    lines.append(f"; IR_OPS: {ops_str}")
    lines.append(f"; Source hash: {sha12(source)}")
    lines.append(f"; EntryPoint: 0x{entry:x}")
    lines.append(f"; Imports: {' '.join(imports)}")
    lines.append(f"; JOCKY_DEMO_MARKER")
    if poly:
        lines.append(f"; -- polymorphic transforms applied --")
        lines.append(f"; cfg-flatten:(dispatch={rng.randint(2,9)})")
        lines.append(f"; string-encrypt:xor(key={rng.randint(1,255)})")
        lines.append(f"; import-obfuscate:shuffled")
    lines.append("define i32 @main() {")
    lines.append("entry:")
    cid = 0
    def emit(name, orig):
        nonlocal cid
        pid = rng.randint(0, 99999) if poly else cid
        lines.append(f"  ; jocky call: {name} [id={pid}]")
        lines.append(f"  %{cid} = call i32 @jocky_{name}() ; poly_id={pid} orig={orig}")
        cid += 1
    has = lambda kw: kw in source
    if has("system.info"): emit("system_info", "system.info")
    if has("process.list"): emit("process_list", "process.list")
    if has("process.tree"): emit("process_tree", "process.tree")
    if has("file.list"): emit("file_list", "file.list")
    if has("file.hash"): emit("file_hash", "file.hash")
    if has("file.analyze"): emit("file_analyze", "file.analyze")
    if has("network.connections"): emit("network_connections", "network.connections")
    if has("network.interfaces"): emit("network_interfaces", "network.interfaces")
    if has("memory.analyze"): emit("memory_analyze", "memory.analyze")
    if has("driver.list"): emit("driver_list", "driver.list")
    if has("driver.scan"): emit("driver_scan", "driver.scan")
    if has("driver.risk"): emit("driver_risk", "driver.risk")
    if cid == 0:
        emit("nop", "nop")
    if poly:
        blocks = rng.randint(2,5)
        for i in range(blocks):
            lines.append(f"bb.poly.{i}:")
            lines.append(f"  %{cid} = add i32 {rng.randint(0,99)}, {rng.randint(0,99)}")
            cid += 1
            lines.append(f"  br label %bb.poly.{i+1}")
        lines.append(f"bb.poly.{blocks}:")
    lines.append("  ret i32 0")
    lines.append("}")
    lines.append("declare i32 @jocky_system_info()")
    lines.append("declare i32 @jocky_process_list()")
    lines.append("declare i32 @jocky_file_analyze()")
    ir_text = "\n".join(lines)
    return ir_text, ops, caps

def ensure_case(case_id: int) -> Dict[str, Any]:
    for c in cases:
        if c["id"] == case_id:
            return c
    rec = {"id": case_id, "title": f"case-{case_id}", "created_at": datetime.datetime.utcnow().isoformat()+"Z", "risk": 0}
    cases.append(rec)
    return rec

def make_envelope(op: str, agent_id: str, host_id: str, case_id: int, ir_hash: str, source_hash: str, caps: List[str]):
    now = datetime.datetime.utcnow().isoformat()+"Z"
    eid = f"EV-{datetime.datetime.utcnow().strftime('%Y%m%d')}-{len(evidence_store)+1:06d}"
    # synthetic payload per op
    t = op.split(".")[0] if "." in op else op
    payload: Dict[str, Any] = {"jocky_op": op, "ir_hash": ir_hash, "source_hash": source_hash}
    if op == "system.info":
        payload.update({"type": "system", "hostname": host_id, "os": "linux", "arch": "x86_64", "kernel": "5.15-jocky", "jocky_version": "1.0", "agent_id": agent_id})
        ev_type = "system"
    elif op.startswith("process."):
        payload.update({"type": "process", "processes": [{"pid": 1234, "ppid": 1, "name": "explorer.exe", "hollowed": False}, {"pid": 5678, "ppid": 1234, "name": "svchost.exe"}], "note": "synthetic - no real enumeration"})
        ev_type = "process"
    elif op.startswith("file."):
        payload.update({"type": "file", "path": "/evidence/sample.exe", "sha256": "demo_"+hashlib.sha256(op.encode()).hexdigest()[:16], "note": "synthetic file op"})
        ev_type = "file"
    elif op.startswith("network."):
        payload.update({"type": "network", "connections": [{"local": "192.0.2.10:49152", "remote": "192.0.2.20:443", "state": "ESTABLISHED"}], "note": "synthetic"})
        ev_type = "network"
    elif op.startswith("driver."):
        payload.update({"type": "driver", "driver": {"name": "RTCore64.sys", "vulnerable": False, "note": "synthetic scan — no .sys loaded"}, "note": "synthetic"})
        ev_type = "driver"
    elif op.startswith("memory."):
        payload.update({"type": "memory", "memory": {"hollowed": False, "note": "synthetic - no dump read"}, "note": "synthetic"})
        ev_type = "memory"
    else:
        payload.update({"type": t, "note": "synthetic generic"})
        ev_type = t
    raw = json.dumps(payload, sort_keys=True).encode()
    sha = hashlib.sha256(raw).hexdigest()
    rec = {
        "id": eid,
        "case_id": case_id,
        "host_id": host_id,
        "agent_id": agent_id,
        "type": ev_type,
        "op": op,
        "source": "jocky_run",
        "collected_at": now,
        "observed_at": now,
        "collector": "jocky-runtime:1.0",
        "schema_version": 1,
        "payload": payload,
        "integrity": {"sha256": sha, "verified": True},
        "provenance": {"ir_hash": ir_hash, "source_hash": source_hash, "capabilities": caps},
        "chain_of_custody": f"{sha}:{agent_id}:{time.time()}",
        "timestamp": time.time(),
        "risk": calc_risk(payload),
        "sha256": sha,
    }
    return rec


# ── Legacy models ──
class Evidence(BaseModel):
    agent_id: str
    type: str
    payload: dict
    sha256: Optional[str] = None
    timestamp: Optional[float] = None

class CompileRequest(BaseModel):
    source: str = Field(..., description="JOCKY source text")
    polymorphic: bool = False
    seed: int = 0

class RunRequest(BaseModel):
    source: str = Field(..., description="JOCKY source text")
    agent_id: str = "WIN-001"
    host_id: str = "HOST-001"
    case_id: int = 1
    polymorphic: bool = False
    seed: int = 0

def calc_risk(payload: dict) -> int:
    r=0
    if payload.get("hollowed"): r+=40
    if payload.get("vulnerable_driver"): r+=30
    if payload.get("ppid_anomaly"): r+=30
    mem = payload.get("memory", {})
    if isinstance(mem, dict) and mem.get("hollowed"): r+=40
    if isinstance(mem, dict) and mem.get("unbacked_rx"): r+=20
    if isinstance(mem, dict) and mem.get("reflective_dll"): r+=35
    proc = payload.get("process", {})
    if isinstance(proc, dict) and proc.get("ppid_anomaly"): r+=30
    drv = payload.get("driver", {})
    if isinstance(drv, dict) and drv.get("vulnerable"): r+=30
    if isinstance(drv, dict) and drv.get("loldrivers_hit"): r+=10
    if payload.get("api_unhooking"): r+=25
    # also direct
    if payload.get("type") == "system": r = max(r, 5)  # system.info baseline
    return min(r, 100)

@app.get("/health")
def health(): return {"status":"ok","service":"jocky-backend","layers":"L5+L6+L7","version":"1.1.0","jocky_ir_version":1}

@app.get("/api/cases")
def list_cases(): return {"cases": cases, "count": len(cases), "evidence": len(evidence_store)}

@app.post("/api/evidence")
def post_evidence(ev: Evidence):
    raw = json.dumps(ev.payload, sort_keys=True).encode()
    sha = hashlib.sha256(raw).hexdigest()
    risk = calc_risk(ev.payload)
    rec = {"id": len(evidence_store)+1, "agent_id": ev.agent_id, "type": ev.type, "payload": ev.payload, "sha256": sha, "timestamp": time.time(), "chain_of_custody": f"{sha}:{ev.agent_id}:{time.time()}", "risk": risk}
    evidence_store.append(rec)
    return rec

@app.post("/api/compile")
def compile_source(req: CompileRequest):
    try:
        ir, ops, caps = generate_ir(req.source, req.seed, req.polymorphic)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    src_hash = hashlib.sha256(req.source.encode()).hexdigest()[:12]
    ir_hash = hashlib.sha256(ir.encode()).hexdigest()[:12]
    return {
        "ir": ir,
        "ir_version": 1,
        "source_hash": src_hash,
        "ir_hash": ir_hash,
        "capabilities": caps,
        "ops": ops,
        "poly": req.polymorphic,
        "seed": req.seed,
    }

@app.post("/api/run")
def run_source(req: RunRequest):
    # 1. compile + validate
    try:
        ir, ops, caps = generate_ir(req.source, req.seed, req.polymorphic)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    # 2. capability policy check (fail-closed)
    denied = [c for c in caps if not DEFAULT_POLICY.get(c, False)]
    if denied:
        raise HTTPException(status_code=403, detail=f"Capability denied by policy: {', '.join(denied)} — fail-closed.")
    if not ops:
        ops = ["nop"]
        caps = []
    src_hash = hashlib.sha256(req.source.encode()).hexdigest()[:12]
    ir_hash = hashlib.sha256(ir.encode()).hexdigest()[:12]
    ensure_case(req.case_id)
    created = []
    for op in ops:
        if op == "nop":
            continue
        rec = make_envelope(op, req.agent_id, req.host_id, req.case_id, ir_hash, src_hash, caps)
        evidence_store.append(rec)
        created.append(rec)
        # also findings for each
        findings.append({"id": f"F-{len(findings)+1:06d}", "case_id": req.case_id, "evidence_id": rec["id"], "rule": op, "severity": "INFO" if rec["risk"] <30 else "HIGH" if rec["risk"]<80 else "CRITICAL", "risk": rec["risk"]})
    # if single op like system.info, we emitted one evidence; keep fallback for nop-only
    if not created:
        rec = make_envelope("system.info", req.agent_id, req.host_id, req.case_id, ir_hash, src_hash, caps)
        rec["payload"]["note"] = "nop run — synthetic placeholder"
        evidence_store.append(rec)
        created.append(rec)
    max_risk = max([e.get("risk",0) for e in evidence_store if e.get("case_id")==req.case_id], default=0)
    # update case risk
    for c in cases:
        if c["id"]==req.case_id:
            c["risk"]=max_risk
    return {
        "ir": ir,
        "ir_version": 1,
        "source_hash": src_hash,
        "ir_hash": ir_hash,
        "capabilities": caps,
        "ops": ops,
        "evidence": created,
        "findings": [f for f in findings if f["case_id"]==req.case_id],
        "risk": max_risk,
        "level": "CRITICAL" if max_risk>80 else "HIGH" if max_risk>60 else "MEDIUM" if max_risk>30 else "LOW",
        "case_id": req.case_id,
    }

@app.get("/api/cases/{case_id}/timeline")
def timeline(case_id: int):
    filtered = [e for e in evidence_store if e.get("case_id")==case_id] or evidence_store
    ordered = sorted(filtered, key=lambda x: x.get("timestamp", 0))
    # normalize to timeline events
    events = []
    for e in ordered:
        events.append({
            "id": e.get("id"),
            "timestamp": e.get("observed_at") or e.get("timestamp"),
            "type": e.get("type"),
            "op": e.get("op"),
            "host_id": e.get("host_id") or e.get("agent_id"),
            "agent_id": e.get("agent_id"),
            "payload": e.get("payload"),
            "risk": e.get("risk",0),
            "sha256": e.get("sha256"),
        })
    return {"case_id": case_id, "timeline": events, "count": len(events)}

@app.get("/api/cases/{case_id}/graph")
def graph(case_id: int):
    filtered = [e for e in evidence_store if e.get("case_id")==case_id] or evidence_store
    if not filtered:
        return {"nodes": [], "edges": [], "mitre": []}
    # Build realistic graph: host -> evidence nodes -> finding
    nodes = [{"id": filtered[0].get("host_id","HOST-001"), "type": "host", "label": filtered[0].get("host_id","HOST-001"), "risk": 0}]
    edges = []
    prev = nodes[0]["id"]
    for e in filtered:
        nid = str(e.get("id"))
        nodes.append({"id": nid, "type": e.get("type","evidence"), "label": f"{e.get('op')}\n{e.get('type')}", "risk": e.get("risk",0), "op": e.get("op")})
        edges.append({"from": prev if prev else nid, "to": nid, "label": e.get("op")})
        prev = nid
    # finding node
    max_risk = max([n.get("risk",0) for n in nodes], default=0)
    nodes.append({"id": "finding", "type": "finding", "label": f"Finding\nRisk {max_risk}", "risk": max_risk})
    edges.append({"from": prev, "to": "finding"})
    return {"nodes": nodes, "edges": edges, "mitre": ["T1055.012","T1068"], "case_id": case_id}

@app.get("/api/cases/{case_id}/risk")
def risk(case_id: int):
    filtered = [e for e in evidence_store if e.get("case_id")==case_id]
    max_risk = max([e.get("risk",0) for e in filtered], default=0)
    # fallback to global if case empty but evidence exists
    if max_risk==0 and evidence_store:
        max_risk = max([e.get("risk",0) for e in evidence_store], default=0)
    return {"case_id": case_id, "risk": max_risk, "level": "CRITICAL" if max_risk>80 else "HIGH" if max_risk>60 else "MEDIUM" if max_risk>30 else "LOW"}

@app.get("/api/evidence")
def list_evidence(case_id: Optional[int] = None):
    if case_id is not None:
        return {"evidence": [e for e in evidence_store if e.get("case_id")==case_id], "count": len([e for e in evidence_store if e.get("case_id")==case_id])}
    return {"evidence": evidence_store, "count": len(evidence_store)}

@app.get("/api/findings")
def list_findings(case_id: Optional[int] = None):
    if case_id is not None:
        return {"findings": [f for f in findings if f["case_id"]==case_id], "count": len([f for f in findings if f["case_id"]==case_id])}
    return {"findings": findings, "count": len(findings)}

@app.websocket("/ws/agent")
async def ws_agent(ws: WebSocket):
    await ws.accept()
    while True:
        data = await ws.receive_text()
        await ws.send_text(f"ack:{hashlib.sha256(data.encode()).hexdigest()[:8]}")

@app.websocket("/ws/dashboard")
async def ws_dash(ws: WebSocket):
    await ws.accept()
    await ws.send_text(json.dumps({"event":"connected","cases":len(cases),"evidence":len(evidence_store)}))

@app.post("/api/detect")
def detect(payload: dict):
    hits = []
    txt = json.dumps(payload)
    if "JOCKY_DEMO_MARKER" in txt: hits.append({"rule":"JOCKY_DEMO_MARKER","severity":"HIGH","mitre":"T1055"})
    if "RTCore64" in txt: hits.append({"rule":"BYOVD_RTCore64","severity":"CRITICAL","mitre":"T1068"})
    if "hollowed" in txt: hits.append({"rule":"ProcessHollowing","severity":"CRITICAL","mitre":"T1055.012"})
    risk = min(len(hits)*35 + calc_risk(payload), 100)
    return {"hits": hits, "risk": risk}
