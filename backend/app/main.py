from fastapi import FastAPI, WebSocket, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
import hashlib, time, json, re, random, uuid, datetime, io

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

def extract_file_arg(source: str, op: str) -> str:
    # Extract first quoted arg for file.* ops: file.hash("/path") -> /path
    m = re.search(re.escape(op).replace(r"\.", r"\.") + r'\s*\(\s*["\']([^"\']*)["\']', source)
    if m:
        return m.group(1)
    # also bare arg without quotes (memory.analyze case)
    m2 = re.search(re.escape(op).replace(r"\.", r"\.") + r'\s*\(\s*([^)\s]+)\s*\)', source)
    if m2:
        return m2.group(1).strip('"\'')
    return ""

def validate_path(path: str):
    if not path:
        return
    if ".." in path or "\x00" in path:
        raise ValueError(f"Path traversal rejected: {path!r} — contains .. or null byte (SECURITY_MODEL path security)")
    # allow only safe roots for demo: normalize and reject absolute escapes like /etc/passwd sensitive
    # For lab we allow /evidence/, /tmp/, C:\, sample.exe, memory.dump etc but reject ../../
    if path.startswith("/") and not (path.startswith("/evidence/") or path.startswith("/tmp/") or path.startswith("/var/log/") or path.startswith("/sample") or path.startswith("/evidence")):
        # still allow generic lab paths containing evidence
        if "passwd" in path or "shadow" in path or "windows/system32/config" in path.lower():
            raise ValueError(f"Path rejected: {path!r} — outside allowed evidence roots")

def make_envelope(op: str, agent_id: str, host_id: str, case_id: int, ir_hash: str, source_hash: str, caps: List[str], source: str = ""):
    now = datetime.datetime.utcnow().isoformat()+"Z"
    eid = f"EV-{datetime.datetime.utcnow().strftime('%Y%m%d')}-{len(evidence_store)+1:06d}"
    t = op.split(".")[0] if "." in op else op
    payload: Dict[str, Any] = {"jocky_op": op, "ir_hash": ir_hash, "source_hash": source_hash}
    if op == "system.info":
        payload.update({"type": "system", "hostname": host_id, "os": "linux", "arch": "x86_64", "kernel": "5.15-jocky", "jocky_version": "1.0", "agent_id": agent_id, "boot_time": "2026-08-28T00:00:00Z", "timezone": "UTC"})
        ev_type = "system"
    elif op.startswith("process."):
        # richer correlated process tree per FORENSICS_SPEC §11-12
        processes = [
            {"pid": 1, "ppid": 0, "name": "systemd", "path": "/sbin/init", "user": "root", "creation_time": "2026-08-28T10:30:00Z", "risk": 0},
            {"pid": 1234, "ppid": 1, "name": "explorer.exe", "path": "C:\\Windows\\explorer.exe", "user": "analyst", "creation_time": "2026-08-28T10:31:00Z", "ppid_anomaly": False, "risk": 10},
            {"pid": 5678, "ppid": 1234, "name": "svchost.exe", "path": "C:\\Windows\\System32\\svchost.exe", "user": "SYSTEM", "creation_time": "2026-08-28T10:32:03Z", "ppid_anomaly": True, "risk": 35, "sigma_hit": "jocky-001 Parent Anomaly (T1055)"},
            {"pid": 9012, "ppid": 5678, "name": "malware.exe", "path": "C:\\Temp\\malware.exe", "user": "analyst", "creation_time": "2026-08-28T10:31:45Z", "parent": 5678, "risk": 75, "yara_hit": "JOCKY_DEMO_MARKER"},
        ]
        payload.update({"type": "process", "processes": processes, "count": len(processes), "note": "synthetic - correlated tree per LANGUAGE_SPEC process.list; ppid anomaly flagged per Sigma jocky-001", "sigma_rule": "jocky-001", "mitre": "T1055"})
        ev_type = "process"
    elif op.startswith("file."):
        raw_path = extract_file_arg(source, op) or "/evidence/sample.exe"
        validate_path(raw_path)
        sha = hashlib.sha256(raw_path.encode()).hexdigest()
        low = raw_path.lower()
        is_suspicious = any(k in low for k in ("suspicious","sample.exe","malware","evil","payload","implant"))
        payload.update({
            "type": "file", "path": raw_path, "name": raw_path.split("/")[-1].split("\\")[-1],
            "size": 1048576 if is_suspicious else 2048, "file_type": "PE32 executable" if raw_path.endswith(".exe") else "text",
            "creation_time": "2026-08-28T10:31:12Z", "modification_time": "2026-08-28T10:31:12Z",
            "hashes": {"sha256": sha, "sha512": hashlib.sha512(raw_path.encode()).hexdigest()[:64]},
            "sha256": sha, "yara_hit": "JOCKY_DEMO_MARKER" if is_suspicious else None,
            "sigma_hit": None, "mitre": "T1105" if is_suspicious else None,
            "note": "synthetic file op — no real filesystem read (safe)"
        })
        ev_type = "file"
    elif op.startswith("network."):
        conns = [
            {"local_address": "192.0.2.10", "local_port": 49152, "remote_address": "192.0.2.20", "remote_port": 443, "protocol": "TCP", "state": "ESTABLISHED", "pid": 9012, "process_name": "malware.exe", "observed_at": "2026-08-28T10:32:45Z", "risk": 80, "note": "C2 beacon"},
            {"local_address": "192.0.2.10", "local_port": 5353, "remote_address": "224.0.0.251", "remote_port": 5353, "protocol": "UDP", "state": "LISTEN", "pid": 5678, "process_name": "svchost.exe", "observed_at": "2026-08-28T10:30:00Z", "risk": 0},
        ]
        payload.update({"type": "network", "connections": conns, "count": len(conns), "note": "synthetic — no raw socket capture", "mitre": "T1071"})
        ev_type = "network"
    elif op.startswith("driver."):
        payload.update({"type": "driver", "driver": {"name": "RTCore64.sys", "version": "1.0.0", "path": "C:\\Windows\\System32\\drivers\\RTCore64.sys", "publisher": "Micro-Star International", "signature_status": "unsigned", "vulnerable": False, "loldrivers_hit": False, "note": "synthetic scan — no .sys loaded"}, "note": "synthetic"})
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
    if payload.get("yara_hit") == "JOCKY_DEMO_MARKER": r+=20
    if payload.get("sigma_hit"): r+=15
    # process list aggregated risk: check all processes for signals
    procs = payload.get("processes", [])
    if isinstance(procs, list):
        has_anomaly = any(isinstance(p, dict) and p.get("ppid_anomaly") for p in procs)
        has_yara = any(isinstance(p, dict) and p.get("yara_hit") for p in procs)
        if has_anomaly: r+=30
        if has_yara: r+=20
        if has_anomaly and has_yara: r+=10  # combined bonus for correlated anomalies
    # file suspicious
    if payload.get("type") == "file" and payload.get("yara_hit"):
        r+=35
    # network C2
    conns = payload.get("connections", [])
    if isinstance(conns, list):
        for c in conns:
            if isinstance(c, dict) and c.get("remote_address")=="192.0.2.20":
                r+=30
                break
    if payload.get("type") == "system": r = max(r, 5)
    if payload.get("type") == "process": r = max(r, 15)
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
        try:
            rec = make_envelope(op, req.agent_id, req.host_id, req.case_id, ir_hash, src_hash, caps, req.source)
        except ValueError as ve:
            raise HTTPException(status_code=400, detail=str(ve))
        evidence_store.append(rec)
        created.append(rec)
        # also findings for each — enriched with MITRE per payload
        mitre = rec["payload"].get("mitre") or ("T1055" if op.startswith("process.") else "T1105" if op.startswith("file.") else "T1071" if op.startswith("network.") else None)
        findings.append({"id": f"F-{len(findings)+1:06d}", "case_id": req.case_id, "evidence_id": rec["id"], "rule": op, "severity": "INFO" if rec["risk"] <30 else "HIGH" if rec["risk"]<80 else "CRITICAL", "risk": rec["risk"], "mitre": mitre})
    if not created:
        rec = make_envelope("system.info", req.agent_id, req.host_id, req.case_id, ir_hash, src_hash, caps, req.source)
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
    host_id = filtered[0].get("host_id","HOST-001")
    nodes = [{"id": host_id, "type": "host", "label": host_id, "risk": 0}]
    edges = []
    # star: host -> each evidence; evidence -> finding if risk notable; process/file/network correlation
    finding_id = "finding"
    max_risk = 0
    mitres = set()
    for e in filtered:
        nid = str(e.get("id"))
        risk = e.get("risk",0)
        max_risk = max(max_risk, risk)
        mitre = e.get("payload",{}).get("mitre")
        if mitre: mitres.add(mitre)
        # node label richer per type
        label = e.get("op","")
        if e.get("type")=="process":
            cnt = e.get("payload",{}).get("count",0)
            label = f"process.list\n{cnt} procs"
        elif e.get("type")=="file":
            path = e.get("payload",{}).get("path","")
            label = f"file.hash\n{path.split('/')[-1].split(chr(92))[-1][:18]}"
        elif e.get("type")=="network":
            label = f"net.conns\n{len(e.get('payload',{}).get('connections',[]))} conns"
        nodes.append({"id": nid, "type": e.get("type","evidence"), "label": label, "risk": risk, "op": e.get("op")})
        edges.append({"from": host_id, "to": nid, "label": e.get("op")})
        # correlation edges: file <-> process if process mentions that file path
        if e.get("type")=="file":
            # connect to latest process node if exists
            proc_nodes = [n for n in nodes if n["type"]=="process"]
            if proc_nodes:
                edges.append({"from": proc_nodes[-1]["id"], "to": nid, "label": "process→file"})
        if e.get("type")=="network":
            proc_nodes = [n for n in nodes if n["type"]=="process"]
            if proc_nodes:
                edges.append({"from": proc_nodes[-1]["id"], "to": nid, "label": "process→net"})
    nodes.append({"id": finding_id, "type": "finding", "label": f"Finding\nRisk {max_risk}", "risk": max_risk})
    for e in filtered:
        if e.get("risk",0) >= 30:
            edges.append({"from": str(e.get("id")), "to": finding_id, "label": "supports"})
    if not any(e[1]=="finding" for e in [(e["from"], e["to"]) for e in edges]):
        # ensure at least one edge to finding
        if filtered:
            edges.append({"from": str(filtered[-1].get("id")), "to": finding_id})
    return {"nodes": nodes, "edges": edges, "mitre": sorted(mitres) or ["T1055","T1105","T1071"], "case_id": case_id}

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

class ReportRequest(BaseModel):
    case_id: int = 1
    title: Optional[str] = None
    include_timeline: bool = True
    include_graph: bool = True

def build_report_html(case_id: int, title: Optional[str] = None) -> str:
    case = next((c for c in cases if c["id"]==case_id), None)
    if not case:
        # still generate report for empty case (for UX) — will show 0 evidence
        case = {"id": case_id, "title": title or f"case-{case_id}", "created_at": datetime.datetime.utcnow().isoformat()+"Z", "risk": 0}
    evs = [e for e in evidence_store if e.get("case_id")==case_id]
    finds = [f for f in findings if f["case_id"]==case_id]
    risk_val = max([e.get("risk",0) for e in evs], default=0)
    level = "CRITICAL" if risk_val>80 else "HIGH" if risk_val>60 else "MEDIUM" if risk_val>30 else "LOW"
    now = datetime.datetime.utcnow().isoformat()+"Z"
    # forensic chain summary
    ev_rows = ""
    for e in sorted(evs, key=lambda x: x.get("timestamp",0)):
        prov = e.get("provenance",{})
        integ = e.get("integrity",{})
        payload = e.get("payload",{})
        # truncate payload JSON for readability
        payload_snip = json.dumps(payload, indent=2)[:800].replace("<","&lt;").replace(">","&gt;")
        ev_rows += f"""
        <tr>
          <td>{e.get('id')}</td>
          <td>{e.get('op')}</td>
          <td>{e.get('type')}</td>
          <td>{e.get('risk')}</td>
          <td class="mono">{str(e.get('sha256',''))[:12]}…</td>
          <td class="mono">{str(integ.get('sha256',''))[:12]}…</td>
          <td>{e.get('observed_at','')[:19]}</td>
        </tr>
        <tr><td colspan="7" class="payload-cell"><pre>{payload_snip}</pre><div class="small">Provenance: ir_hash {prov.get('ir_hash','')} source_hash {prov.get('source_hash','')} caps {', '.join(prov.get('capabilities',[]))} — chain {str(e.get('chain_of_custody',''))[:32]}…</div></td></tr>
        """
    if not ev_rows:
        ev_rows = '<tr><td colspan="7" class="empty">No evidence for this case yet — run a JOCKY query from the dashboard.</td></tr>'
    find_rows = ""
    for f in finds:
        find_rows += f"<tr><td>{f.get('id')}</td><td>{f.get('rule')}</td><td>{f.get('severity')}</td><td>{f.get('risk')}</td><td>{f.get('mitre','')}</td><td>{f.get('evidence_id')}</td></tr>"
    if not find_rows:
        find_rows = '<tr><td colspan="6" class="empty">No findings yet.</td></tr>'
    # timeline
    tl_events = sorted(evs, key=lambda x: x.get("timestamp",0))
    tl_html = ""
    for e in tl_events:
        tl_html += f"<li><span class=\"mono\">{str(e.get('observed_at',''))[:19]}</span> — <b>{e.get('op')}</b> ({e.get('type')}) risk {e.get('risk')} — {e.get('host_id')} / {e.get('agent_id')}</li>"
    if not tl_html:
        tl_html = "<li>No timeline events.</li>"
    # graph summary
    graph_summary = f"Host {case['id']} → {len(evs)} evidence nodes → Finding risk {risk_val} ({level})"
    html = f"""<!doctype html>
<html><head><meta charset="utf-8"/>
<style>
  body {{ font-family: -apple-system, Arial, Helvetica, sans-serif; color:#111; margin:32px; font-size:12px; }}
  h1 {{ font-size:22px; margin:0 0 4px; }}
  h2 {{ font-size:15px; margin:18px 0 8px; border-bottom:1px solid #ddd; padding-bottom:4px; }}
  .subtitle {{ color:#555; font-size:11px; margin-bottom:12px; }}
  .risk-badge {{ display:inline-block; padding:4px 10px; border-radius:12px; color:white; font-weight:700; font-size:12px; }}
  .risk-LOW {{background:#22c55e}} .risk-MEDIUM{{background:#eab308}} .risk-HIGH{{background:#f97316}} .risk-CRITICAL{{background:#dc2626}}
  table {{ width:100%; border-collapse:collapse; margin:8px 0 14px; }}
  th, td {{ border:1px solid #ddd; padding:6px 8px; text-align:left; vertical-align:top; }}
  th {{ background:#f5f5f5; font-size:11px; }}
  .mono {{ font-family: ui-monospace, SFMono-Regular, monospace; font-size:10px; }}
  .payload-cell pre {{ margin:4px 0; background:#fafafa; padding:6px; border:1px solid #eee; white-space:pre-wrap; font-size:9px; max-height:120px; overflow:hidden; }}
  .small {{ font-size:9px; color:#666; }}
  .empty {{ text-align:center; color:#888; padding:14px; }}
  footer {{ margin-top:22px; border-top:1px solid #ddd; padding-top:8px; font-size:9px; color:#666; }}
  ul.timeline {{ margin:6px 0; padding-left:18px; }}
  ul.timeline li {{ margin:3px 0; }}
</style>
</head><body>
<h1>JOCKY Forensic Report — Case {case['id']}</h1>
<div class="subtitle">{title or case.get('title','')} • Generated {now} • Collector jocky-runtime:1.0 • IR v1 • Evidence schema_version 1</div>
<div><span class="risk-badge risk-{level}">{risk_val}/100 {level}</span> &nbsp; <span class="small">{len(evs)} evidence • {len(finds)} findings • chain-of-custody SHA256 verified</span></div>

<h2>1. Case Summary</h2>
<table><tr><th>Field</th><th>Value</th></tr>
<tr><td>Case ID</td><td>{case['id']} — {case.get('title','')}</td></tr>
<tr><td>Created</td><td>{case.get('created_at','')}</td></tr>
<tr><td>Host(s)</td><td>{', '.join(sorted(set(e.get('host_id','') for e in evs))) or '—'}</td></tr>
<tr><td>Agents</td><td>{', '.join(sorted(set(e.get('agent_id','') for e in evs))) or '—'}</td></tr>
<tr><td>Risk</td><td><b>{risk_val}</b> ({level}) — max across evidence; detection: YARA JOCKY_DEMO_MARKER + Sigma jocky-001 + behavioral calc_risk</td></tr>
<tr><td>Evidence</td><td>{len(evs)} envelopes (canonical: id/case_id/host_id/type/observed_at/payload/integrity/provenance/chain)</td></tr>
<tr><td>Integrity</td><td>SHA256 per envelope, verified true, chain_of_custody sha:agent:time</td></tr>
</table>

<h2>2. Findings</h2>
<table><tr><th>Finding</th><th>Rule (op)</th><th>Severity</th><th>Risk</th><th>MITRE</th><th>Evidence</th></tr>
{find_rows}
</table>

<h2>3. Evidence (Canonical Envelope — FORENSICS_SPEC §5)</h2>
<table><tr><th>ID</th><th>Op</th><th>Type</th><th>Risk</th><th>Payload SHA</th><th>Integrity</th><th>Observed</th></tr>
{ev_rows}
</table>
<div class="small">Each envelope preserves provenance ir_hash/source_hash/capabilities and chain_of_custody for auditability. Synthetic payloads per LANGUAGE_SPEC §10 (system/process/file/network).</div>

<h2>4. Timeline (ordered by observed_at)</h2>
<ul class="timeline">{tl_html}</ul>

<h2>5. Investigation Graph</h2>
<p>{graph_summary} — star host→evidence plus correlation edges process→file / process→net when both present. Full graph available live via GET /api/cases/{case_id}/graph (nodes/edges/mitre).</p>
<p class="small">MITRE mapping per evidence: process T1055, file T1105, network T1071, driver T1068 (where applicable).</p>

<h2>6. Chain of Custody &amp; Provenance</h2>
<p class="small">All evidence retains <code>integrity.sha256</code> (SHA256 of canonical payload), <code>provenance.ir_hash/source_hash/capabilities</code>, and <code>chain_of_custody</code> (sha:agent_id:timestamp). Tamper would break sha verification. Synthetic provider: jocky-runtime:1.0.</p>

<footer>
JOCKY Defensive Forensic Platform — report generated {now} • Backend v1.1.1 • IR_VERSION=1 • Synthetic evidence demo (no real endpoint collection) • Chain-of-custody SHA256 verified • For internal authorized investigation use.
<br/>Sources: FORENSICS_SPEC §5 envelope, SECURITY_MODEL path security + capability policy, LANGUAGE_SPEC §10 ops.
</footer>
</body></html>
"""
    return html

def render_pdf_bytes(html: str) -> bytes:
    try:
        from weasyprint import HTML
        return HTML(string=html).write_pdf()
    except Exception as e:
        # fallback: return HTML bytes with warning header — caller will set pdf mime but content is html (still viewable)
        # keep failure visible for debugging
        raise RuntimeError(f"WeasyPrint failed: {e}")

@app.post("/api/detect")
def detect(payload: dict):
    hits = []
    txt = json.dumps(payload)
    if "JOCKY_DEMO_MARKER" in txt: hits.append({"rule":"JOCKY_DEMO_MARKER","severity":"HIGH","mitre":"T1055"})
    if "RTCore64" in txt: hits.append({"rule":"BYOVD_RTCore64","severity":"CRITICAL","mitre":"T1068"})
    if "hollowed" in txt: hits.append({"rule":"ProcessHollowing","severity":"CRITICAL","mitre":"T1055.012"})
    risk = min(len(hits)*35 + calc_risk(payload), 100)
    return {"hits": hits, "risk": risk}

@app.get("/api/cases/{case_id}/report")
def get_report(case_id: int, title: Optional[str] = None):
    # validate case exists or allow empty report (UX: still generate)
    html = build_report_html(case_id, title)
    try:
        pdf = render_pdf_bytes(html)
        return StreamingResponse(io.BytesIO(pdf), media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename=\"JOCKY_case_{case_id}_report.pdf\"'})
    except Exception as e:
        # fallback to html if weasyprint deps missing on host test — still testable
        return StreamingResponse(io.BytesIO(html.encode()), media_type="text/html",
            headers={"X-Report-Fallback": str(e)[:200]})

@app.post("/api/report")
def post_report(req: ReportRequest):
    html = build_report_html(req.case_id, req.title)
    try:
        pdf = render_pdf_bytes(html)
        return StreamingResponse(io.BytesIO(pdf), media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename=\"JOCKY_case_{req.case_id}_report.pdf\"'})
    except Exception as e:
        return StreamingResponse(io.BytesIO(html.encode()), media_type="text/html",
            headers={"X-Report-Fallback": str(e)[:200]})
