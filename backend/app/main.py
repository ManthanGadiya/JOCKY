from fastapi import FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import hashlib, time, json

app = FastAPI(title="JOCKY Backend - Central Forensics (L5+L6)", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

cases = []
evidence_store = []

class Evidence(BaseModel):
    agent_id: str
    type: str
    payload: dict
    sha256: Optional[str] = None
    timestamp: Optional[float] = None

def calc_risk(payload: dict) -> int:
    # L7 Behavioral Risk 0-100 - checks nested synthetic fields
    r=0
    # direct flags
    if payload.get("hollowed"): r+=40
    if payload.get("vulnerable_driver"): r+=30
    if payload.get("ppid_anomaly"): r+=30
    # nested in testdata/*.json
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
    return min(r, 100)

@app.get("/health")
def health(): return {"status":"ok","service":"jocky-backend","layers":"L5+L6+L7"}

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

@app.get("/api/cases/{case_id}/timeline")
def timeline(case_id: int):
    return {"case_id": case_id, "timeline": sorted(evidence_store, key=lambda x: x["timestamp"])}

@app.get("/api/cases/{case_id}/graph")
def graph(case_id: int):
    nodes = [{"id": e["agent_id"], "type": e["type"], "risk": e.get("risk",0)} for e in evidence_store]
    edges = [{"from": evidence_store[i]["agent_id"], "to": evidence_store[i+1]["agent_id"]} for i in range(len(evidence_store)-1)]
    return {"nodes": nodes, "edges": edges, "mitre": ["T1055.012","T1068"]}

@app.get("/api/cases/{case_id}/risk")
def risk(case_id: int):
    max_risk = max([e.get("risk",0) for e in evidence_store], default=0)
    return {"case_id": case_id, "risk": max_risk, "level": "CRITICAL" if max_risk>80 else "HIGH" if max_risk>60 else "MEDIUM" if max_risk>30 else "LOW"}

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
