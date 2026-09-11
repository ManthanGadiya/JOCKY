#!/usr/bin/env python3
"""
JOCKY Agent — real HTTP transport via nginx (Layer 4 → L5 → L6)
Per AGENTS.md §7 + docs/ARCHITECTURE.md §7 + docs/FORENSICS_SPEC.md §52-54

Responsibilities:
  1. receive authorized work (here: configured JOCKY source + fixtures)
  2. validate (fail-closed via backend 422/403)
  3. collect (synthetic per FORENSICS_SPEC §23 — no WinAPI/ETW, no BSOD)
  4. normalize → canonical envelope is produced by backend's make_envelope()
  5. transmit via nginx (http://nginx:80) → backend:8000
  6. audit log with agent_id/host_id/case_id/provenance

Transport: BACKEND_URL env (default http://nginx:80 inside docker, http://localhost:8000 host fallback)
           POST /health, POST /api/evidence, POST /api/run  — all via nginx when available.
"""
import os, sys, json, time, pathlib, hashlib
import urllib.request
import urllib.error

BACKEND_URL = os.getenv("BACKEND_URL", "http://nginx:80").rstrip("/")
AGENT_ID = os.getenv("AGENT_ID", "WIN-001")
HOST_ID = os.getenv("HOST_ID", os.getenv("AGENT_ID", "WIN-001"))
CASE_ID = int(os.getenv("CASE_ID", "1"))
FIXTURE_DIR = pathlib.Path(os.getenv("FIXTURE_DIR", "/app/testdata"))
JOCKY_SOURCE = os.getenv("JOCKY_SOURCE", 'system.info();\nprocess.list();\nfile.hash("/evidence/sample.exe");\nnetwork.connections();')
POLL_SECONDS = int(os.getenv("AGENT_POLL_SECONDS", "0"))  # 0 = run once then idle

def log(msg: str):
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    print(f"[agent {AGENT_ID}@{HOST_ID} case={CASE_ID}] {ts} {msg}", flush=True)

def http_get(path: str, timeout=5):
    url = f"{BACKEND_URL}{path}"
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read().decode()
            return r.status, body
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode() if e.fp else str(e)
    except Exception as e:
        return None, str(e)

def http_post_json(path: str, payload: dict, timeout=10):
    url = f"{BACKEND_URL}{path}"
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, method="POST", headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read().decode()
            return r.status, body
    except urllib.error.HTTPError as e:
        body = e.read().decode() if e.fp else str(e)
        return e.code, body
    except Exception as e:
        return None, str(e)

def post_fixture_via_nginx(fixture_path: pathlib.Path, case_id: int):
    """POST a testdata fixture through nginx → POST /api/evidence"""
    raw = json.loads(fixture_path.read_text(encoding="utf-8"))
    # Handle fixtures that are lists (e.g., timeline.json) or dicts without type
    if isinstance(raw, list):
        # list fixture (e.g., timeline.json) — wrap as timeline type, send first element or whole list as payload
        # per FORENSICS_SPEC §39 timeline events — send as single timeline evidence
        if len(raw) == 0:
            log(f"Skipping empty list fixture {fixture_path.name}")
            return False, "empty list"
        # If list contains event dicts, send as type=timeline with payload containing events
        raw_wrapped = {"type": "timeline", "events": raw, "count": len(raw), "note": f"wrapped {fixture_path.name} list per FORENSICS §39"}
        ev_type = "timeline"
        payload = raw_wrapped
        body = {"agent_id": AGENT_ID, "type": ev_type, "payload": payload}
        status, resp = http_post_json("/api/evidence", body)
        if status == 200:
            j = json.loads(resp)
            log(f"POST /api/evidence via nginx {fixture_path.name} (list {len(raw)} events) → {j.get('id')} risk={j.get('risk')}")
            return True, j
        else:
            log(f"POST /api/evidence via nginx {fixture_path.name} (list) FAILED status={status} resp={resp[:300]}")
            return False, resp
    # dict fixture
    if isinstance(raw, dict):
        # Handle demo fixture like polymorphic_files.json which is not forensic evidence (has demo/builds)
        if "demo" in raw and "builds" not in raw.get("type","") and raw.get("type") is None:
            # polymorphic_files.json — demo artifact, treat as file evidence with payload containing demo
            raw_wrapped = {"type": "file", "demo": raw.get("demo"), "builds": raw.get("builds"), "yara_cluster": raw.get("yara_cluster"), "behavior": raw.get("behavior"), "note": f"demo {fixture_path.name}"}
            raw = raw_wrapped
        ev_type = raw.get("type", "unknown")
        # Map unknown demo types to file/timeline
        if ev_type == "unknown" and "demo" in raw:
            ev_type = "file"
        body = {
            "agent_id": raw.get("agent_id", AGENT_ID),
            "type": ev_type if ev_type != "unknown" else "evidence",
            "payload": raw,
            "timestamp": raw.get("timestamp") if isinstance(raw.get("timestamp"), (int,float)) else None,
        }
    else:
        # raw is scalar (unlikely) — wrap
        body = {"agent_id": AGENT_ID, "type": "unknown", "payload": {"raw": raw}}
    # Don't send string timestamp to backend — let backend generate its own (avoids float_parsing 422)
    # Remove None timestamp so backend uses default
    if body.get("timestamp") is None:
        body.pop("timestamp", None)
    status, resp = http_post_json("/api/evidence", body)
    if status == 200:
        j = json.loads(resp)
        log(f"POST /api/evidence via nginx {fixture_path.name} → {j.get('id')} risk={j.get('risk')} sha={str(j.get('sha256',''))[:12]}")
        return True, j
    else:
        log(f"POST /api/evidence via nginx {fixture_path.name} FAILED status={status} resp={resp[:300]}")
        return False, resp

def post_jocky_via_nginx(source: str, case_id: int, host_id: str, agent_id: str):
    """POST JOCKY source via nginx → POST /api/run (canonical envelope path per IR_SPEC §28)"""
    body = {"source": source, "agent_id": agent_id, "host_id": host_id, "case_id": case_id}
    status, resp = http_post_json("/api/run", body)
    if status == 200:
        j = json.loads(resp)
        ops = j.get("ops", [])
        ev = j.get("evidence", [])
        risk = j.get("risk")
        log(f"POST /api/run via nginx → ops={ops} evidence={len(ev)} risk={risk} level={j.get('level')}")
        return True, j
    elif status in (422, 403, 400):
        # fail-closed expected for malicious/policy-denied per SECURITY_MODEL §14-17
        log(f"POST /api/run via nginx REJECTED (fail-closed) status={status} detail={resp[:300]}")
        return False, resp
    else:
        log(f"POST /api/run via nginx FAILED status={status} resp={resp[:300]}")
        return False, resp

def agent_scan_once():
    # 1. Health via nginx
    status, body = http_get("/health")
    if status == 200:
        try:
            j = json.loads(body)
            log(f"GET /health via nginx {BACKEND_URL} → ok db={j.get('db')} yara={j.get('yara')} version={j.get('version')}")
        except Exception:
            log(f"GET /health via nginx → {body[:200]}")
    else:
        log(f"GET /health via nginx FAILED status={status} → trying direct backend fallback http://backend:8000")
        # fallback probe (only for diagnostics; primary must be nginx)
        fb_url = "http://backend:8000"
        try:
            req = urllib.request.Request(f"{fb_url}/health", method="GET")
            with urllib.request.urlopen(req, timeout=5) as r:
                log(f"  fallback {fb_url}/health → {r.status} (nginx should be used in prod)")
        except Exception as e:
            log(f"  fallback also failed: {e}")

    # 2. POST each fixture found in FIXTURE_DIR via nginx (synthetic per SECURITY_MODEL §47-49)
    fixtures = sorted(FIXTURE_DIR.glob("*.json")) if FIXTURE_DIR.exists() else []
    if fixtures:
        log(f"Found {len(fixtures)} fixtures in {FIXTURE_DIR}")
        for fx in fixtures:
            post_fixture_via_nginx(fx, CASE_ID)
            time.sleep(0.2)
    else:
        log(f"No fixtures at {FIXTURE_DIR} — synthetic evidence will come from JOCKY Run")

    # 3. POST JOCKY sweep via nginx → backend canonical envelope
    log(f"Posting JOCKY sweep via nginx (case {CASE_ID}): {repr(JOCKY_SOURCE[:60])}...")
    ok, resp = post_jocky_via_nginx(JOCKY_SOURCE, CASE_ID, HOST_ID, AGENT_ID)
    if ok:
        # verify evidence is retrievable via nginx GET
        status, body = http_get(f"/api/evidence?case_id={CASE_ID}")
        if status == 200:
            try:
                j = json.loads(body)
                log(f"GET /api/evidence?case_id={CASE_ID} via nginx → count={j.get('count')} (evidence persisted PG)")
            except Exception as e:
                log(f"GET /api/evidence via nginx parse failed: {e}")
        # also verify timeline/graph/risk
        for path in [f"/api/cases/{CASE_ID}/timeline", f"/api/cases/{CASE_ID}/graph", f"/api/cases/{CASE_ID}/risk"]:
            s, b = http_get(path)
            log(f"GET {path} via nginx → status={s} body_snip={b[:120].replace(chr(10),' ')}")

    # 4. Demonstrate fail-closed via nginx (unknown op should 422, not 200)
    bad_source = "edr.disable();"
    bs, br = http_post_json("/api/run", {"source": bad_source, "agent_id": AGENT_ID, "host_id": HOST_ID, "case_id": CASE_ID})
    if bs == 422:
        log(f"Fail-closed verified via nginx: {bad_source!r} → 422 as expected per SECURITY_MODEL §14")
    else:
        log(f"Fail-closed check via nginx unexpected: {bad_source!r} → status={bs} (expected 422)")

def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "--scan"
    # support --once flag for one-shot, otherwise loop if POLL_SECONDS >0
    once = "--once" in sys.argv or POLL_SECONDS == 0
    log(f"JOCKY Agent starting — BACKEND_URL={BACKEND_URL} FIXTURE_DIR={FIXTURE_DIR} mode={mode}")
    # wait for nginx/backend to be ready (docker startup order)
    for attempt in range(12):
        s, _ = http_get("/health")
        if s == 200:
            break
        log(f"Waiting for nginx/backend... attempt {attempt+1}/12 status={s}")
        time.sleep(2)
    agent_scan_once()
    if once:
        log("Agent scan complete — idling (tail -f /dev/null semantics preserved). Set AGENT_POLL_SECONDS>0 to loop.")
        # keep container alive like original Dockerfile tail -f /dev/null
        try:
            while True:
                if POLL_SECONDS > 0:
                    time.sleep(POLL_SECONDS)
                    agent_scan_once()
                else:
                    time.sleep(3600)
        except KeyboardInterrupt:
            log("Agent stopped")
    else:
        while True:
            time.sleep(POLL_SECONDS)
            agent_scan_once()

if __name__ == "__main__":
    main()
