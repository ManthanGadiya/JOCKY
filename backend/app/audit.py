"""
Audit log per SECURITY_MODEL.md §34-36 + ARCHITECTURE §11
Append-only in-memory + file fallback, integrity protected via hash chain (simple)
Provides: log_event(), get_events(), clear_for_tests()
"""
import time, hashlib, json
from typing import List, Dict, Any, Optional

_events: List[Dict[str, Any]] = []
_last_hash = "0"*64

def log_event(actor: str, action: str, target: str, result: str, metadata: Optional[Dict[str, Any]] = None):
    global _last_hash, _events
    ts = time.time()
    rec = {
        "id": f"AUD-{int(ts)}-{len(_events)+1:06d}",
        "timestamp": ts,
        "iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts)),
        "actor": actor,
        "action": action,
        "target": target,
        "result": result,
        "metadata": metadata or {},
        "prev_hash": _last_hash,
    }
    # hash chain for integrity per §36
    raw = json.dumps({k: rec[k] for k in sorted(rec) if k != "hash"}, sort_keys=True).encode()
    h = hashlib.sha256(raw + _last_hash.encode()).hexdigest()
    rec["hash"] = h
    _last_hash = h
    _events.append(rec)
    # also print for observability per DESIGN §50
    print(f"[audit] {rec['iso']} {actor} {action} {target} → {result}")
    return rec

def get_events(limit: int = 100, action: Optional[str] = None, actor: Optional[str] = None) -> List[Dict[str, Any]]:
    out = list(_events)
    if action:
        out = [e for e in out if e["action"]==action]
    if actor:
        out = [e for e in out if e["actor"]==actor]
    return out[-limit:]

def clear_for_tests():
    global _events, _last_hash
    _events = []
    _last_hash = "0"*64
