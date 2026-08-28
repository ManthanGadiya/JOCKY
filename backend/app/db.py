"""DB helpers — Postgres via SQLAlchemy with in-memory fallback for host tests."""
import os
import datetime
from typing import List, Dict, Any, Optional
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import OperationalError

from .models import Base, Case, Evidence, Finding

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://jocky:jocky@db:5432/jockydb")
# allow disabling DB explicitly for tests
USE_DB = os.getenv("USE_DB", "auto")  # auto | true | false

engine = None
SessionLocal = None
_db_available = False

def init_db():
    global engine, SessionLocal, _db_available
    if USE_DB == "false":
        _db_available = False
        return False
    url = DATABASE_URL
    try:
        # short timeout for host without postgres
        if "postgresql" in url:
            engine = create_engine(url, pool_pre_ping=True, connect_args={"connect_timeout": 2})
        else:
            engine = create_engine(url)
        # test connection
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
        Base.metadata.create_all(bind=engine)
        _db_available = True
        print(f"[db] Connected to {url.split('@')[-1][:40]} — tables ready")
        return True
    except Exception as e:
        print(f"[db] Postgres not available ({e}) — falling back to in-memory")
        engine = None
        SessionLocal = None
        _db_available = False
        return False

# try on import (but don't crash)
try:
    if USE_DB != "false":
        init_db()
except Exception:
    pass

def is_db_available() -> bool:
    return _db_available and engine is not None

def get_session():
    if not is_db_available():
        return None
    return SessionLocal()

# ---- Case helpers ----
def db_upsert_case(case_id: int, title: str = "", risk: int = 0) -> Dict[str, Any]:
    if not is_db_available():
        return None
    s = get_session()
    try:
        c = s.get(Case, case_id)
        if c:
            if risk is not None:
                c.risk = risk
            s.commit()
            s.refresh(c)
        else:
            c = Case(id=case_id, title=title or f"case-{case_id}", risk=risk)
            s.add(c)
            s.commit()
            s.refresh(c)
        return {"id": c.id, "title": c.title, "created_at": c.created_at.isoformat()+"Z" if c.created_at else "", "risk": c.risk}
    finally:
        s.close()

def db_list_cases() -> Optional[List[Dict[str, Any]]]:
    if not is_db_available():
        return None
    s = get_session()
    try:
        rows = s.query(Case).order_by(Case.id).all()
        return [{"id": r.id, "title": r.title, "created_at": r.created_at.isoformat()+"Z" if r.created_at else "", "risk": r.risk} for r in rows]
    finally:
        s.close()

def db_update_case_risk(case_id: int, risk: int):
    if not is_db_available():
        return
    s = get_session()
    try:
        c = s.get(Case, case_id)
        if c:
            c.risk = risk
            s.commit()
    finally:
        s.close()

# ---- Evidence helpers ----
def db_add_evidence(rec: Dict[str, Any]) -> bool:
    if not is_db_available():
        return False
    s = get_session()
    try:
        ev = Evidence(
            evidence_id=rec.get("id"),
            case_id=rec.get("case_id"),
            host_id=rec.get("host_id"),
            agent_id=rec.get("agent_id"),
            type=rec.get("type"),
            op=rec.get("op"),
            source=rec.get("source"),
            collected_at=rec.get("collected_at"),
            observed_at=rec.get("observed_at"),
            collector=rec.get("collector"),
            schema_version=rec.get("schema_version"),
            payload=rec.get("payload"),
            integrity=rec.get("integrity"),
            provenance=rec.get("provenance"),
            chain_of_custody=rec.get("chain_of_custody"),
            timestamp=rec.get("timestamp"),
            risk=rec.get("risk"),
            sha256=rec.get("sha256"),
        )
        s.add(ev)
        s.commit()
        return True
    except Exception as e:
        s.rollback()
        print(f"[db] evidence add failed: {e}")
        return False
    finally:
        s.close()

def db_list_evidence(case_id: Optional[int] = None) -> Optional[List[Dict[str, Any]]]:
    if not is_db_available():
        return None
    s = get_session()
    try:
        q = s.query(Evidence)
        if case_id is not None:
            q = q.filter(Evidence.case_id == case_id)
        q = q.order_by(Evidence.timestamp)
        rows = q.all()
        out = []
        for r in rows:
            out.append({
                "id": r.evidence_id,
                "case_id": r.case_id,
                "host_id": r.host_id,
                "agent_id": r.agent_id,
                "type": r.type,
                "op": r.op,
                "source": r.source,
                "collected_at": r.collected_at,
                "observed_at": r.observed_at,
                "collector": r.collector,
                "schema_version": r.schema_version,
                "payload": r.payload,
                "integrity": r.integrity,
                "provenance": r.provenance,
                "chain_of_custody": r.chain_of_custody,
                "timestamp": r.timestamp,
                "risk": r.risk,
                "sha256": r.sha256,
            })
        return out
    finally:
        s.close()

# ---- Finding helpers ----
def db_add_finding(rec: Dict[str, Any]) -> bool:
    if not is_db_available():
        return False
    s = get_session()
    try:
        f = Finding(
            finding_id=rec.get("id"),
            case_id=rec.get("case_id"),
            evidence_id=rec.get("evidence_id"),
            rule=rec.get("rule"),
            severity=rec.get("severity"),
            risk=rec.get("risk"),
            mitre=rec.get("mitre"),
        )
        s.add(f)
        s.commit()
        return True
    except Exception as e:
        s.rollback()
        print(f"[db] finding add failed: {e}")
        return False
    finally:
        s.close()

def db_list_findings(case_id: Optional[int] = None) -> Optional[List[Dict[str, Any]]]:
    if not is_db_available():
        return None
    s = get_session()
    try:
        q = s.query(Finding)
        if case_id is not None:
            q = q.filter(Finding.case_id == case_id)
        q = q.order_by(Finding.finding_id)
        rows = q.all()
        return [{"id": r.finding_id, "case_id": r.case_id, "evidence_id": r.evidence_id, "rule": r.rule, "severity": r.severity, "risk": r.risk, "mitre": r.mitre} for r in rows]
    finally:
        s.close()

def db_clear_for_tests():
    """Clear all tables — used only in tests when DB is available."""
    if not is_db_available():
        return
    s = get_session()
    try:
        s.query(Finding).delete()
        s.query(Evidence).delete()
        s.query(Case).delete()
        s.commit()
    finally:
        s.close()
