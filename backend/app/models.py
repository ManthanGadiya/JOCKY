# SQLAlchemy models (L6 Backend Store - Postgres)
# Tables: cases, evidence, findings
# Mirrors canonical envelope per FORENSICS_SPEC §5 + chain-of-custody
from sqlalchemy import Column, Integer, String, Float, JSON, DateTime, Text
from sqlalchemy.orm import declarative_base
import datetime

Base = declarative_base()

class Case(Base):
    __tablename__ = "cases"
    id = Column(Integer, primary_key=True)  # case_id from API (not autoincrement in app but DB PK)
    title = Column(String, default="")
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    risk = Column(Integer, default=0)

class Evidence(Base):
    __tablename__ = "evidence"
    # autoincrement PK for DB; evidence_id is the JOCKY EV-... string
    pk = Column(Integer, primary_key=True, autoincrement=True)
    evidence_id = Column(String, unique=True, index=True)  # e.g., EV-20260828-000001
    case_id = Column(Integer, index=True)
    host_id = Column(String)
    agent_id = Column(String)
    type = Column(String)
    op = Column(String)
    source = Column(String)
    collected_at = Column(String)  # ISO string
    observed_at = Column(String)
    collector = Column(String)
    schema_version = Column(Integer)
    payload = Column(JSON)
    integrity = Column(JSON)
    provenance = Column(JSON)
    chain_of_custody = Column(Text)
    timestamp = Column(Float, index=True)
    risk = Column(Integer)
    sha256 = Column(String)

class Finding(Base):
    __tablename__ = "findings"
    pk = Column(Integer, primary_key=True, autoincrement=True)
    finding_id = Column(String, unique=True, index=True)  # F-000001
    case_id = Column(Integer, index=True)
    evidence_id = Column(String, index=True)
    rule = Column(String)
    severity = Column(String)
    risk = Column(Integer)
    mitre = Column(String)
