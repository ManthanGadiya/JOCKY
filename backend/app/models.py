# SQLAlchemy models (L6 Backend Store - Postgres)
# Tables: cases, evidence, timeline, detections, audit
# For Docker demo, main.py uses in-memory; this is production schema
from sqlalchemy import Column, Integer, String, Float, JSON, DateTime
from sqlalchemy.orm import declarative_base
import datetime
Base = declarative_base()
class Case(Base):
    __tablename__ = "cases"
    id = Column(Integer, primary_key=True)
    title = Column(String)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    risk = Column(Integer, default=0)
class Evidence(Base):
    __tablename__ = "evidence"
    id = Column(Integer, primary_key=True)
    case_id = Column(Integer)
    agent_id = Column(String)
    type = Column(String)
    payload = Column(JSON)
    sha256 = Column(String)
    timestamp = Column(Float)
