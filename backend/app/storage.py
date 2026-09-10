"""
Storage layer — MinIO object store + local fallback per ARCHITECTURE.md §11
Per DESIGN.md §14-15: MinIO stores evidence artifacts, reports, large objects.
Provides: init_storage(), is_minio_available(), put_report(), get_report(), put_evidence_artifact()

Host tests use in-memory fallback; Docker uses real MinIO at minio:9000 (or localhost:9000)
"""
import os, io, hashlib, time
from typing import Optional, Dict, Any

BUCKET_REPORTS = os.getenv("MINIO_BUCKET_REPORTS", "jocky-reports")
BUCKET_EVIDENCE = os.getenv("MINIO_BUCKET_EVIDENCE", "jocky-evidence")
MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT", "minio:9000")
MINIO_ACCESS = os.getenv("MINIO_ACCESS_KEY", os.getenv("MINIO_ROOT_USER", "minioadmin"))
MINIO_SECRET = os.getenv("MINIO_SECRET_KEY", os.getenv("MINIO_ROOT_PASSWORD", "minioadmin"))
MINIO_SECURE = os.getenv("MINIO_SECURE", "false").lower() == "true"

_client = None
_available = False
# in-memory fallback for host tests (dict key → bytes)
_mem_store: Dict[str, bytes] = {}

def _build_client():
    global _client, _available
    try:
        from minio import Minio  # type: ignore
        # endpoint may be like "minio:9000" inside docker or "localhost:9000" host
        # try docker endpoint first, fallback to localhost if not reachable
        endpoints = [MINIO_ENDPOINT, "localhost:9000", "127.0.0.1:9000"]
        last_err = None
        for ep in endpoints:
            try:
                c = Minio(ep, access_key=MINIO_ACCESS, secret_key=MINIO_SECRET, secure=MINIO_SECURE)
                # test bucket existence quickly (list_buckets timeout short)
                c.list_buckets()
                _client = c
                _available = True
                print(f"[storage] MinIO connected at {ep} — buckets ready")
                # ensure buckets exist
                for bucket in (BUCKET_REPORTS, BUCKET_EVIDENCE):
                    if not c.bucket_exists(bucket):
                        c.make_bucket(bucket)
                        print(f"[storage] created bucket {bucket}")
                return True
            except Exception as e:
                last_err = e
                continue
        print(f"[storage] MinIO not available ({last_err}) — falling back to in-memory")
        _client = None
        _available = False
        return False
    except ImportError:
        print("[storage] minio package not installed — in-memory fallback")
        _client = None
        _available = False
        return False
    except Exception as e:
        print(f"[storage] MinIO init failed ({e}) — in-memory fallback")
        _client = None
        _available = False
        return False

def init_storage():
    return _build_client()

# try on import but don't crash
try:
    init_storage()
except Exception:
    pass

def is_minio_available() -> bool:
    return _available and _client is not None

def _mem_key(bucket: str, key: str) -> str:
    return f"{bucket}/{key}"

def put_bytes(bucket: str, key: str, data: bytes, content_type: str = "application/octet-stream") -> bool:
    """Put bytes to MinIO or fallback mem. Returns True if stored (either)."""
    if is_minio_available():
        try:
            _client.put_object(bucket, key, io.BytesIO(data), length=len(data), content_type=content_type)
            return True
        except Exception as e:
            print(f"[storage] MinIO put failed {bucket}/{key}: {e} — falling back to mem")
    # fallback
    _mem_store[_mem_key(bucket, key)] = data
    return True

def get_bytes(bucket: str, key: str) -> Optional[bytes]:
    if is_minio_available():
        try:
            resp = _client.get_object(bucket, key)
            data = resp.read()
            resp.close(); resp.release_conn()
            return data
        except Exception:
            pass
    return _mem_store.get(_mem_key(bucket, key))

def put_report(case_id: int, pdf_bytes: bytes) -> str:
    """Store PDF report per FORENSICS_SPEC §64 + ARCHITECTURE §11. Returns key."""
    key = f"case-{case_id}/JOCKY_case_{case_id}_report.pdf"
    put_bytes(BUCKET_REPORTS, key, pdf_bytes, "application/pdf")
    # also store via mem fallback for host test easy retrieval
    _mem_store[_mem_key(BUCKET_REPORTS, key)] = pdf_bytes
    return key

def get_report(case_id: int) -> Optional[bytes]:
    key = f"case-{case_id}/JOCKY_case_{case_id}_report.pdf"
    return get_bytes(BUCKET_REPORTS, key)

def put_evidence_artifact(evidence_id: str, data: bytes, content_type: str = "application/json") -> str:
    key = f"{evidence_id}.json"
    put_bytes(BUCKET_EVIDENCE, key, data, content_type)
    return key

def storage_status() -> Dict[str, Any]:
    return {
        "minio_endpoint": MINIO_ENDPOINT,
        "minio_available": is_minio_available(),
        "bucket_reports": BUCKET_REPORTS,
        "bucket_evidence": BUCKET_EVIDENCE,
        "mem_fallback_keys": len(_mem_store),
    }
