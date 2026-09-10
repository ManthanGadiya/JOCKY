"""
Cache layer — Redis with in-memory fallback per ARCHITECTURE.md §11
Provides: init_cache(), is_redis_available(), cache_get/set/invalidate()

Used for: job queue placeholder, timeline/graph caching, rate limit counters
Per DESIGN.md §13-14: minimal, version-pinned, auditable
"""
import os, json, time, hashlib
from typing import Optional, Any

REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")

_client = None
_available = False
_mem_cache: dict = {}
_mem_expiry: dict = {}

def init_cache():
    global _client, _available
    try:
        from redis import Redis  # type: ignore
        # parse URL like redis://redis:6379/0
        # try docker host first, fallback to localhost
        for url in [REDIS_URL, "redis://localhost:6379/0", "redis://127.0.0.1:6379/0"]:
            try:
                c = Redis.from_url(url, socket_connect_timeout=2, decode_responses=True)
                c.ping()
                _client = c
                _available = True
                print(f"[cache] Redis connected at {url}")
                return True
            except Exception as e:
                last_err = e
                continue
        print(f"[cache] Redis not available ({last_err}) — in-memory fallback")
        _client = None
        _available = False
        return False
    except ImportError:
        print("[cache] redis package not installed — in-memory fallback")
        _client = None
        _available = False
        return False
    except Exception as e:
        print(f"[cache] init failed {e} — fallback")
        _client = None
        _available = False
        return False

try:
    init_cache()
except Exception:
    pass

def is_redis_available() -> bool:
    return _available and _client is not None

def _mem_cleanup():
    now = time.time()
    for k, exp in list(_mem_expiry.items()):
        if exp and now > exp:
            _mem_cache.pop(k, None)
            _mem_expiry.pop(k, None)

def cache_get(key: str) -> Optional[Any]:
    if is_redis_available():
        try:
            v = _client.get(key)
            if v is not None:
                try:
                    return json.loads(v)
                except Exception:
                    return v
        except Exception:
            pass
    _mem_cleanup()
    return _mem_cache.get(key)

def cache_set(key: str, value: Any, ttl: int = 60) -> None:
    payload = json.dumps(value) if not isinstance(value, str) else value
    if is_redis_available():
        try:
            _client.setex(key, ttl, payload)
            return
        except Exception:
            pass
    _mem_cleanup()
    _mem_cache[key] = value if not isinstance(value, str) else value
    if ttl:
        _mem_expiry[key] = time.time() + ttl

def cache_invalidate(pattern: str = None, key: str = None) -> int:
    """Invalidate by exact key or pattern prefix."""
    if key:
        if is_redis_available():
            try:
                return int(_client.delete(key) or 0)
            except Exception:
                pass
        return int(_mem_cache.pop(key, None) is not None)
    if pattern and is_redis_available():
        try:
            keys = _client.keys(pattern)
            if keys:
                return int(_client.delete(*keys) or 0)
        except Exception:
            pass
    # mem fallback: delete keys matching prefix
    if pattern:
        pref = pattern.replace("*","")
        removed = 0
        for k in list(_mem_cache.keys()):
            if k.startswith(pref):
                _mem_cache.pop(k, None); _mem_expiry.pop(k, None); removed+=1
        return removed
    return 0

def cache_status() -> dict:
    return {"redis_url": REDIS_URL, "redis_available": is_redis_available(), "mem_keys": len(_mem_cache)}
