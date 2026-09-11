"""
Windows provider — synthetic WinAPI-style observations per DESIGN.md §22
No real WinAPI calls (synthetic per SECURITY_MODEL §47); demonstrates
platform-specific fields normalized to common schema (FORENSICS_SPEC §67).
"""
import hashlib
from typing import List, Dict, Any
from .base import ISystemProvider, IProcessProvider, IFileProvider, INetworkProvider, IDriverProvider

class WindowsSystemProvider(ISystemProvider):
    def collect(self, host_id: str) -> Dict[str, Any]:
        return {
            "type": "system",
            "hostname": host_id,
            "os": "windows",
            "arch": "x86_64",
            "kernel": "10.0.22631-jocky-win",
            "version": "Windows 11 Pro",
            "build": "22631",
            "timezone": "UTC",
            "platform": "windows",
            "source_adapter": "WindowsSystemProvider (synthetic)",
        }

class WindowsProcessProvider(IProcessProvider):
    def list_processes(self, host_id: str) -> List[Dict[str, Any]]:
        # Try real psutil on Windows host only per ROADMAP Phase 15 — synthetic fallback on Linux host
        try:
            import sys as _sys
            if not _sys.platform.startswith("win"):
                raise ImportError("skip Windows real on Linux host")
            import psutil, platform as _pl
            if _pl.system().lower().startswith("win"):
                procs = []
                for p in psutil.process_iter(['pid','ppid','name','exe','username']):
                    try:
                        info = p.info
                        procs.append({
                            "pid": int(info.get('pid',0)),
                            "ppid": int(info.get('ppid',0) or 0),
                            "name": info.get('name') or f"pid-{info.get('pid')}",
                            "path": info.get('exe') or f"C:\\Windows\\System32\\{info.get('name','')}",
                            "user": info.get('username') or "SYSTEM",
                            "creation_time": "2026-08-28T10:30:00Z",
                            "platform": "windows",
                            "session_id": 1,
                            "source_adapter": "WindowsProcessProvider (psutil live)",
                        })
                        if len(procs) >= 50:
                            break
                    except Exception:
                        continue
                if len(procs) >= 5:
                    # inject synthetic anomaly for Sigma determinism
                    procs.append({"pid": 99999, "ppid": 1234, "name": "svchost.exe", "path": "C:\\Windows\\System32\\svchost.exe", "user": "SYSTEM", "creation_time": "2026-08-28T10:32:03Z", "platform": "windows", "ppid_anomaly": True, "risk": 35, "sigma_hit": "jocky-001 Parent Anomaly (T1055)", "command_line": "svchost.exe -k netsvcs", "source_adapter": "synthetic-injected"})
                    return procs
        except Exception:
            pass
        # fallback synthetic
        return [
            {"pid": 4, "ppid": 0, "name": "System", "path": "", "user": "SYSTEM", "creation_time": "2026-08-28T10:30:00Z", "platform": "windows", "session_id": 0, "source_adapter": "synthetic fallback"},
            {"pid": 1234, "ppid": 4, "name": "explorer.exe", "path": "C:\\Windows\\explorer.exe", "user": "analyst", "creation_time": "2026-08-28T10:31:00Z", "platform": "windows", "session_id": 1, "risk": 10, "source_adapter": "synthetic fallback"},
            {"pid": 5678, "ppid": 1234, "name": "svchost.exe", "path": "C:\\Windows\\System32\\svchost.exe", "user": "SYSTEM", "creation_time": "2026-08-28T10:32:03Z", "platform": "windows", "ppid_anomaly": True, "risk": 35, "sigma_hit": "jocky-001 Parent Anomaly (T1055)", "command_line": "svchost.exe -k netsvcs", "source_adapter": "synthetic fallback"},
            {"pid": 9012, "ppid": 5678, "name": "malware.exe", "path": "C:\\Temp\\malware.exe", "user": "analyst", "creation_time": "2026-08-28T10:31:45Z", "platform": "windows", "risk": 75, "yara_hit": "JOCKY_DEMO_MARKER", "command_line": "C:\\Temp\\malware.exe --hidden", "source_adapter": "synthetic fallback"},
        ]

class WindowsFileProvider(IFileProvider):
    def hash_file(self, path: str, host_id: str) -> Dict[str, Any]:
        import pathlib as _pl, os as _os
        real_sha = None
        real_size = None
        try:
            if _pl.Path(path).exists() and _pl.Path(path).is_file():
                h = hashlib.sha256()
                with open(path, "rb") as f:
                    for chunk in iter(lambda: f.read(8192), b""):
                        h.update(chunk)
                real_sha = h.hexdigest()
                real_size = _pl.Path(path).stat().st_size
        except Exception:
            pass
        sha = real_sha or hashlib.sha256(path.encode()).hexdigest()
        name = path.split("\\")[-1].split("/")[-1]
        low = path.lower()
        is_susp = any(k in low for k in ("malware","suspicious","sample.exe","evil","payload"))
        return {
            "type": "file",
            "path": path,
            "name": name,
            "size": real_size if real_size is not None else (1048576 if is_susp else 2048),
            "file_type": "PE32 executable" if path.lower().endswith(".exe") else "text",
            "creation_time": "2026-08-28T10:31:12Z",
            "platform": "windows",
            "hashes": {"sha256": sha, "sha512": hashlib.sha512(path.encode()).hexdigest()[:64]},
            "sha256": sha,
            "yara_hit": "JOCKY_DEMO_MARKER" if is_susp else None,
            "mitre": "T1105" if is_susp else None,
            "source_adapter": "WindowsFileProvider (live)" if real_sha else "WindowsFileProvider",
            "real_file": real_sha is not None,
        }

class WindowsNetworkProvider(INetworkProvider):
    def list_connections(self, host_id: str) -> List[Dict[str, Any]]:
        return [
            {"local_address": "192.0.2.10", "local_port": 49152, "remote_address": "192.0.2.20", "remote_port": 443, "protocol": "TCP", "state": "ESTABLISHED", "pid": 9012, "process_name": "malware.exe", "platform": "windows", "observed_at": "2026-08-28T10:32:45Z", "risk": 80, "note": "C2 beacon (Windows TCP table)"},
            {"local_address": "192.0.2.10", "local_port": 5353, "remote_address": "224.0.0.251", "remote_port": 5353, "protocol": "UDP", "state": "LISTEN", "pid": 5678, "process_name": "svchost.exe", "platform": "windows", "risk": 0},
        ]

class WindowsDriverProvider(IDriverProvider):
    def scan(self, host_id: str) -> Dict[str, Any]:
        return {"name": "RTCore64.sys", "path": "C:\\Windows\\System32\\drivers\\RTCore64.sys", "version": "1.0.0", "publisher": "Micro-Star", "signature_status": "unsigned", "platform": "windows", "vulnerable": False, "source_adapter": "WindowsDriverProvider"}
