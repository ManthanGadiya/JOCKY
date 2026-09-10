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
        # Synthetic WinAPI Toolhelp32-style tree with Windows paths
        return [
            {"pid": 4, "ppid": 0, "name": "System", "path": "", "user": "SYSTEM", "creation_time": "2026-08-28T10:30:00Z", "platform": "windows", "session_id": 0},
            {"pid": 1234, "ppid": 4, "name": "explorer.exe", "path": "C:\\Windows\\explorer.exe", "user": "analyst", "creation_time": "2026-08-28T10:31:00Z", "platform": "windows", "session_id": 1, "risk": 10},
            {"pid": 5678, "ppid": 1234, "name": "svchost.exe", "path": "C:\\Windows\\System32\\svchost.exe", "user": "SYSTEM", "creation_time": "2026-08-28T10:32:03Z", "platform": "windows", "ppid_anomaly": True, "risk": 35, "sigma_hit": "jocky-001 Parent Anomaly (T1055)", "command_line": "svchost.exe -k netsvcs"},
            {"pid": 9012, "ppid": 5678, "name": "malware.exe", "path": "C:\\Temp\\malware.exe", "user": "analyst", "creation_time": "2026-08-28T10:31:45Z", "platform": "windows", "risk": 75, "yara_hit": "JOCKY_DEMO_MARKER", "command_line": "C:\\Temp\\malware.exe --hidden"},
        ]

class WindowsFileProvider(IFileProvider):
    def hash_file(self, path: str, host_id: str) -> Dict[str, Any]:
        sha = hashlib.sha256(path.encode()).hexdigest()
        name = path.split("\\")[-1].split("/")[-1]
        low = path.lower()
        is_susp = any(k in low for k in ("malware","suspicious","sample.exe","evil","payload"))
        return {
            "type": "file",
            "path": path,
            "name": name,
            "size": 1048576 if is_susp else 2048,
            "file_type": "PE32 executable" if path.lower().endswith(".exe") else "text",
            "creation_time": "2026-08-28T10:31:12Z",
            "platform": "windows",
            "hashes": {"sha256": sha, "sha512": hashlib.sha512(path.encode()).hexdigest()[:64]},
            "sha256": sha,
            "yara_hit": "JOCKY_DEMO_MARKER" if is_susp else None,
            "mitre": "T1105" if is_susp else None,
            "source_adapter": "WindowsFileProvider",
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
