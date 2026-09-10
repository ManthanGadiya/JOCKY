"""
Linux provider — synthetic /proc-style observations per DESIGN.md §22
No real /proc parsing (synthetic per SECURITY_MODEL §47); demonstrates
Linux-specific fields normalized to common schema (FORENSICS_SPEC §29).
"""
import hashlib
from typing import List, Dict, Any
from .base import ISystemProvider, IProcessProvider, IFileProvider, INetworkProvider, IDriverProvider

class LinuxSystemProvider(ISystemProvider):
    def collect(self, host_id: str) -> Dict[str, Any]:
        return {
            "type": "system",
            "hostname": host_id,
            "os": "linux",
            "arch": "x86_64",
            "kernel": "5.15.0-jocky-linux",
            "version": "Ubuntu 24.04",
            "distro": "ubuntu",
            "timezone": "UTC",
            "platform": "linux",
            "source_adapter": "LinuxSystemProvider (synthetic, /proc)",
        }

class LinuxProcessProvider(IProcessProvider):
    def list_processes(self, host_id: str) -> List[Dict[str, Any]]:
        # /proc-style with Linux paths and uid, ppid anomaly preserved
        return [
            {"pid": 1, "ppid": 0, "name": "systemd", "path": "/usr/lib/systemd/systemd", "user": "root", "uid": 0, "creation_time": "2026-08-28T10:30:00Z", "platform": "linux", "cmdline": "/sbin/init splash"},
            {"pid": 1234, "ppid": 1, "name": "explorer.exe", "path": "/usr/bin/explorer.exe", "user": "analyst", "uid": 1000, "creation_time": "2026-08-28T10:31:00Z", "platform": "linux", "risk": 10, "note": "synthetic Linux mapping of Windows process for contract test"},
            {"pid": 5678, "ppid": 1234, "name": "svchost.exe", "path": "/usr/bin/svchost", "user": "root", "uid": 0, "creation_time": "2026-08-28T10:32:03Z", "platform": "linux", "ppid_anomaly": True, "risk": 35, "sigma_hit": "jocky-001 Parent Anomaly (T1055)", "cmdline": "svchost --daemon"},
            {"pid": 9012, "ppid": 5678, "name": "malware.exe", "path": "/tmp/malware.exe", "user": "analyst", "uid": 1000, "creation_time": "2026-08-28T10:31:45Z", "platform": "linux", "risk": 75, "yara_hit": "JOCKY_DEMO_MARKER", "cmdline": "/tmp/malware.exe --hidden"},
        ]

class LinuxFileProvider(IFileProvider):
    def hash_file(self, path: str, host_id: str) -> Dict[str, Any]:
        sha = hashlib.sha256(path.encode()).hexdigest()
        name = path.split("/")[-1]
        low = path.lower()
        is_susp = any(k in low for k in ("malware","suspicious","sample","evil","payload"))
        return {
            "type": "file",
            "path": path,
            "name": name,
            "size": 1048576 if is_susp else 2048,
            "file_type": "ELF 64-bit" if path.endswith(".elf") or "malware" in low else "PE32" if path.endswith(".exe") else "text",
            "creation_time": "2026-08-28T10:31:12Z",
            "platform": "linux",
            "permissions": "755" if is_susp else "644",
            "owner": "analyst:analyst",
            "hashes": {"sha256": sha, "sha512": hashlib.sha512(path.encode()).hexdigest()[:64]},
            "sha256": sha,
            "yara_hit": "JOCKY_DEMO_MARKER" if is_susp else None,
            "mitre": "T1105" if is_susp else None,
            "source_adapter": "LinuxFileProvider",
        }

class LinuxNetworkProvider(INetworkProvider):
    def list_connections(self, host_id: str) -> List[Dict[str, Any]]:
        return [
            {"local_address": "192.0.2.10", "local_port": 49152, "remote_address": "192.0.2.20", "remote_port": 443, "protocol": "TCP", "state": "ESTABLISHED", "pid": 9012, "process_name": "malware.exe", "platform": "linux", "observed_at": "2026-08-28T10:32:45Z", "risk": 80, "note": "C2 beacon (/proc/net/tcp)", "inode": 12345},
            {"local_address": "192.0.2.10", "local_port": 5353, "remote_address": "224.0.0.251", "remote_port": 5353, "protocol": "UDP", "state": "LISTEN", "pid": 5678, "process_name": "svchost.exe", "platform": "linux", "risk": 0, "inode": 12346},
        ]

class LinuxDriverProvider(IDriverProvider):
    def scan(self, host_id: str) -> Dict[str, Any]:
        return {"name": "rtc_core.ko", "path": "/lib/modules/5.15.0/drivers/rtc_core.ko", "version": "1.0.0", "publisher": "kernel", "signature_status": "unsigned", "platform": "linux", "vulnerable": False, "source_adapter": "LinuxDriverProvider", "lsmod": "rtc_core 16384 0"}
