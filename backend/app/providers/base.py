from abc import ABC, abstractmethod
from typing import List, Dict, Any

class ISystemProvider(ABC):
    @abstractmethod
    def collect(self, host_id: str) -> Dict[str, Any]:
        """Return normalized system payload per FORENSICS_SPEC §10"""
        ...

class IProcessProvider(ABC):
    @abstractmethod
    def list_processes(self, host_id: str) -> List[Dict[str, Any]]:
        """Return list of normalized process dicts per FORENSICS_SPEC §11 (pid, ppid, name, path, ...)."""
        ...

class IFileProvider(ABC):
    @abstractmethod
    def hash_file(self, path: str, host_id: str) -> Dict[str, Any]:
        """Return normalized file payload per §13 (path, size, hashes, etc). Must validate path first."""
        ...

class INetworkProvider(ABC):
    @abstractmethod
    def list_connections(self, host_id: str) -> List[Dict[str, Any]]:
        """Return normalized network connections per §15."""
        ...

class IDriverProvider(ABC):
    @abstractmethod
    def scan(self, host_id: str) -> Dict[str, Any]:
        ...
