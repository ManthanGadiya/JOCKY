"""
Provider factory per ARCHITECTURE.md §8 + DESIGN.md §71
Selects Windows vs Linux adapter without leaking platform details into JOCKY language (LANGUAGE_SPEC §27).
"""
import os, sys
from typing import Literal

Platform = Literal["windows","linux"]

def detect_platform() -> Platform:
    # 1. explicit env (used by docker-compose AGENT_PLATFORM / JOCKY_PLATFORM)
    for key in ("JOCKY_PLATFORM","AGENT_PLATFORM","PLATFORM"):
        v = os.getenv(key)
        if v and v.lower() in ("windows","linux","win","ubuntu"):
            return "windows" if v.lower().startswith("win") else "linux"
    # 2. sys.platform (host auto-detect)
    if sys.platform.startswith("win"):
        return "windows"
    return "linux"

def get_providers(platform: str = None):
    """Return tuple (system, process, file, network, driver) providers for given platform."""
    p = (platform or detect_platform()).lower()
    if p in ("win","windows"):
        from .windows import WindowsSystemProvider, WindowsProcessProvider, WindowsFileProvider, WindowsNetworkProvider, WindowsDriverProvider
        return WindowsSystemProvider(), WindowsProcessProvider(), WindowsFileProvider(), WindowsNetworkProvider(), WindowsDriverProvider()
    else:
        from .linux import LinuxSystemProvider, LinuxProcessProvider, LinuxFileProvider, LinuxNetworkProvider, LinuxDriverProvider
        return LinuxSystemProvider(), LinuxProcessProvider(), LinuxFileProvider(), LinuxNetworkProvider(), LinuxDriverProvider()

def platform_from_request(platform_param: str = None, header_platform: str = None) -> Platform:
    """Priority: explicit param > header X-Platform > env/auto-detect."""
    if platform_param and platform_param.lower() in ("windows","linux"):
        return platform_param.lower()  # type: ignore
    if header_platform and header_platform.lower() in ("windows","linux"):
        return header_platform.lower()  # type: ignore
    return detect_platform()
