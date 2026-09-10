"""
Providers — platform abstraction per ARCHITECTURE.md §8, DESIGN.md §22-23, FORENSICS_SPEC.md §67

Implements:
  IProcessProvider / IFileProvider / INetworkProvider / ISystemProvider
  WindowsProcessProvider (WinAPI-style synthetic) vs LinuxProcessProvider (/proc-style synthetic)
  Both return normalized evidence payloads satisfying FORENSICS_SPEC §11-15 common schema.

Selection via:
  - Request param platform="windows"|"linux" (explicit per LANGUAGE_SPEC §27 — JOCKY language not platform-specific, provider chosen at runtime)
  - Env JOCKY_PLATFORM or AGENT_PLATFORM
  - Fallback auto-detect (sys.platform)
  - Header X-Platform (future/nginx)
Single-source contract tests in tests/test_platform_providers.py per TEST_PLAN.md §57

Safety: synthetic only per SECURITY_MODEL §47-49 — no WinAPI Toolhelp32/ETW, no /proc parsing requiring root.
"""
