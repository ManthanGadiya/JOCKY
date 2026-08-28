#pragma once
#include <string>
#include <vector>
// JOCKY Runtime - cross-platform forensic adapters
// Windows: WinAPI Toolhelp32/PSAPI/WMI/ETW, Linux: /proc/auditd (inside Docker: synthetic JSON)
namespace jocky { namespace rt {
struct Process { int pid; int ppid; std::string name; std::string cmdline; int risk; bool hollowed; };
std::vector<Process> processList();
std::string systemInfo();
std::string fileHash(const std::string& path);
std::string driverScan(const std::string& name);
}}
