#pragma once
#include <string>
#include <vector>
// JOCKY Runtime - cross-platform forensic adapters (Gap 4: expanded to match Python providers)
// Windows: WinAPI Toolhelp32/PSAPI/WMI (live via psutil-equivalent), Linux: /proc + hashlib (inside Docker: synthetic JSON + real /proc when available)
namespace jocky { namespace rt {
struct Process { int pid; int ppid; std::string name; std::string cmdline; std::string path; std::string user; int risk; bool hollowed; bool ppid_anomaly; std::string platform; };
struct NetworkConn { std::string local; std::string remote; int pid; std::string state; std::string platform; };
struct FileInfo { std::string path; std::string name; size_t size; std::string sha256; bool isPE; std::string platform; };
struct DriverInfo { std::string name; std::string path; bool vulnerable; std::string platform; };

std::vector<Process> processList();
std::vector<NetworkConn> networkConnections();
std::vector<FileInfo> fileList(const std::string& dir);
FileInfo fileHash(const std::string& path);
FileInfo fileMetadata(const std::string& path);
DriverInfo driverScan(const std::string& name);
std::string systemInfo();
std::string evidenceLoad(const std::string& path);
}}
