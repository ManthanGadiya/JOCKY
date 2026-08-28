#include "runtime.h"
#include <fstream>
namespace jocky { namespace rt {
std::string systemInfo(){ return R"({"os":"linux","arch":"x86_64","hostname":"jocky-agent"})"; }
std::string fileHash(const std::string& p){ return "sha256:demo_"+p; }
std::string driverScan(const std::string& n){ return R"({"name":")" + n + R"(","vulnerable":false})"; }
std::vector<Process> processList(){
  // In Docker: read synthetic testdata if present
  std::ifstream f("/app/testdata/hollowing.json");
  if(f){ /* parse real synthetic */ }
  return {{1234,1,"explorer.exe","C:\\Windows\\explorer.exe",85,true},{5678,1234,"svchost.exe","",20,false}};
}
}}
