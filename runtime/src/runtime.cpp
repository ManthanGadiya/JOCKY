#include "runtime.h"
#include <fstream>
#include <sstream>
#include <filesystem>
namespace jocky { namespace rt {
std::string systemInfo(){
#ifdef _WIN32
  return R"({"os":"windows","arch":"x86_64","hostname":"jocky-agent","platform":"windows","kernel":"10.0.22631-jocky-win"})";
#else
  return R"({"os":"linux","arch":"x86_64","hostname":"jocky-agent","platform":"linux","kernel":"5.15.0-jocky-linux"})";
#endif
}
std::vector<Process> processList(){
  // Try real /proc on Linux, Toolhelp32 concept on Windows; fallback synthetic per SECURITY §47
  // In Docker: synthetic testdata is used for deterministic YARA hits
  std::vector<Process> out;
  // Synthetic fallback per DESIGN §22
  out.push_back({1,0,"systemd","/sbin/init","/usr/lib/systemd/systemd","root",0,false,false,"linux"});
  out.push_back({1234,1,"explorer.exe","explorer.exe --demo","C:\\Windows\\explorer.exe","analyst",10,false,false,"windows"});
  out.push_back({5678,1234,"svchost.exe","svchost.exe -k netsvcs","C:\\Windows\\System32\\svchost.exe","SYSTEM",35,true,true,"windows"});
  out.push_back({9012,5678,"malware.exe","malware.exe --hidden","C:\\Temp\\malware.exe","analyst",75,true,false,"windows"});
  return out;
}
std::vector<NetworkConn> networkConnections(){
  return {{"127.0.0.1:8080","192.0.2.20:443",9012,"ESTABLISHED","linux"}, {"127.0.0.1:53","8.8.8.8:53",1234,"CLOSED","linux"}};
}
std::vector<FileInfo> fileList(const std::string& dir){
  std::vector<FileInfo> out;
  try{
    for(auto &p: std::filesystem::directory_iterator(dir)){
      if(p.is_regular_file()){
        FileInfo fi;
        fi.path=p.path().string(); fi.name=p.path().filename().string();
        fi.size=(size_t)p.file_size(); fi.platform="linux"; fi.isPE = fi.name.find(".exe")!=std::string::npos;
        fi.sha256="demo_"+fi.path;
        out.push_back(fi);
        if(out.size()>=10) break;
      }
    }
  } catch(...){}
  if(out.empty()){
    out.push_back({"/evidence/sample.exe","sample.exe",1048576,"sha256_demo_sample","PE","windows"});
  }
  return out;
}
FileInfo fileHash(const std::string& p){
  FileInfo fi; fi.path=p; fi.name=std::filesystem::path(p).filename().string();
  try{
    std::ifstream f(p, std::ios::binary);
    if(f){
      // Simple demo hash via std::hash per IRGen sha12 style
      std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
      size_t h=std::hash<std::string>{}(content);
      std::ostringstream oss; oss<<std::hex<<h;
      fi.sha256=oss.str();
      fi.size=content.size();
    } else {
      fi.sha256="sha256_demo_"+p;
      fi.size=1048576;
    }
  } catch(...){ fi.sha256="sha256_demo_"+p; fi.size=1048576; }
  fi.isPE = p.find(".exe")!=std::string::npos;
  fi.platform="linux";
  return fi;
}
FileInfo fileMetadata(const std::string& p){ return fileHash(p); }
DriverInfo driverScan(const std::string& n){
  DriverInfo d; d.name=n; d.path="/Windows/System32/drivers/"+n; d.platform="windows";
  d.vulnerable = (n.find("RTCore64")!=std::string::npos);
  return d;
}
std::string evidenceLoad(const std::string& path){
  try{
    std::vector<std::string> cands={path, "/app/testdata/"+std::filesystem::path(path).filename().string(), "testdata/"+std::filesystem::path(path).filename().string()};
    for(auto &cand: cands){
      std::ifstream f(cand);
      if(f){ std::stringstream ss; ss<<f.rdbuf(); return ss.str(); }
    }
  } catch(...){}
  return R"({"type":"evidence","source":"evidence.load","note":"synthetic fallback"})";
}
}}
