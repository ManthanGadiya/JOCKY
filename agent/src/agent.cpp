#include <iostream>
#include <fstream>
#include <string>
// jocky-agent - endpoint collector (Layer 4)
// Inside Docker: reads testdata/*.json and POSTs to backend via Nginx proxy (Layer 5)
// No real WinAPI here - synthetic evidence mode (ethical, no BSOD)
int main(int argc, char** argv){
  std::string mode="scan";
  if(argc>1) mode=argv[1];
  std::cout << "[agent] JOCKY Agent (synthetic mode) - " << mode << "\n";
  std::cout << "[agent] Reading testdata/hollowing.json, byovd_driver.json...\n";
  std::ifstream f("/app/testdata/hollowing.json");
  if(f){ std::string s((std::istreambuf_iterator<char>(f)),{}); std::cout << s.substr(0,300) << "\n"; }
  else std::cout << "[agent] No testdata found - using built-in synthetic\n";
  std::cout << "[agent] Would POST to $BACKEND_URL/api/evidence via wss://nginx/agent/ws\n";
  std::cout << "[agent] Done. Evidence queued.\n";
  return 0;
}
