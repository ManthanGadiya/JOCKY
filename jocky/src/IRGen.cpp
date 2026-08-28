#include "jocky/IRGen.h"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <random>
#include <filesystem>
#include <chrono>

namespace jocky {

static std::string xorEncrypt(const std::string& s, uint32_t seed){
  std::string o=s; std::mt19937 rng(seed); uint8_t k=rng()%255+1;
  for(auto& c:o) c ^= k; return o;
}

std::string generateIRText(const std::string& jockySource, uint32_t seed, bool poly){
  std::mt19937 rng(seed ? seed : (uint32_t)std::chrono::steady_clock::now().time_since_epoch().count());
  uint32_t entry = 0x140001000 + (poly ? (rng()%0x5000) : 0);
  // shuffle imports
  std::vector<std::string> imports = {"kernel32.dll","ntdll.dll","advapi32.dll","user32.dll"};
  if(poly) std::shuffle(imports.begin(), imports.end(), rng);
  // token stream mock
  std::ostringstream ir;
  ir << "; JOCKY IR - seed=" << seed << " poly=" << (poly?"1":"0") << "\n";
  ir << "; Source hash: " << std::hash<std::string>{}(jockySource) << "\n";
  ir << "; EntryPoint: 0x" << std::hex << entry << std::dec << "\n";
  ir << "; Imports: ";
  for(auto &im: imports) ir << im << " ";
  ir << "\n";
  ir << "; JOCKY_DEMO_MARKER\n";
  if(poly){
    ir << "; -- polymorphic transforms applied --\n";
    ir << "; cfg-flatten:(dispatch=" << (rng()%8+2) << ")\n";
    ir << "; string-encrypt:xor(key=" << (rng()%255) << ")\n";
    ir << "; import-obfuscate:shuffled\n";
  }
  ir << "define i32 @main() {\n";
  ir << "entry:\n";
  // emit calls based on source detection
  auto has = [&](const char* kw){ return jockySource.find(kw)!=std::string::npos; };
  int callId=0;
  auto emitCall=[&](const char* fn){
    uint32_t id = poly ? rng() : (uint32_t)callId;
    ir << "  ; jocky call: " << fn << " [id=" << id << "]\n";
    ir << "  %" << callId++ << " = call i32 @jocky_" << fn << "() ; poly_id=" << id << "\n";
  };
  if(has("system.info")) emitCall("system_info");
  if(has("process.list")) emitCall("process_list");
  if(has("process.tree")) emitCall("process_tree");
  if(has("file.list")) emitCall("file_list");
  if(has("file.hash")) emitCall("file_hash");
  if(has("file.analyze")) emitCall("file_analyze");
  if(has("network.connections")) emitCall("network_connections");
  if(has("network.interfaces")) emitCall("network_interfaces");
  if(has("memory.analyze")) emitCall("memory_analyze");
  if(has("driver.list")) emitCall("driver_list");
  if(has("driver.scan")) emitCall("driver_scan");
  if(has("driver.risk")) emitCall("driver_risk");
  if(callId==0) emitCall("nop");
  // CFG flatten extra blocks
  if(poly){
    int blocks = rng()%4+2;
    for(int i=0;i<blocks;i++){
      ir << "bb.poly." << i << ":\n";
      ir << "  %" << callId++ << " = add i32 " << (rng()%100) << ", " << (rng()%100) << "\n";
      ir << "  br label %bb.poly." << (i+1) << "\n";
    }
    ir << "bb.poly." << blocks << ":\n";
  }
  ir << "  ret i32 0\n";
  ir << "}\n";
  ir << "declare i32 @jocky_system_info()\n";
  ir << "declare i32 @jocky_process_list()\n";
  ir << "declare i32 @jocky_file_analyze()\n";
  return ir.str();
}

int generateIR(const std::string& sourcePath, const IRGenOptions& opts, std::string* out_ir){
  std::ifstream f(sourcePath);
  if(!f) return 1;
  std::string src((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
  uint32_t seed = opts.seed ? opts.seed : (opts.polymorphic ? (uint32_t)std::random_device{}() : 0x1234);
  std::string ir = generateIRText(src, seed, opts.polymorphic);
  if(out_ir) *out_ir = ir;
  if(!opts.output.empty()){
    std::filesystem::create_directories(std::filesystem::path(opts.output).parent_path());
    std::ofstream o(opts.output); o << ir;
    // also write tokens/ast dumps
    std::ofstream t(opts.output + ".tokens"); t << "; tokens seed=" << seed << " poly=" << opts.polymorphic << "\n" << src.size() << " bytes\n";
    std::ofstream a(opts.output + ".ast"); a << "; AST for " << sourcePath << " seed=" << seed << "\n";
  }
  return 0;
}
}
