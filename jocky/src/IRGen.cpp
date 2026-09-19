#include "jocky/IRGen.h"
#include "jocky/Lexer.h"
#include "jocky/Parser.h"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <random>
#include <filesystem>
#include <chrono>
#include <regex>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace jocky {

static std::string xorEncrypt(const std::string& s, uint32_t seed){
  std::string o=s; std::mt19937 rng(seed); uint8_t k=rng()%255+1;
  for(auto& c:o) c ^= k; return o;
}

// Whitelisted forensic ops per LANGUAGE_SPEC.md + SECURITY_MODEL.md §16
static const std::unordered_map<std::string, std::string> OP_CAPS = {
  {"system.info","system.read"},
  {"process.list","process.read"},
  {"process.tree","process.read"},
  {"process.modules","process.read"},
  {"file.list","file.read"},
  {"file.hash","file.hash"},
  {"file.analyze","file.read"},
  {"file.metadata","file.read"},
  {"network.connections","network.read"},
  {"network.interfaces","network.read"},
  {"memory.analyze","memory.analyze"},
  {"driver.list","driver.read"},
  {"driver.scan","driver.read"},
  {"driver.risk","driver.read"},
  {"report.generate","report.generate"},
  {"evidence.load","evidence.read"},
};

static std::vector<std::string> detShuffle(const std::vector<std::string>& in, uint32_t seed){ std::vector<std::string> o=in; std::mt19937 r(seed); std::shuffle(o.begin(), o.end(), r); return o; }
static uint32_t xorKey(uint32_t seed){ std::mt19937 r(seed ^ 0x5A5A); return r()%255+1; }
static void cfgParams(uint32_t seed, int &states, int &disp, std::vector<int> &order){ std::mt19937 r(seed ^ 0xA11CE); states=r()%4+3; disp=r()%8+2; std::vector<int> v; for(int i=0;i<states;i++) v.push_back(i); order=std::vector<int>(states); std::mt19937 r2(seed ^ 0xC0FFEE); std::shuffle(v.begin(), v.end(), r2); order=v; }
static std::string sha12(const std::string& s){
  // simple header hash: use std::hash then hex, but for IRResult we use sha12 via hash
  // Real SHA256 is computed in Python fallback; here keep std::hash for backward compat + also expose hex hash
  size_t h = std::hash<std::string>{}(s);
  std::ostringstream oss; oss << std::hex << std::setw(12) << std::setfill('0') << (h & 0xffffffffffffULL);
  return oss.str();
}

IRResult generateIRWithValidation(const std::string& jockySource, uint32_t seed, bool poly){
  IRResult res;
  res.ir_version = 1;
  res.source_hash = sha12(jockySource);
  // Use lexer + parser for validation (Gap 4: token-based per g4, not just regex)
  auto toks = lex(jockySource);
  auto pr = parseMemberCalls(toks);
  // Collect parser errors (investigation, imports, funcs, filter/correlate)
  auto inv = parseInvestigations(toks);
  auto imp = parseImports(toks);
  auto fnc = parseFunctions(toks);
  // Filter/correlate arity via simple string scan for now (mirrors Python's parse_lang_builtins)
  std::vector<std::string> builtinErrs;
  // Check for filter( and correlate( arity via regex on source for simplicity in C++ (kept per Python)
  {
    std::regex reFilter(R"(\bfilter\s*\()");
    std::sregex_iterator it(jockySource.begin(), jockySource.end(), reFilter);
    std::sregex_iterator end;
    for(; it!=end; ++it){
      size_t pos = it->position();
      // find matching ')' and count commas at depth 1
      size_t start = pos + it->str().size();
      int depth=1; size_t j=start; int commas=0; bool hasContent=false;
      while(j<jockySource.size() && depth>0){
        char c=jockySource[j];
        if(c=='(') depth++;
        else if(c==')'){ depth--; if(depth==0) break; }
        else if(c==',' && depth==1) commas++;
        else if(!isspace((unsigned char)c) && depth==1) hasContent=true;
        j++;
      }
      int args = hasContent ? commas+1 : 0;
      if(args < 2) builtinErrs.push_back("filter() requires at least 2 args per LANGUAGE_SPEC §12 at col "+std::to_string(pos));
    }
    std::regex reCorr(R"(\bcorrelate\s*\()");
    it = std::sregex_iterator(jockySource.begin(), jockySource.end(), reCorr);
    for(; it!=end; ++it){
      size_t pos = it->position();
      size_t start = pos + it->str().size();
      int depth=1; size_t j=start; int commas=0; bool hasContent=false;
      while(j<jockySource.size() && depth>0){
        char c=jockySource[j];
        if(c=='(') depth++;
        else if(c==')'){ depth--; if(depth==0) break; }
        else if(c==',' && depth==1) commas++;
        else if(!isspace((unsigned char)c) && depth==1) hasContent=true;
        j++;
      }
      int args = hasContent ? commas+1 : 0;
      if(args < 2) builtinErrs.push_back("correlate() requires at least 2 args per LANGUAGE_SPEC §15 at col "+std::to_string(pos));
    }
  }
  // Aggregate all parser errors first (fail-closed)
  std::vector<std::string> allErrs;
  allErrs.insert(allErrs.end(), pr.errors.begin(), pr.errors.end());
  allErrs.insert(allErrs.end(), inv.second.begin(), inv.second.end());
  allErrs.insert(allErrs.end(), imp.second.begin(), imp.second.end());
  allErrs.insert(allErrs.end(), fnc.second.begin(), fnc.second.end());
  allErrs.insert(allErrs.end(), builtinErrs.begin(), builtinErrs.end());
  if(!allErrs.empty()){
    res.code = 2;
    std::string msg;
    for(size_t i=0;i<allErrs.size();i++){ if(i) msg+=", "; msg+=allErrs[i]; }
    res.error = msg;
    return res;
  }
  // Build found list from parsed MemberCalls (not regex)
  std::vector<std::pair<std::string,std::string>> found;
  for(auto &c: pr.calls){
    found.push_back({c.ns, c.ns+"."+c.method});
  }
  // validate: each found must be in whitelist; also track unique ops/caps
  std::unordered_set<std::string> seen;
  for(auto &p: found){
    std::string key = p.second;
    auto f = OP_CAPS.find(key);
    if(f == OP_CAPS.end()){
      res.code = 2;
      res.error = "Unknown or unsupported capability: " + key + " — not in JOCKY IR whitelist (see IR_SPEC). Fail-closed.";
      return res;
    }
    if(seen.insert(key).second){
      res.ops.push_back(key);
      res.capabilities.push_back(f->second);
    }
  }
  // deduplicate capabilities
  {
    std::unordered_set<std::string> cset(res.capabilities.begin(), res.capabilities.end());
    res.capabilities.assign(cset.begin(), cset.end());
  }
  // if no ops found but source non-empty and contains a member call pattern that was rejected above would have errored
  // otherwise generate IR text (delegates to generateIRText for backward compat)
  res.ir = generateIRText(jockySource, seed, poly);
  // prepend validated header (we regenerate header part with capabilities)
  // Inject after first line: add IR_VERSION and IR_CAPS
  std::string capsStr;
  for(size_t i=0;i<res.capabilities.size();i++){
    if(i) capsStr += ", ";
    capsStr += res.capabilities[i];
  }
  if(capsStr.empty()) capsStr = "(none)";
  std::string opsStr;
  for(size_t i=0;i<res.ops.size();i++){
    if(i) opsStr += ", ";
    opsStr += res.ops[i];
  }
  if(opsStr.empty()) opsStr = "(none)";
  // Insert lines after "; JOCKY IR - seed=..."
  std::string inject = "; IR_VERSION=1\n; IR_CAPS: " + capsStr + "\n; IR_OPS: " + opsStr + "\n";
  size_t pos = res.ir.find("\n");
  if(pos != std::string::npos) res.ir.insert(pos+1, inject);
  res.code = 0;
  return res;
}

std::string generateIRText(const std::string& jockySource, uint32_t seed, bool poly){
  // First run validation to get ops/caps but ignore error for pure text generation? Keep validation separate.
  // For generateIRText we still produce IR even if ops empty; validation is done in generateIRWithValidation
  // Phase 2 LAB deterministic transforms (see docs/PHASE2_DESIGN.md)
  std::mt19937 rng(seed ? seed : (uint32_t)std::chrono::steady_clock::now().time_since_epoch().count());
  uint32_t entry = 0x140001000 + (poly ? (rng()%0x5000) : 0);
  std::vector<std::string> baseImports = {"kernel32.dll","ntdll.dll","advapi32.dll","user32.dll"};
  std::vector<std::string> imports = poly ? detShuffle(baseImports, seed) : baseImports;
  uint32_t labXorKey = poly ? xorKey(seed) : 0;
  int labStates=0, labDisp=0; std::vector<int> labOrder; if(poly) cfgParams(seed, labStates, labDisp, labOrder);
  std::ostringstream ir;
  ir << "; JOCKY IR - seed=" << seed << " poly=" << (poly?"1":"0") << "\n";
  ir << "; Source hash: " << sha12(jockySource) << "\n";
  ir << "; EntryPoint: 0x" << std::hex << entry << std::dec << "\n";
  ir << "; Imports: ";
  for(auto &im: imports) ir << im << " ";
  ir << "\n";
  ir << "; JOCKY_DEMO_MARKER\n";
  if(poly){
    ir << "; -- polymorphic transforms applied -- LAB / SIMULATED --\n";
    ir << "; cfg-flatten:states=" << labStates << " dispatch=" << labDisp << " order=";
    for(size_t i=0;i<labOrder.size();i++){ if(i) ir<<","; ir<<labOrder[i]; } ir<<"\n";
    ir << "; string-encrypt:xor(key=" << labXorKey << ")\n";
    ir << "; import-obfuscate:shuffled seed=" << seed << "\n";
    ir << "; @LAB transform=import_shuffle seed=" << seed << " order="; for(auto &im: imports) ir<<im<<" "; ir<<"\n";
    ir << "; @LAB transform=string_encrypt key=" << labXorKey << " reversible=seed\n";
    ir << "; @LAB transform=cfg_flatten dispatcher=" << labDisp << " states=" << labStates << "\n";
    ir << "; LAB reversible: seed=" << seed << " -> xor_key=" << labXorKey << "\n";
  }
  ir << "define i32 @main() {\n";
  ir << "entry:\n";
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
  if(poly){
    ir << "  ; -- LAB CFG flatten dispatcher state=" << labDisp << " -- LAB / SIMULATED\n";
    ir << "  %state = alloca i32\n";
    ir << "  store i32 " << labDisp << ", i32* %state\n";
    ir << "  br label %dispatch\n";
    ir << "dispatch:\n";
    ir << "  %cur = load i32, i32* %state\n";
    ir << "  switch i32 %cur, label %bb.poly." << labOrder[0] << " [\n";
    for(int s: labOrder) ir << "    i32 " << s << ", label %bb.poly." << s << "\n";
    ir << "  ]\n";
    for(int s: labOrder){
      ir << "bb.poly." << s << ":\n";
      std::mt19937 r2(seed ^ (0x1000 + s));
      ir << "  %" << callId++ << " = add i32 " << (r2()%100) << ", " << (r2()%100) << " ; state=" << s << " LAB\n";
      // next state
      size_t idx=0; for(size_t k=0;k<labOrder.size();k++) if(labOrder[k]==s) idx=k;
      int nxt = labOrder[(idx+1)%labOrder.size()];
      ir << "  br label %bb.poly." << nxt << " ; next state\n";
    }
    ir << "bb.poly.exit:\n";
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
  IRResult r = generateIRWithValidation(src, seed, opts.polymorphic);
  if(r.code != 0){
    if(out_ir) *out_ir = r.error;
    std::cerr << "IR validation failed: " << r.error << "\n";
    return r.code;
  }
  if(out_ir) *out_ir = r.ir;
  if(!opts.output.empty()){
    std::filesystem::create_directories(std::filesystem::path(opts.output).parent_path());
    std::ofstream o(opts.output); o << r.ir;
    std::ofstream t(opts.output + ".tokens"); t << "; tokens seed=" << seed << " poly=" << opts.polymorphic << " ops=" << r.ops.size() << " caps=" << r.capabilities.size() << "\n" << src.size() << " bytes\n";
    std::ofstream a(opts.output + ".ast"); a << "; AST for " << sourcePath << " seed=" << seed << " ir_version=1\n";
  }
  return 0;
}
}
