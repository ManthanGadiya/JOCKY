#include "jocky/IRGen.h"
#include <iostream>
#include <string>
#include <filesystem>

void printHelp(const char* prog){
  std::cout << "jockyc - JOCKY Compiler (Point 1: Independent Language, Point 2: Polymorphism)\n";
  std::cout << "Usage: " << prog << " <input.jocky> -o <output.ll> [--polymorphic] [--seed N]\n";
  std::cout << "  --polymorphic  apply CFG flatten + string encrypt + import shuffle (unique hash)\n";
  std::cout << "  --seed N       deterministic seed (for reproducible builds)\n";
  std::cout << "  --help         show this help\n";
  std::cout << "Examples:\n";
  std::cout << "  jockyc examples/test.jocky -o build/a.ll\n";
  std::cout << "  jockyc examples/test.jocky --polymorphic -o build/b.ll\n";
  std::cout << "  jockyc examples/test.jocky --polymorphic --seed 42 -o build/c.ll\n";
}

int main(int argc, char** argv){
  if(argc<2){ printHelp(argv[0]); return 1; }
  std::string input, output="a.ll";
  bool poly=false; uint32_t seed=0;
  for(int i=1;i<argc;i++){
    std::string a=argv[i];
    if(a=="--help"||a=="-h"){ printHelp(argv[0]); return 0; }
    else if(a=="-o" && i+1<argc) output=argv[++i];
    else if(a=="--polymorphic") poly=true;
    else if(a=="--seed" && i+1<argc) seed= (uint32_t)std::stoul(argv[++i]);
    else if(a.rfind("-",0)!=0 && input.empty()) input=a;
    else if(a.rfind("-",0)==0){ std::cerr << "Unknown flag: "<<a<<"\n"; return 1; }
  }
  if(input.empty()){ std::cerr << "No input .jocky file\n"; return 1; }
  if(!std::filesystem::exists(input)){ std::cerr << "Input not found: "<<input<<"\n"; return 1; }
  jocky::IRGenOptions opts; opts.polymorphic=poly; opts.seed=seed; opts.output=output;
  std::string ir;
  int rc = jocky::generateIR(input, opts, &ir);
  if(rc!=0){ std::cerr << "IR generation failed: " << ir << "\n"; return rc; }
  std::cout << ir;
  auto jsrc = [&]{ std::ifstream f(input); return std::string((std::istreambuf_iterator<char>(f)),{}); }();
  auto res = jocky::generateIRWithValidation(jsrc, seed?seed:0x1234, poly);
  std::cerr << "\n[ jockyc: wrote " << output << " (" << ir.size() << " bytes) poly=" << poly << " seed=" << (seed?std::to_string(seed):"random") << " ir_version=" << res.ir_version << " caps=";
  for(auto &c: res.capabilities) std::cerr << c << " ";
  std::cerr << "]\n";
  return 0;
}
