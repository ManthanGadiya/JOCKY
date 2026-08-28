// LLVM Pass stub: CFG Flatten - Point 2 polymorphism
// Real pass would be loadable via opt; here we document intent
// For textual IR fallback, the flattening is done in IRGen.cpp (bb.poly.* blocks)
#include <string>
namespace jocky { namespace transform {
std::string cfgFlatten(const std::string& ir, uint32_t seed){ return ir + "; cfgFlatten seed=" + std::to_string(seed) + "\n"; }
}}
