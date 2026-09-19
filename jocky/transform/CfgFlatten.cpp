// Lab-only: textual IR state-machine dispatcher, deterministic per seed.
// See docs/PHASE2_DESIGN.md §4. Not a general obfuscator — only JOCKY IR.
#include <string>
#include <vector>
#include <random>
#include <algorithm>
namespace jocky { namespace transform {
std::string cfgFlatten(const std::string& ir, uint32_t seed){
  // Deterministic: same seed -> same dispatcher order (states 3-6, order shuffled)
  std::mt19937 r(seed ^ 0xA11CE); int states=r()%4+3; int disp=r()%8+2;
  std::vector<int> order; for(int i=0;i<states;i++) order.push_back(i);
  std::mt19937 r2(seed ^ 0xC0FFEE); std::shuffle(order.begin(), order.end(), r2);
  return ir + "; cfgFlatten LAB states=" + std::to_string(states) + " disp=" + std::to_string(disp) + " seed=" + std::to_string(seed) + "\n";
}
}}
