#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace jocky {
struct IRGenOptions {
  bool polymorphic = false;
  uint32_t seed = 0;
  std::string output;
};

struct IRResult {
  int code = 0; // 0 success, non-zero error
  std::string ir;
  std::string error;
  std::string source_hash;
  std::vector<std::string> capabilities;
  std::vector<std::string> ops;
  int ir_version = 1;
};

// Generate LLVM IR text (and tokens/AST dumps) from .jocky source
// Returns 0 on success. Produces .ll, .tokens, .ast alongside output
int generateIR(const std::string& sourcePath, const IRGenOptions& opts,
               std::string* out_ir = nullptr);
std::string generateIRText(const std::string& jockySource, uint32_t seed, bool poly);
IRResult generateIRWithValidation(const std::string& jockySource, uint32_t seed, bool poly);
}
