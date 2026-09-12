#pragma once
#include "jocky/Lexer.h"
#include <string>
#include <vector>

namespace jocky {
struct MemberCall { std::string ns; std::string method; int line; int col; };
struct ParseResult { std::vector<MemberCall> calls; std::vector<std::string> errors; };

ParseResult parseMemberCalls(const std::vector<Token>& toks);
std::pair<std::vector<std::string>, std::vector<std::string>> parseInvestigations(const std::vector<Token>& toks);
std::pair<std::vector<std::string>, std::vector<std::string>> parseImports(const std::vector<Token>& toks);
std::pair<std::vector<std::string>, std::vector<std::string>> parseFunctions(const std::vector<Token>& toks);
}
