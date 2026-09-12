#pragma once
#include <string>
#include <vector>
#include <unordered_set>

namespace jocky {
enum class TokKind { ID, DOT, LPAREN, RPAREN, LBRACE, RBRACE, SEMI, COMMA, STRING, NUMBER, OP, KW, END };
struct Token { TokKind kind; std::string text; int line; int col; };
std::vector<Token> lex(const std::string& src);
}
