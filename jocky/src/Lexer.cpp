#include <cctype>
#include <string>
#include <vector>
#include <unordered_set>

namespace jocky {
enum class TokKind { ID, DOT, LPAREN, RPAREN, LBRACE, RBRACE, SEMI, COMMA, STRING, NUMBER, OP, KW, END };
struct Token { TokKind kind; std::string text; int line; };
static std::unordered_set<std::string> kws = {"let","if","else","for","while","func","return","import","true","false","null","investigation"};

std::vector<Token> lex(const std::string& src) {
  std::vector<Token> out; int line=1; size_t i=0; auto add=[&](TokKind k,std::string t){ out.push_back({k,t,line});};
  while(i<src.size()){
    char c=src[i];
    if(c=='\n'){ line++; i++; continue; }
    if(isspace((unsigned char)c)){ i++; continue; }
    if(c=='/' && i+1<src.size() && src[i+1]=='/'){ while(i<src.size()&&src[i]!='\n') i++; continue; }
    if(c=='/' && i+1<src.size() && src[i+1]=='*'){ i+=2; while(i+1<src.size() && !(src[i]=='*'&&src[i+1]=='/')){ if(src[i]=='\n')line++; i++;} i+=2; continue; }
    if(c=='.' ) { add(TokKind::DOT,"."); i++; continue; }
    if(c=='(') { add(TokKind::LPAREN,"("); i++; continue; }
    if(c==')') { add(TokKind::RPAREN,")"); i++; continue; }
    if(c=='{') { add(TokKind::LBRACE,"{"); i++; continue; }
    if(c=='}') { add(TokKind::RBRACE,"}"); i++; continue; }
    if(c==';') { add(TokKind::SEMI,";"); i++; continue; }
    if(c==',') { add(TokKind::COMMA,","); i++; continue; }
    if(c=='"'||c=='\''){ char q=c; size_t j=i+1; std::string s; s+=q; while(j<src.size()&&src[j]!=q){ if(src[j]=='\\'&&j+1<src.size()){ s+=src[j]; s+=src[j+1]; j+=2; } else s+=src[j++]; } if(j<src.size()) s+=q, j++; add(TokKind::STRING,s); i=j; continue; }
    if(isalpha((unsigned char)c)||c=='_'){ size_t j=i; while(j<src.size()&&(isalnum((unsigned char)src[j])||src[j]=='_')) j++; std::string w=src.substr(i,j-i); add(kws.count(w)?TokKind::KW:TokKind::ID,w); i=j; continue; }
    if(isdigit((unsigned char)c)){ size_t j=i; while(j<src.size()&&(isdigit((unsigned char)src[j])||src[j]=='.')) j++; add(TokKind::NUMBER,src.substr(i,j-i)); i=j; continue; }
    // operators
    std::string op; op+=c;
    if(i+1<src.size()){
      std::string two=op+src[i+1];
      if(two=="=="||two=="!="||two=="<="||two==">="||two=="&&"||two=="||"||two=="=>"){ add(TokKind::OP,two); i+=2; continue; }
    }
    add(TokKind::OP,op); i++; continue;
  }
  add(TokKind::END,"<EOF>");
  return out;
}
}
