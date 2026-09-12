#include "jocky/Lexer.h"
#include <cctype>
#include <string>
#include <vector>
#include <unordered_set>

namespace jocky {
static std::unordered_set<std::string> kws = {"let","if","else","for","while","func","function","return","import","true","false","null","investigation"};

std::vector<Token> lex(const std::string& src) {
  std::vector<Token> out; int line=1; int col=1; size_t i=0;
  auto add=[&](TokKind k,std::string t,int l,int c){ out.push_back({k,t,l,c}); };
  while(i<src.size()){
    char c=src[i];
    if(c=='\n'){ line++; col=1; i++; continue; }
    if(c==' '||c=='\t'||c=='\r'){ col++; i++; continue; }
    if(c=='/' && i+1<src.size() && src[i+1]=='/'){ while(i<src.size()&&src[i]!='\n') i++; continue; }
    if(c=='/' && i+1<src.size() && src[i+1]=='*'){ i+=2; col+=2; while(i+1<src.size() && !(src[i]=='*'&&src[i+1]=='/')){ if(src[i]=='\n'){line++; col=1;} else col++; i++;} i+=2; col+=2; continue; }
    if(c=='.'){ add(TokKind::DOT,".",line,col); i++; col++; continue; }
    if(c=='('){ add(TokKind::LPAREN,"(",line,col); i++; col++; continue; }
    if(c==')'){ add(TokKind::RPAREN,")",line,col); i++; col++; continue; }
    if(c=='{'){ add(TokKind::LBRACE,"{",line,col); i++; col++; continue; }
    if(c=='}'){ add(TokKind::RBRACE,"}",line,col); i++; col++; continue; }
    if(c==';'){ add(TokKind::SEMI,";",line,col); i++; col++; continue; }
    if(c==','){ add(TokKind::COMMA,",",line,col); i++; col++; continue; }
    if(c=='['){ add(TokKind::LBRACE,"[",line,col); i++; col++; continue; } // treat as LBRACK
    if(c==']'){ add(TokKind::RBRACE,"]",line,col); i++; col++; continue; }
    if(c=='"'||c=='\''){
      char q=c; size_t j=i+1; std::string s; s+=q; int start_col=col;
      while(j<src.size()&&src[j]!=q){
        if(src[j]=='\\'&&j+1<src.size()){ s+=src[j]; s+=src[j+1]; j+=2; continue; }
        if(src[j]=='\n') break;
        s+=src[j++];
      }
      if(j<src.size()&&src[j]==q){ s+=q; j++; }
      add(TokKind::STRING,s,line,start_col);
      int consumed=(int)(j-i);
      col+=consumed; i=j; continue;
    }
    if(isalpha((unsigned char)c)||c=='_'){
      size_t j=i; while(j<src.size()&&(isalnum((unsigned char)src[j])||src[j]=='_')) j++;
      std::string w=src.substr(i,j-i);
      add(kws.count(w)?TokKind::KW:TokKind::ID,w,line,col);
      col+=(int)(j-i); i=j; continue;
    }
    if(isdigit((unsigned char)c)){
      size_t j=i; while(j<src.size()&&isdigit((unsigned char)src[j])) j++;
      if(j<src.size()&&src[j]=='.'&&j+1<src.size()&&isdigit((unsigned char)src[j+1])){
        j++; while(j<src.size()&&isdigit((unsigned char)src[j])) j++;
      }
      add(TokKind::NUMBER,src.substr(i,j-i),line,col);
      col+=(int)(j-i); i=j; continue;
    }
    std::string two; if(i+1<src.size()) two=std::string()+c+src[i+1];
    if(two=="=="||two=="!="||two=="<="||two==">="||two=="&&"||two=="||"||two=="=>"){ add(TokKind::OP,two,line,col); i+=2; col+=2; continue; }
    if(std::string("+-*/!<>=").find(c)!=std::string::npos){ add(TokKind::OP,std::string(1,c),line,col); i++; col++; continue; }
    add(TokKind::OP,std::string(1,c),line,col); i++; col++; continue;
  }
  add(TokKind::END,"<EOF>",line,col);
  return out;
}
}
