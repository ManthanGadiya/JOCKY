#include "jocky/Parser.h"
#include <string>
#include <vector>
#include <unordered_set>
#include <regex>

namespace jocky {

// Whitelist per LANGUAGE_SPEC §10 + SECURITY_MODEL §16 (shared with IRGen)
static const std::unordered_set<std::string> OP_WHITELIST = {
  "system.info","process.list","process.tree","process.modules","file.list","file.hash","file.analyze","file.metadata",
  "network.connections","network.interfaces","memory.analyze","driver.list","driver.scan","driver.risk","report.generate","evidence.load"
};

static const std::unordered_set<std::string> ALLOWED_IMPORTS = {
  "forensic.process","forensic.network","forensic.net","forensic.file","forensic.system","forensic.driver","forensic.memory","forensic.evidence"
};

// Parse MemberCall: ID '.' ID '(' per g4 expr MemberCall, with line:col and unmatched '(' detection
ParseResult parseMemberCalls(const std::vector<Token>& toks){
  ParseResult res;
  size_t i=0;
  while(i<toks.size()){
    auto t=toks[i];
    if(t.kind==TokKind::END) break;
    if((t.kind==TokKind::ID||t.kind==TokKind::KW) && i+3<toks.size()){
      auto t2=toks[i+1], t3=toks[i+2], t4=toks[i+3];
      if(t2.kind==TokKind::DOT && (t3.kind==TokKind::ID||t3.kind==TokKind::KW) && t4.kind==TokKind::LPAREN){
        res.calls.push_back({t.text, t3.text, t.line, t.col});
        int depth=0; size_t j=i+3; bool found=false;
        while(j<toks.size()){
          if(toks[j].kind==TokKind::LPAREN) depth++;
          else if(toks[j].kind==TokKind::RPAREN){ depth--; if(depth==0){ found=true; break; } }
          j++;
        }
        if(!found) res.errors.push_back("Syntax error: unmatched '(' for " + t.text + "." + t3.text + " at " + std::to_string(t.line)+":"+std::to_string(t.col));
        i = found? j+1 : i+4;
        continue;
      }
    }
    i++;
  }
  for(auto &t: toks){
    if(t.kind==TokKind::STRING && !t.text.empty() && (t.text[0]=='"' || t.text[0]=='\'') && t.text.back()!=t.text[0]){
      res.errors.push_back("Syntax error: unterminated string " + t.text.substr(0,20) + " at " + std::to_string(t.line)+":"+std::to_string(t.col));
    }
  }
  return res;
}

// Investigation blocks: 'investigation' STRING block with balanced braces (LANGUAGE_SPEC §11)
std::pair<std::vector<std::string>, std::vector<std::string>> parseInvestigations(const std::vector<Token>& toks){
  std::vector<std::string> titles; std::vector<std::string> errs;
  size_t i=0;
  while(i<toks.size()){
    auto t=toks[i];
    if(t.kind==TokKind::KW && t.text=="investigation"){
      if(i+1>=toks.size() || toks[i+1].kind!=TokKind::STRING){
        errs.push_back("Syntax error: investigation requires string title at "+std::to_string(t.line)+":"+std::to_string(t.col));
        i++; continue;
      }
      std::string raw=toks[i+1].text;
      std::string title = (raw.size()>=2 && (raw[0]=='"'||raw[0]=='\'') && raw.back()==raw[0]) ? raw.substr(1,raw.size()-2) : raw;
      if(title.find_first_not_of(" \t\r\n")==std::string::npos) errs.push_back("Investigation title cannot be empty at "+std::to_string(toks[i+1].line)+":"+std::to_string(toks[i+1].col));
      if(i+2>=toks.size() || toks[i+2].kind!=TokKind::LBRACE){
        errs.push_back("Syntax error: investigation \""+title+"\" missing '{' at "+std::to_string(toks[i+1].line)+":"+std::to_string(toks[i+1].col));
        i+=2; continue;
      }
      int depth=0; size_t j=i+2; bool found=false;
      while(j<toks.size()){
        if(toks[j].kind==TokKind::LBRACE) depth++;
        else if(toks[j].kind==TokKind::RBRACE){ depth--; if(depth==0){ found=true; break; } }
        else if(toks[j].kind==TokKind::END) break;
        j++;
      }
      if(!found) errs.push_back("Syntax error: unterminated investigation block \""+title+"\" at "+std::to_string(t.line)+":"+std::to_string(t.col));
      else titles.push_back(title);
      i = found? j+1 : j;
      continue;
    }
    i++;
  }
  return {titles, errs};
}

// Imports: 'import' (STRING | forensic.path) ';' (LANGUAGE_SPEC §18)
std::pair<std::vector<std::string>, std::vector<std::string>> parseImports(const std::vector<Token>& toks){
  std::vector<std::string> mods; std::vector<std::string> errs;
  size_t i=0;
  while(i<toks.size()){
    auto t=toks[i];
    if(t.kind==TokKind::KW && t.text=="import"){
      if(i+1>=toks.size()){ errs.push_back("Syntax error: import requires module at "+std::to_string(t.line)+":"+std::to_string(t.col)); i++; continue; }
      auto nxt=toks[i+1];
      std::string module; bool isString=false;
      size_t consumed=1;
      if(nxt.kind==TokKind::STRING){
        std::string raw=nxt.text;
        module = (raw.size()>=2 && (raw[0]=='"'||raw[0]=='\'')) ? raw.substr(1,raw.size()-2) : raw;
        isString=true;
        if(i+2>=toks.size() || toks[i+2].kind!=TokKind::SEMI) errs.push_back("Syntax error: import \""+module+"\" missing ';' at "+std::to_string(nxt.line)+":"+std::to_string(nxt.col));
        else consumed=3;
      } else if(nxt.kind==TokKind::ID){
        module=nxt.text; size_t j=i+2;
        while(j+1<toks.size() && toks[j].kind==TokKind::DOT && toks[j+1].kind==TokKind::ID){ module+="."+toks[j+1].text; j+=2; }
        if(j>=toks.size() || toks[j].kind!=TokKind::SEMI) errs.push_back("Syntax error: import "+module+" missing ';' at "+std::to_string(t.line)+":"+std::to_string(t.col));
        else consumed=(j - i)+1;
      } else {
        errs.push_back("Syntax error: import requires STRING or dotted path at "+std::to_string(t.line)+":"+std::to_string(t.col));
        i++; continue;
      }
      if(module.find("..")!=std::string::npos || module.find('\0')!=std::string::npos) errs.push_back("Import rejected: "+module+" contains .. at "+std::to_string(nxt.line)+":"+std::to_string(nxt.col));
      else if(ALLOWED_IMPORTS.find(module)==ALLOWED_IMPORTS.end() && module.rfind("forensic.",0)!=0 && module.find(".jocky")==std::string::npos && module.find('/')==std::string::npos){
        errs.push_back("Unknown import module: '"+module+"' at "+std::to_string(nxt.line)+":"+std::to_string(nxt.col));
      } else {
        // dedup
        bool exists=false; for(auto &m:mods) if(m==module) exists=true;
        if(!exists) mods.push_back(module);
      }
      i+=consumed; continue;
    }
    i++;
  }
  return {mods, errs};
}

// Functions: ('func'|'function') ID '(' ... ')' block (LANGUAGE_SPEC §19)
std::pair<std::vector<std::string>, std::vector<std::string>> parseFunctions(const std::vector<Token>& toks){
  std::vector<std::string> names; std::vector<std::string> errs;
  size_t i=0;
  while(i<toks.size()){
    auto t=toks[i];
    if(t.kind==TokKind::KW && (t.text=="func"||t.text=="function")){
      if(i+1>=toks.size() || (toks[i+1].kind!=TokKind::ID && toks[i+1].kind!=TokKind::KW)){ errs.push_back("Syntax error: "+t.text+" requires name at "+std::to_string(t.line)+":"+std::to_string(t.col)); i++; continue; }
      std::string name=toks[i+1].text;
      if(i+2>=toks.size() || toks[i+2].kind!=TokKind::LPAREN){ errs.push_back("Syntax error: func "+name+" missing '(' at "+std::to_string(toks[i+1].line)+":"+std::to_string(toks[i+1].col)); i+=2; continue; }
      int depth=0; size_t j=i+2; bool found=false;
      while(j<toks.size()){
        if(toks[j].kind==TokKind::LPAREN) depth++;
        else if(toks[j].kind==TokKind::RPAREN){ depth--; if(depth==0){ found=true; break; }}
        else if(toks[j].kind==TokKind::END) break;
        j++;
      }
      if(!found){ errs.push_back("Syntax error: func "+name+" unmatched '(' at "+std::to_string(t.line)+":"+std::to_string(t.col)); i=j; continue; }
      if(j+1>=toks.size() || toks[j+1].kind!=TokKind::LBRACE){ errs.push_back("Syntax error: func "+name+" missing '{' at "+std::to_string(t.line)+":"+std::to_string(t.col)); i=j+1; continue; }
      int d2=0; size_t k=j+1; bool found2=false;
      while(k<toks.size()){
        if(toks[k].kind==TokKind::LBRACE) d2++;
        else if(toks[k].kind==TokKind::RBRACE){ d2--; if(d2==0){ found2=true; break; }}
        else if(toks[k].kind==TokKind::END) break;
        k++;
      }
      if(!found2){ errs.push_back("Syntax error: unterminated func "+name+" block at "+std::to_string(t.line)+":"+std::to_string(t.col)); i=k; continue; }
      names.push_back(name); i=k+1; continue;
    }
    i++;
  }
  return {names, errs};
}

} // namespace jocky
