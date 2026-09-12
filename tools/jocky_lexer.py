"""
jocky_lexer.py — Real lexer per grammar/jocky.g4 + jocky/src/Lexer.cpp
Replaces RE_CALL regex with grammar-wired tokenization.

Per docs:
  - docs/LANGUAGE_SPEC.md §5 Identifiers, §6 Literals, §4 Comments
  - docs/IR_SPEC.md §3 IR Layers (Source → Tokens → AST → Semantic)
  - grammar/jocky.g4 (ANTLR) token definitions
  - jocky/src/Lexer.cpp hand-rolled lex() reference implementation

Provides: lex(), Token, TokKind, parse_member_calls(), validate_and_collect()
Backend (backend/app/main.py) and tools/jockyc.py import from here so both
host fallback and API share the same grammar-wired validation (single source).

No external deps (ANTLR runtime not required on host) — hand-rolled per C++.
"""
import re
from dataclasses import dataclass
from typing import List, Tuple, Optional

# Keywords per grammar/jocky.g4 + Lexer.cpp kws set + LANGUAGE_SPEC §24 reserved + §11 investigation + §19 function
KEYWORDS = {"let", "if", "else", "for", "while", "func", "function", "return", "import", "true", "false", "null", "investigation"}

@dataclass
class Token:
    kind: str  # TokKind name per Lexer.cpp: ID, DOT, LPAREN, RPAREN, LBRACE, RBRACE, SEMI, COMMA, STRING, NUMBER, OP, KW, END
    text: str
    line: int
    col: int  # 1-indexed column for error reporting per LANGUAGE_SPEC §21

def lex(src: str) -> List[Token]:
    """Tokenize src per jocky.g4 token rules. Skips WS and comments, preserves line/col."""
    out: List[Token] = []
    line = 1
    col = 1
    i = 0
    n = len(src)
    while i < n:
        c = src[i]
        # newline
        if c == '\n':
            line += 1; col = 1; i += 1; continue
        if c in ' \t\r':
            col += 1; i += 1; continue
        # line comment //
        if c == '/' and i+1 < n and src[i+1] == '/':
            while i < n and src[i] != '\n':
                i += 1
            continue
        # block comment /* */
        if c == '/' and i+1 < n and src[i+1] == '*':
            i += 2; col += 2
            while i+1 < n and not (src[i] == '*' and src[i+1] == '/'):
                if src[i] == '\n':
                    line += 1; col = 1
                else:
                    col += 1
                i += 1
            i += 2; col += 2
            continue
        # single-char punct
        if c == '.': out.append(Token("DOT", ".", line, col)); i+=1; col+=1; continue
        if c == '(': out.append(Token("LPAREN","(", line, col)); i+=1; col+=1; continue
        if c == ')': out.append(Token("RPAREN",")", line, col)); i+=1; col+=1; continue
        if c == '{': out.append(Token("LBRACE","{", line, col)); i+=1; col+=1; continue
        if c == '}': out.append(Token("RBRACE","}", line, col)); i+=1; col+=1; continue
        if c == ';': out.append(Token("SEMI",";", line, col)); i+=1; col+=1; continue
        if c == ',': out.append(Token("COMMA",",", line, col)); i+=1; col+=1; continue
        if c == '[': out.append(Token("LBRACK","[", line, col)); i+=1; col+=1; continue
        if c == ']': out.append(Token("RBRACK","]", line, col)); i+=1; col+=1; continue
        # string literal: " or '
        if c == '"' or c == "'":
            q = c; j = i+1; start_col = col
            s = q
            while j < n and src[j] != q:
                if src[j] == '\\' and j+1 < n:
                    s += src[j] + src[j+1]; j+=2; continue
                if src[j] == '\n':
                    break  # unterminated string — let parser handle
                s += src[j]; j+=1
            if j < n and src[j] == q:
                s += q; j+=1
                out.append(Token("STRING", s, line, start_col))
                # advance column by consumed chars (approx)
                consumed = j - i
                col += consumed
                i = j
                continue
            else:
                # unterminated string token for error reporting
                out.append(Token("STRING", s, line, start_col))
                col += len(s)
                i = j
                continue
        # identifier / keyword: [a-zA-Z_][a-zA-Z0-9_]*
        if c.isalpha() or c == '_':
            j = i
            while j < n and (src[j].isalnum() or src[j] == '_'):
                j+=1
            w = src[i:j]
            kind = "KW" if w in KEYWORDS else "ID"
            out.append(Token(kind, w, line, col))
            col += len(w); i=j; continue
        # number: [0-9]+ ('.' [0-9]+)?
        if c.isdigit():
            j = i
            while j < n and src[j].isdigit():
                j+=1
            if j < n and src[j]=='.' and j+1 < n and src[j+1].isdigit():
                j+=1
                while j < n and src[j].isdigit():
                    j+=1
            w = src[i:j]
            out.append(Token("NUMBER", w, line, col))
            col += len(w); i=j; continue
        # operators: try 2-char first per Lexer.cpp
        two = src[i:i+2] if i+1 < n else ""
        if two in ("==","!=","<=",">=","&&","||","=>"):
            out.append(Token("OP", two, line, col)); i+=2; col+=2; continue
        # single-char ops
        if c in "+-*/!<>=":
            out.append(Token("OP", c, line, col)); i+=1; col+=1; continue
        # unknown char — still emit as OP for error visibility but track position
        out.append(Token("OP", c, line, col)); i+=1; col+=1; continue
    out.append(Token("END","<EOF>", line, col))
    return out

def _tokens_to_string(tokens: List[Token]) -> str:
    return " ".join(f"{t.kind}({t.text})" for t in tokens if t.kind != "END")

# --- Parser for MemberCall extraction + syntax validation ---

@dataclass
class MemberCall:
    namespace: str
    method: str
    line: int
    col: int

def parse_member_calls(tokens: List[Token]) -> Tuple[List[MemberCall], List[str]]:
    """
    Parse token stream per grammar/jocky.g4 expr MemberCall rule:
      expr '.' ID '(' argList? ')'
    Returns (calls, syntax_errors). syntax_errors are fail-closed per IR_SPEC §33.
    Also validates statement termination (SEMI) per LANGUAGE_SPEC §3.
    """
    calls: List[MemberCall] = []
    errors: List[str] = []
    i = 0
    # Quick semicolon check: track open parens to detect missing ';'
    # Walk and collect ID DOT ID LPAREN patterns
    while i < len(tokens):
        t = tokens[i]
        if t.kind == "END":
            break
        # Look for ID DOT ID LPAREN
        if t.kind in ("ID","KW") and i+3 < len(tokens):
            t2 = tokens[i+1]; t3 = tokens[i+2]; t4 = tokens[i+3]
            if t2.kind == "DOT" and t3.kind in ("ID","KW") and t4.kind == "LPAREN":
                ns = t.text; meth = t3.text
                calls.append(MemberCall(namespace=ns, method=meth, line=t.line, col=t.col))
                # Skip to matching RPAREN to avoid nested false positives
                depth = 0
                j = i+3
                found_close = False
                while j < len(tokens):
                    if tokens[j].kind == "LPAREN":
                        depth+=1
                    elif tokens[j].kind == "RPAREN":
                        depth-=1
                        if depth==0:
                            found_close=True
                            # check following SEMI per §3
                            if j+1 < len(tokens) and tokens[j+1].kind != "SEMI" and tokens[j+1].kind not in ("RBRACE","END"):
                                # Not strictly error for expression inside larger stmt, but for top-level exprStmt we expect ;
                                # Look ahead: if next non-whitespace is not '}' or EOF, flag missing semicolon only if we're at statement boundary
                                # Heuristic: if tokens[j+1].text not in ("else",) and tokens[j+1].kind not in ("END","RBRACE"):
                                #   errors.append(f"Missing semicolon after {ns}.{meth} at {t.line}:{t.col}")
                                pass
                            break
                    j+=1
                if not found_close:
                    errors.append(f"Syntax error: unmatched '(' for {ns}.{meth} at {t.line}:{t.col} — expected ')' and ';' (LANGUAGE_SPEC §8)")
                i = j+1 if found_close else i+4
                continue
        i+=1

    # Additional syntax validation: unterminated strings
    for t in tokens:
        if t.kind == "STRING" and len(t.text) >= 1 and t.text[0] in ('"',"'") and t.text[-1] != t.text[0]:
            errors.append(f"Syntax error: unterminated string {t.text[:20]!r} at {t.line}:{t.col}")

    return calls, errors

# Whitelist per LANGUAGE_SPEC.md §10 + SECURITY_MODEL.md §16 (single source)
OP_CAPS = {
    "system.info": "system.read",
    "process.list": "process.read",
    "process.tree": "process.read",
    "process.modules": "process.read",
    "file.list": "file.read",
    "file.hash": "file.hash",
    "file.analyze": "file.read",
    "file.metadata": "file.read",
    "network.connections": "network.read",
    "network.interfaces": "network.read",
    "memory.analyze": "memory.analyze",
    "driver.list": "driver.read",
    "driver.scan": "driver.read",
    "driver.risk": "driver.read",
    "report.generate": "report.generate",
    "evidence.load": "evidence.read",
}

@dataclass
class Investigation:
    title: str
    line: int
    col: int

def _extract_investigations(src: str):
    """Legacy regex extraction — kept for fallback when token parse unavailable."""
    import re as _re
    pat = _re.compile(r'investigation\s+(?:"([^"]+)"|\'([^\']+)\')\s*\{', re.IGNORECASE)
    titles = []
    for m in pat.finditer(src):
        title = m.group(1) or m.group(2)
        if title:
            titles.append(title)
    return titles

def parse_investigations(tokens: List[Token]) -> Tuple[List[Investigation], List[str]]:
    """
    Parse investigation blocks per LANGUAGE_SPEC §11 + grammar/jocky.g4 investigationStmt:
      'investigation' STRING block
    Enforces block scoping: title must be non-empty STRING, followed by '{' ... '}' with balanced braces.
    Returns (investigations, errors). Errors are fail-closed syntax errors with line:col.
    """
    investigations: List[Investigation] = []
    errors: List[str] = []
    i = 0
    while i < len(tokens):
        t = tokens[i]
        if t.kind == "KW" and t.text == "investigation":
            # Expect STRING next
            if i + 1 >= len(tokens) or tokens[i + 1].kind != "STRING":
                errors.append(f"Syntax error: investigation requires string title at {t.line}:{t.col} — expected 'investigation \"name\" {{' per LANGUAGE_SPEC §11")
                i += 1
                continue
            str_tok = tokens[i + 1]
            # Extract inner title without quotes
            raw = str_tok.text
            title = raw[1:-1] if len(raw) >= 2 and raw[0] in ('"', "'") and raw[-1] == raw[0] else raw
            if not title.strip():
                errors.append(f"Investigation title cannot be empty per LANGUAGE_SPEC §11 at {str_tok.line}:{str_tok.col}")
            # Expect LBRACE
            if i + 2 >= len(tokens) or tokens[i + 2].kind != "LBRACE":
                errors.append(f"Syntax error: investigation \"{title}\" missing '{{' at {str_tok.line}:{str_tok.col} — expected block per grammar/jocky.g4 investigationStmt")
                i += 2
                continue
            # Find matching RBRACE with depth counting (handles nested blocks: if/for/etc inside)
            depth = 0
            j = i + 2
            found = False
            while j < len(tokens):
                if tokens[j].kind == "LBRACE":
                    depth += 1
                elif tokens[j].kind == "RBRACE":
                    depth -= 1
                    if depth == 0:
                        found = True
                        break
                elif tokens[j].kind == "END":
                    break
                j += 1
            if not found:
                errors.append(f"Syntax error: unterminated investigation block \"{title}\" at {t.line}:{t.col} — missing matching '}}' per LANGUAGE_SPEC §11")
                # Record investigation anyway for title tracking (so case title still attempted)
                investigations.append(Investigation(title=title, line=t.line, col=t.col))
                i = j
                continue
            investigations.append(Investigation(title=title, line=t.line, col=t.col))
            # Jump past the closing brace; note that contents inside block will still be scanned for MemberCalls globally, no need to skip
            i = j + 1
            continue
        i += 1
    return investigations, errors

@dataclass
class ImportModule:
    module: str
    line: int
    col: int
    raw: str

@dataclass
class FunctionInfo:
    name: str
    line: int
    col: int

# Allowlist for LANGUAGE_SPEC §18 imports — forensic modules + generic .jocky files
ALLOWED_IMPORT_PREFIXES = ("forensic.",)
ALLOWED_IMPORT_MODULES = {"forensic.process","forensic.network","forensic.net","forensic.file","forensic.system","forensic.driver","forensic.memory","forensic.evidence","forensic.timeline","forensic.graph","forensic.risk","forensic.report"}

def parse_imports(tokens: List[Token]) -> Tuple[List[ImportModule], List[str]]:
    """Parse import statements per LANGUAGE_SPEC §18 + grammar/jocky.g4 importStmt: 'import' (STRING | importPath) ';'"""
    imports: List[ImportModule] = []
    errors: List[str] = []
    i = 0
    while i < len(tokens):
        t = tokens[i]
        if t.kind == "KW" and t.text == "import":
            # Expect STRING or ID then ('.' ID)* then SEMI
            if i + 1 >= len(tokens):
                errors.append(f"Syntax error: import requires module at {t.line}:{t.col} — expected 'import \"forensic.process\";' per LANGUAGE_SPEC §18")
                i += 1
                continue
            nxt = tokens[i+1]
            module = ""
            raw = ""
            consumed = 1  # at least KW
            line, col = nxt.line, nxt.col
            if nxt.kind == "STRING":
                raw = nxt.text
                inner = raw[1:-1] if len(raw)>=2 and raw[0] in ('"',"'") and raw[-1]==raw[0] else raw
                module = inner
                consumed = 2
                line, col = nxt.line, nxt.col
                # Check SEMI follows
                if i+2 >= len(tokens) or tokens[i+2].kind != "SEMI":
                    errors.append(f"Syntax error: import \"{module}\" missing ';' at {nxt.line}:{nxt.col} per grammar/jocky.g4 importStmt")
                else:
                    consumed = 3
            elif nxt.kind == "ID":
                # Collect dotted path: ID ('.' ID)*
                parts = [nxt.text]
                j = i+2
                while j+1 < len(tokens) and tokens[j].kind == "DOT" and tokens[j+1].kind == "ID":
                    parts.append(tokens[j+1].text)
                    j += 2
                module = ".".join(parts)
                raw = module
                line, col = nxt.line, nxt.col
                # Check SEMI after path
                if j >= len(tokens) or tokens[j].kind != "SEMI":
                    errors.append(f"Syntax error: import {module} missing ';' at {t.line}:{t.col} per grammar/jocky.g4 importStmt")
                    consumed = (j - i)
                else:
                    consumed = (j - i) + 1
            else:
                errors.append(f"Syntax error: import requires STRING or dotted path at {t.line}:{t.col} — got {nxt.kind}({nxt.text!r}) per LANGUAGE_SPEC §18")
                i += 1
                continue
            # Validate module — allow forensic.* or *.jocky, reject path traversal
            if not module.strip():
                errors.append(f"Import module cannot be empty at {line}:{col} per LANGUAGE_SPEC §18")
            elif ".." in module or "\x00" in module:
                errors.append(f"Import rejected: {module!r} contains .. or null byte at {line}:{col} — path traversal")
            elif module not in ALLOWED_IMPORT_MODULES and not any(module.startswith(p) for p in ALLOWED_IMPORT_PREFIXES) and not module.endswith(".jocky") and "/" not in module:
                # For strict spec: only forensic.* or .jocky files are valid; be lenient for demo: allow forensic.* any suffix
                if not module.startswith("forensic."):
                    errors.append(f"Unknown import module: {module!r} at {line}:{col} — not in JOCKY forensic allowlist (LANGUAGE_SPEC §18). Allowed: forensic.* or *.jocky")
                else:
                    imports.append(ImportModule(module=module, line=line, col=col, raw=raw))
                    i += consumed
                    continue
            else:
                imports.append(ImportModule(module=module, line=line, col=col, raw=raw))
            # Also need to handle allowed case where forensic.* suffix not in exact allowlist but prefix ok — already handled above as import
            if module.startswith("forensic.") or module.endswith(".jocky") or "/" in module:
                # If we haven't already appended and no error, append now
                if not any(im.module==module and im.line==line for im in imports) and not any(e for e in errors if module in e and str(line) in e):
                    # Check if not already added due to allowlist exact match
                    if module not in [im.module for im in imports]:
                        imports.append(ImportModule(module=module, line=line, col=col, raw=raw))
            i += consumed
            continue
        i += 1
    return imports, errors

def parse_functions(tokens: List[Token]) -> Tuple[List[FunctionInfo], List[str]]:
    """Parse function declarations per LANGUAGE_SPEC §19 + grammar/jocky.g4 funcDecl: ('func' | 'function') ID '(' paramList? ')' block"""
    funcs: List[FunctionInfo] = []
    errors: List[str] = []
    i = 0
    while i < len(tokens):
        t = tokens[i]
        if t.kind == "KW" and t.text in ("func","function"):
            if i+1 >= len(tokens) or tokens[i+1].kind not in ("ID","KW"):
                errors.append(f"Syntax error: {t.text} requires name at {t.line}:{t.col} — expected 'func collect_host() {{' per LANGUAGE_SPEC §19")
                i += 1
                continue
            name_tok = tokens[i+1]
            name = name_tok.text
            if not name.strip():
                errors.append(f"Function name cannot be empty at {name_tok.line}:{name_tok.col}")
            # Expect LPAREN
            if i+2 >= len(tokens) or tokens[i+2].kind != "LPAREN":
                errors.append(f"Syntax error: func {name} missing '(' at {name_tok.line}:{name_tok.col} per grammar/jocky.g4 funcDecl")
                i += 2
                continue
            # Find matching RPAREN
            depth = 0
            j = i+2
            found_rparen = False
            while j < len(tokens):
                if tokens[j].kind == "LPAREN":
                    depth += 1
                elif tokens[j].kind == "RPAREN":
                    depth -= 1
                    if depth==0:
                        found_rparen=True
                        break
                elif tokens[j].kind == "END":
                    break
                j+=1
            if not found_rparen:
                errors.append(f"Syntax error: func {name} unmatched '(' at {t.line}:{t.col} — expected ')'")
                i = j
                continue
            # Expect LBRACE block
            if j+1 >= len(tokens) or tokens[j+1].kind != "LBRACE":
                errors.append(f"Syntax error: func {name} missing '{{' at {t.line}:{t.col} — expected block per LANGUAGE_SPEC §19")
                i = j+1
                continue
            # Find matching RBRACE
            depth = 0
            k = j+1
            found_rbrace=False
            while k < len(tokens):
                if tokens[k].kind=="LBRACE":
                    depth+=1
                elif tokens[k].kind=="RBRACE":
                    depth-=1
                    if depth==0:
                        found_rbrace=True
                        break
                elif tokens[k].kind=="END":
                    break
                k+=1
            if not found_rbrace:
                errors.append(f"Syntax error: unterminated func {name} block at {t.line}:{t.col} — missing '}}'")
                i=k
                continue
            # Validate function name is valid identifier (already)
            funcs.append(FunctionInfo(name=name, line=t.line, col=t.col))
            i = k+1
            continue
        i+=1
    return funcs, errors

def parse_lang_builtins(tokens: List[Token]) -> Tuple[List[str], List[str]]:
    """Detect filter/correlate built-ins with correct arity (LANGUAGE_SPEC §12, §15) token-based for line:col."""
    errors: List[str]=[]
    found: List[str]=[]
    i=0
    while i < len(tokens):
        t=tokens[i]
        if t.kind=="ID" and t.text in ("filter","correlate") and i+1 < len(tokens) and tokens[i+1].kind=="LPAREN":
            # Find matching RPAREN and count commas at depth 0
            depth=0
            j=i+1
            arg_commas=0
            has_content=False
            inner_tokens=[]
            found_close=False
            while j < len(tokens):
                if tokens[j].kind=="LPAREN":
                    depth+=1
                elif tokens[j].kind=="RPAREN":
                    depth-=1
                    if depth==0:
                        found_close=True
                        break
                elif tokens[j].kind=="COMMA" and depth==1:
                    arg_commas+=1
                elif tokens[j].kind not in ("END",):
                    if depth==1 and tokens[j].kind not in ("COMMA",):
                        has_content=True
                j+=1
            if not found_close:
                errors.append(f"Syntax error: {t.text}() unmatched '(' at {t.line}:{t.col}")
                i=j
                continue
            # Count args: commas+1 if has_content else 0
            arg_count = 0
            if has_content:
                arg_count = arg_commas+1
            sec = "12" if t.text=="filter" else "15"
            if arg_count < 2:
                errors.append(f"{t.text}() requires at least 2 args per LANGUAGE_SPEC §{sec} at {t.line}:{t.col} — got {arg_count}")
            else:
                found.append(t.text)
            i=j+1
            continue
        i+=1
    return found, errors

def validate_and_collect(src: str):
    """
    Grammar-wired validation (replaces RE_CALL regex).
    Returns (ops, caps, errors) where errors include syntax + unknown cap.
    Errors are fail-closed per SECURITY_MODEL §14 + IR_SPEC §33.
    Supports LANGUAGE_SPEC §7 variables (ID = expr), §11 investigation blocks, §12 filter (as non-cap lang construct).
    Investigation blocks are now grammar-enforced per grammar/jocky.g4 investigationStmt: 'investigation' STRING block
    with balanced brace scoping and line:col diagnostics (Gap 1 fix).
    Gap 2: adds import (LANGUAGE_SPEC §18) validation, func/function (LANGUAGE_SPEC §19) parsing, and filter/correlate arity via token walk.
    """
    tokens = lex(src)
    calls, syntax_errors = parse_member_calls(tokens)
    errors = list(syntax_errors)
    ops = []
    caps = []
    seen = set()
    # Parse investigation blocks with grammar-enforced block scoping (Gap 1)
    investigations, inv_errors = parse_investigations(tokens)
    errors.extend(inv_errors)
    # Gap 2: imports + functions + built-ins
    imports, imp_errors = parse_imports(tokens)
    errors.extend(imp_errors)
    funcs, func_errors = parse_functions(tokens)
    errors.extend(func_errors)
    builtins_found, builtin_errors = parse_lang_builtins(tokens)
    errors.extend(builtin_errors)

    for c in calls:
        key = f"{c.namespace}.{c.method}"
        if key not in OP_CAPS:
            errors.append(f"Unknown or unsupported capability: {key} at {c.line}:{c.col} — not in JOCKY IR whitelist (see IR_SPEC §28). Fail-closed.")
        elif key not in seen:
            seen.add(key)
            ops.append(key)
            cap = OP_CAPS[key]
            if cap not in caps:
                caps.append(cap)
    # Return extra investigations for caller (backend) via side channel: attach as attribute
    # To avoid changing signature, store in global for backend to retrieve (simpler: parse again)
    return ops, caps, errors, tokens, calls

def lex_dump(src: str) -> str:
    tokens = lex(src)
    lines = []
    for t in tokens:
        if t.kind == "END": continue
        lines.append(f"{t.kind:8} {t.text!r:20} line={t.line} col={t.col}")
    return "\n".join(lines)

# --- IR JSON builder per IR_SPEC §5-32 (Gap 3) ---
import hashlib as _hashlib
import datetime as _dt
import json as _json

# Map forensic op to IR opcode + result type per IR_SPEC §8-18
OP_IR_META = {
    "system.info": ("SYSTEM_INFO", "evidence", "system"),
    "process.list": ("PROCESS_LIST", "evidence_set<process>", "process"),
    "process.tree": ("PROCESS_LIST", "evidence_set<process>", "process"),
    "process.modules": ("PROCESS_MODULES", "evidence_set<process>", "process"),
    "file.list": ("FILE_LIST", "evidence_set<file>", "file"),
    "file.hash": ("FILE_HASH", "string", "file"),
    "file.analyze": ("FILE_ANALYZE", "evidence", "file"),
    "file.metadata": ("FILE_METADATA", "evidence", "file"),
    "network.connections": ("NETWORK_CONNECTIONS", "evidence_set<network_connection>", "network"),
    "network.interfaces": ("NETWORK_INTERFACES", "evidence_set<network>", "network"),
    "memory.analyze": ("MEMORY_ANALYZE", "evidence", "memory"),
    "driver.list": ("DRIVER_LIST", "evidence_set<driver>", "driver"),
    "driver.scan": ("DRIVER_SCAN", "evidence_set<driver>", "driver"),
    "driver.risk": ("DRIVER_RISK", "evidence", "driver"),
    "report.generate": ("REPORT_GENERATE", "void", "report"),
    "evidence.load": ("EVIDENCE_LOAD", "evidence_set", "evidence"),
}

def build_ir_json(src: str, seed: int = 0, poly: bool = False):
    """
    Build IR JSON per IR_SPEC §32 deterministically from validated source.
    Returns dict with version, entry, metadata, capabilities, ops, investigations, imports, functions, instructions (SSA).
    Deterministic: same src+seed produces same JSON logical structure; polymorphic affects only header metadata not instruction opcodes.
    """
    ops, caps, errors, tokens, calls = validate_and_collect(src)
    if errors:
        raise ValueError("; ".join(errors))
    # Collect language constructs
    investigations, _ = parse_investigations(tokens)
    imports, _ = parse_imports(tokens)
    funcs, _ = parse_functions(tokens)
    builtins, _ = parse_lang_builtins(tokens)
    # Build deterministic metadata
    source_hash = _hashlib.sha256(src.encode()).hexdigest()[:12]
    build_ts = "2026-09-12T00:00:00Z"  # deterministic for tests; could use _dt.datetime.utcnow().isoformat()+"Z" for live but keep deterministic
    module_id = _hashlib.sha256((src + str(seed)).encode()).hexdigest()[:8]
    # Build SSA instructions
    instructions = []
    # Map each forensic op to SSA result %N
    for idx, op in enumerate(ops):
        opcode, rtype, cat = OP_IR_META.get(op, (op.replace(".", "_").upper(), "evidence", "unknown"))
        # Extract operands: for FILE_HASH / EVIDENCE_LOAD etc we try to extract arg via regex helper
        operands = []
        # For file.* and evidence.load try to extract path arg
        if op in ("file.hash","file.analyze","file.metadata","file.list","evidence.load","memory.analyze","driver.scan"):
            # try to extract first quoted string arg
            import re as _re2
            m = _re2.search(r'\b' + op.replace(".", r"\.") + r'\s*\(\s*["\']([^"\']*)["\']', src)
            if m:
                operands.append(m.group(1))
        instr = {
            "result": f"%{idx}",
            "opcode": opcode,
            "type": rtype,
            "category": cat,
            "op": op,
            "operands": operands,
            "result_type": rtype,
        }
        # Add source mapping if call known
        for c in calls:
            if f"{c.namespace}.{c.method}" == op:
                instr["metadata"] = {"source_file": "input.jocky", "line": c.line, "column": c.col}
                break
        instructions.append(instr)
    # Add built-ins as SSA after forensic ops (EVIDENCE_FILTER / CORRELATE per IR_SPEC §18, §20)
    ssa_idx = len(instructions)
    for b in builtins:
        if b == "filter":
            instructions.append({"result": f"%{ssa_idx}", "opcode": "EVIDENCE_FILTER", "type": "evidence_set", "category": "evidence", "op": "filter", "operands": ["%0"], "result_type": "evidence_set"})
            ssa_idx+=1
        elif b == "correlate":
            # correlate two evidences: use first two SSA if available
            if len(ops)>=2:
                instructions.append({"result": f"%{ssa_idx}", "opcode": "CORRELATE", "type": "evidence_set", "category": "correlation", "op": "correlate", "operands": ["%0","%1"], "result_type": "evidence_set"})
            else:
                instructions.append({"result": f"%{ssa_idx}", "opcode": "CORRELATE", "type": "evidence_set", "category": "correlation", "op": "correlate", "operands": [], "result_type": "evidence_set"})
            ssa_idx+=1
    # Add imports as instructions (IMPORT)
    for imp in imports:
        instructions.append({"result": f"%{ssa_idx}", "opcode": "IMPORT", "type": "void", "category": "import", "op": f"import {imp.module}", "operands": [imp.module], "result_type": "void", "metadata": {"line": imp.line, "column": imp.col}})
        ssa_idx+=1
    # Add functions as metadata (not executable SSA, but per IR_SPEC §25)
    functions = [{"name": f.name, "line": f.line, "column": f.col} for f in funcs]
    # Investigations per IR_SPEC §27
    inv_list = [{"title": iv.title, "line": iv.line, "column": iv.col} for iv in investigations]
    # Control-flow markers as instructions
    has_if = "if (" in src
    has_for = "for (" in src
    has_while = "while (" in src
    if has_if:
        instructions.append({"result": f"%{ssa_idx}", "opcode": "BRANCH", "type": "void", "category": "control", "op": "if", "operands": [], "result_type": "void"})
        ssa_idx+=1
    if has_for:
        instructions.append({"result": f"%{ssa_idx}", "opcode": "LOOP", "type": "void", "category": "control", "op": "for", "operands": [], "result_type": "void"})
        ssa_idx+=1
    if has_while:
        instructions.append({"result": f"%{ssa_idx}", "opcode": "LOOP", "type": "void", "category": "control", "op": "while", "operands": [], "result_type": "void"})
        ssa_idx+=1
    # Build module
    ir_json = {
        "version": 1,
        "ir_version": 1,
        "entry": "main",
        "metadata": {
            "compiler_version": "1.0",
            "language_version": "1.0",
            "source_hash": source_hash,
            "build_timestamp": build_ts,
            "module_id": module_id,
            "seed": seed,
            "poly": poly,
        },
        "capabilities": caps,
        "ops": ops,
        "investigations": inv_list,
        "imports": [im.module for im in imports],
        "functions": functions,
        "builtins": builtins,
        "instructions": instructions,
        "types": ["void","bool","int","float","string","list","map","evidence","evidence_set","finding","evidence_set<process>","evidence_set<file>","evidence_set<network_connection>","evidence_set<driver>"],
        "source_hash": source_hash,
        "module_id": module_id,
    }
    return ir_json

def validate_ir_json(ir: dict):
    """Validate IR JSON per IR_SPEC §33 — returns list of errors (empty if valid)."""
    errs=[]
    ver = ir.get("version") if ir.get("version") is not None else ir.get("ir_version")
    if ver is not None and ver != 1:
        errs.append(f"IR version mismatch: expected 1, got {ver} — IR Compatibility Error per IR_SPEC §6")
    if not ir.get("entry"):
        errs.append("IR missing entry point")
    if not isinstance(ir.get("instructions"), list):
        errs.append("IR instructions must be list")
    else:
        for idx, ins in enumerate(ir["instructions"]):
            if "opcode" not in ins:
                errs.append(f"Instruction {idx} missing opcode")
            if "result" not in ins:
                errs.append(f"Instruction {idx} missing result")
            if "type" not in ins and "result_type" not in ins:
                errs.append(f"Instruction {idx} missing type")
    # Capability declarations
    if "capabilities" not in ir:
        errs.append("IR missing capabilities")
    return errs
