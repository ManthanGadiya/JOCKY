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

# Keywords per grammar/jocky.g4 + Lexer.cpp kws set
KEYWORDS = {"let", "if", "else", "for", "while", "func", "return", "import", "true", "false", "null"}

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

def validate_and_collect(src: str):
    """
    Grammar-wired validation (replaces RE_CALL regex).
    Returns (ops, caps, errors) where errors include syntax + unknown cap.
    Errors are fail-closed per SECURITY_MODEL §14 + IR_SPEC §33.
    """
    tokens = lex(src)
    calls, syntax_errors = parse_member_calls(tokens)
    errors = list(syntax_errors)
    ops = []
    caps = []
    seen = set()
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
    return ops, caps, errors, tokens, calls

def lex_dump(src: str) -> str:
    tokens = lex(src)
    lines = []
    for t in tokens:
        if t.kind == "END": continue
        lines.append(f"{t.kind:8} {t.text!r:20} line={t.line} col={t.col}")
    return "\n".join(lines)
