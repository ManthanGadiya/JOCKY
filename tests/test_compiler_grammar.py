"""
Compiler grammar wiring tests — Phase 3 per docs/STATUS.md Lexer/Parser scaffold → wired
Per: grammar/jocky.g4, jocky/src/Lexer.cpp, docs/LANGUAGE_SPEC.md §4-6, §23, docs/IR_SPEC.md §33
Validates: lex() tokenization, parse_member_calls() extraction, syntax errors, fail-closed
"""
import pathlib
from tools.jocky_lexer import lex, parse_member_calls, validate_and_collect, OP_CAPS

def test_lex_simple_statement():
    toks = lex("system.info();")
    kinds = [t.kind for t in toks if t.kind != "END"]
    assert kinds == ["ID","DOT","ID","LPAREN","RPAREN","SEMI"]
    assert toks[0].text == "system"
    assert toks[2].text == "info"

def test_lex_with_comment_and_string():
    src = '// comment\nfile.hash("/evidence/sample.exe"); /* block */'
    toks = lex(src)
    # comments skipped, should still find member call
    texts = [t.text for t in toks if t.kind not in ("END",)]
    assert "file" in texts
    assert "hash" in texts
    str_toks = [t for t in toks if t.kind=="STRING"]
    assert len(str_toks)==1 and "/evidence/sample.exe" in str_toks[0].text

def test_lex_keywords():
    toks = lex("let x = true; if (x) { return false; }")
    kws = [t.text for t in toks if t.kind=="KW"]
    assert "let" in kws and "if" in kws and "return" in kws

def test_parse_member_calls_extracts_ops():
    src = 'system.info();\nprocess.list();\nfile.hash("/a.exe");\nnetwork.connections();'
    toks = lex(src)
    calls, errs = parse_member_calls(toks)
    assert errs == []
    keys = [f"{c.namespace}.{c.method}" for c in calls]
    assert keys == ["system.info","process.list","file.hash","network.connections"]

def test_parse_syntax_error_unterminated_string():
    toks = lex('file.hash("unterminated);')
    calls, errs = parse_member_calls(toks)
    assert any("unterminated string" in e.lower() for e in errs)

def test_parse_syntax_error_unmatched_paren():
    toks = lex("system.info(;")
    calls, errs = parse_member_calls(toks)
    assert any("unmatched" in e.lower() for e in errs)

def test_validate_whitelist_pass():
    ops, caps, errs, toks, calls = validate_and_collect('system.info();\nprocess.list();')
    assert errs == []
    assert ops == ["system.info","process.list"]
    assert "system.read" in caps and "process.read" in caps

def test_validate_unknown_fail_closed_with_location():
    ops, caps, errs, toks, calls = validate_and_collect('edr.disable();')
    assert any("edr.disable" in e for e in errs)
    assert any("Fail-closed" in e for e in errs)
    assert any("1:" in e or "at" in e for e in errs)  # line-col reporting per LANGUAGE_SPEC §21

def test_validate_dedup():
    ops, caps, errs, toks, calls = validate_and_collect('system.info();\nsystem.info();\nprocess.list();')
    assert ops.count("system.info")==1
    assert len(ops)==2

def test_validate_integration_with_tools_jockyc():
    from tools.jockyc import validate_and_collect as j_validate
    ops, caps, errs = j_validate('edr.disable();')
    assert any("edr.disable" in e for e in errs)
    ops2, caps2, errs2 = j_validate('system.info();')
    assert errs2 == []

def test_g4_tokens_present_in_lexer():
    # Every JOCKY op per LANGUAGE_SPEC §10 should lex correctly
    for op in ["system.info","process.list","file.hash","network.connections","driver.scan","memory.analyze","report.generate","evidence.load"]:
        ns, meth = op.split(".")
        src = f"{ns}.{meth}();"
        toks = lex(src)
        calls, errs = parse_member_calls(toks)
        assert len(calls)==1 and f"{calls[0].namespace}.{calls[0].method}"==op, f"failed for {op}"

def test_backend_uses_same_lexer():
    from backend.app.main import validate_and_collect as b_validate
    ops, caps, errs = b_validate('edr.disable();')
    assert any("edr.disable" in e for e in errs)
    ops2, caps2, errs2 = b_validate('system.info(); memory.analyze("x");')
    # memory.analyze is whitelisted → no unknown error, but policy will deny at run time (403) not here
    assert errs2 == []
    assert "memory.analyze" in ops2
