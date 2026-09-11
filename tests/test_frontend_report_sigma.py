"""
Frontend report history + sigma panel presence per P0-2
"""
def test_frontend_report_sigma_ui():
    import pathlib
    txt = pathlib.Path("frontend/src/App.tsx").read_text(encoding="utf-8")
    assert "reports" in txt.lower()
    assert "/api/cases/${caseId}/reports" in txt or "/api/cases/" in txt
    assert "/api/sigma/rules" in txt
    assert "Auto-Tune" in txt
    assert "tune" in txt.lower()
