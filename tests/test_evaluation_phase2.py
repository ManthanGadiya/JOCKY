import pathlib, json
def test_evaluate_json_exists_and_f1():
    p = pathlib.Path("build/evaluate.json")
    assert p.exists(), "build/evaluate.json must exist (run tools/evaluate.py --n 1000 --seed 42)"
    j = json.loads(p.read_text())
    assert j["N"] == 1000 and j["seed"] == 42
    assert 0.90 <= j["precision"] <= 1.0
    assert 0.90 <= j["recall"] <= 1.0
    assert j["TP"]+j["FP"]+j["TN"]+j["FN"] == 1000

def test_four_stages_resilience():
    j = json.loads(pathlib.Path("build/evaluate.json").read_text())
    st = j["stages"]
    assert st["labels"] == ["plain","shuffled","encrypted","flattened"]
    assert len(st["traditional"]) == 4 and len(st["jocky"]) == 4
    # JOCKY should be more resilient than YARA at encrypted stage
    assert st["jocky"][2] >= st["traditional"][2], "JOCKY encrypted resilience should >= YARA"
    assert 0.65 <= st["jocky_resilience"] <= 1.0
    assert 0.50 <= st["yara_resilience"] <= 1.0

def test_perf_json_p95():
    p = pathlib.Path("build/perf.json")
    assert p.exists()
    j = json.loads(p.read_text())
    ev = j.get("evidence", j)
    assert "avg_ms" in ev and "p95_ms" in ev
    assert ev["p95_ms"] < 500, "p95 should be <500ms per perf bench"
    assert ev["avg_ms"] < 100
