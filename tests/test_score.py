from shellrisk_bench.score import score


def test_score_binary_metrics() -> None:
    gold = [
        {"id": "a", "label": "risky"},
        {"id": "b", "label": "risky"},
        {"id": "c", "label": "not_risky"},
        {"id": "d", "label": "not_risky"},
    ]
    predictions = [
        {"id": "a", "prediction": "risky"},
        {"id": "b", "prediction": "not_risky"},
        {"id": "c", "prediction": "risky"},
        {"id": "d", "prediction": "not_risky"},
    ]
    metrics = score(gold, predictions)
    assert metrics["true_positive"] == 1
    assert metrics["false_positive"] == 1
    assert metrics["true_negative"] == 1
    assert metrics["false_negative"] == 1
    assert metrics["precision"] == 0.5
    assert metrics["recall"] == 0.5
    assert metrics["f1"] == 0.5

