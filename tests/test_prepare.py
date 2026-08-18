import json
from pathlib import Path

from shellrisk_bench.prepare import load_clean


def _write(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def _instance(source: str, index: int, command: str, verdict: str, layer: str = "command") -> dict:
    return {
        "id": f"{source}-{index:06d}",
        "source": source,
        "layer": layer,
        "actions": [{"type": "shell", "content": command}],
        "label": {"verdict": verdict},
    }


def test_load_clean_deduplicates_and_drops_collisions(tmp_path: Path) -> None:
    from shellrisk_bench.prepare import SOURCES

    for source in SOURCES:
        _write(tmp_path / f"{source}.jsonl", [])
    _write(
        tmp_path / "atomicredteam.jsonl",
        [
            _instance("atomicredteam", 0, "risky only", "deny"),
            _instance("atomicredteam", 1, "collision", "deny"),
            _instance("atomicredteam", 2, "ignored session", "deny", "session"),
        ],
    )
    _write(
        tmp_path / "nl2bash.jsonl",
        [
            _instance("nl2bash", 0, "benign only", "allow"),
            _instance("nl2bash", 1, "benign only", "allow"),
            _instance("nl2bash", 2, "collision", "allow"),
        ],
    )
    clean, stats = load_clean(tmp_path)
    assert set(clean) == {"risky only", "benign only"}
    assert stats["raw_command_rows"] == 5
    assert stats["unique_commands"] == 3
    assert stats["cross_label_collisions_dropped"] == 1

