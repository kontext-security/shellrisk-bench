import hashlib
import json
from pathlib import Path

import pytest

from shellrisk_bench.export_huggingface import export, verify_loadable


def _write_jsonl(path: Path, rows: list[dict]) -> str:
    path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _row(index: int, label: str) -> dict:
    return {
        "id": f"sha256:{index:064x}",
        "source": "fixture",
        "upstream_id": f"fixture-{index:06d}",
        "command": f"printf fixture-{index}",
        "label": label,
    }


def _split_fixture(tmp_path: Path) -> Path:
    split_dir = tmp_path / "splits"
    split_dir.mkdir()
    train = [_row(1, "not_risky"), _row(2, "risky")]
    test = [_row(3, "not_risky")]
    train_sha = _write_jsonl(split_dir / "train.jsonl", train)
    test_sha = _write_jsonl(split_dir / "test.jsonl", test)
    manifest = {
        "benchmark": "ShellRisk-Bench",
        "version": "0.1.0",
        "train": {"n": len(train), "sha256": train_sha},
        "test": {"n": len(test), "sha256": test_sha},
    }
    (split_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return split_dir


def test_export_is_loadable_by_datasets(tmp_path: Path) -> None:
    split_dir = _split_fixture(tmp_path)
    output_dir = tmp_path / "hub"

    manifest = export(split_dir, output_dir)

    assert manifest["files"]["train"]["rows"] == 2
    assert manifest["files"]["test"]["rows"] == 1
    assert verify_loadable(output_dir) == {"train": 2, "test": 1}
    assert (output_dir / "README.md").exists()
    assert (output_dir / "split-manifest.json").exists()


def test_export_rejects_checksum_mismatch(tmp_path: Path) -> None:
    split_dir = _split_fixture(tmp_path)
    with (split_dir / "test.jsonl").open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(_row(4, "risky")) + "\n")

    with pytest.raises(ValueError, match="test checksum mismatch"):
        export(split_dir, tmp_path / "hub")
