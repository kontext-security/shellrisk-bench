"""Export the frozen ShellRisk-Bench split as a Hugging Face dataset repository."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from pathlib import Path

from datasets import Dataset, load_dataset

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SPLIT_DIR = ROOT / "data" / "splits"
DEFAULT_OUTPUT_DIR = ROOT / "dist" / "huggingface"
CARD_PATH = ROOT / "huggingface" / "README.md"
SPLITS = ("train", "test")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _jsonl_rows(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def _verify_input(split_dir: Path, manifest: dict) -> None:
    for split in SPLITS:
        source_path = split_dir / f"{split}.jsonl"
        if not source_path.exists():
            raise FileNotFoundError(f"missing {source_path}")
        expected = manifest.get(split, {}).get("sha256")
        actual = _sha256(source_path)
        if expected != actual:
            raise ValueError(
                f"{split} checksum mismatch: expected {expected!r}, got {actual!r}; "
                "rebuild and verify the frozen split before exporting"
            )


def export(split_dir: Path = DEFAULT_SPLIT_DIR, output_dir: Path = DEFAULT_OUTPUT_DIR) -> dict:
    """Write a viewer-compatible dataset repository without uploading it."""
    manifest_path = split_dir / "manifest.json"
    if not manifest_path.exists():
        raise FileNotFoundError(f"missing {manifest_path}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    _verify_input(split_dir, manifest)

    data_dir = output_dir / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(CARD_PATH, output_dir / "README.md")
    shutil.copyfile(manifest_path, output_dir / "split-manifest.json")

    exported: dict[str, dict] = {}
    for split in SPLITS:
        rows = _jsonl_rows(split_dir / f"{split}.jsonl")
        expected_rows = manifest[split]["n"]
        if len(rows) != expected_rows:
            raise ValueError(
                f"{split} row count mismatch: expected {expected_rows}, got {len(rows)}"
            )
        output_path = data_dir / f"{split}-00000-of-00001.parquet"
        temporary_path = output_path.with_suffix(".parquet.tmp")
        try:
            Dataset.from_list(rows).to_parquet(temporary_path)
            temporary_path.replace(output_path)
        finally:
            temporary_path.unlink(missing_ok=True)
        exported[split] = {
            "path": str(output_path.relative_to(output_dir)),
            "rows": len(rows),
            "sha256": _sha256(output_path),
        }

    export_manifest = {
        "benchmark": manifest["benchmark"],
        "version": manifest["version"],
        "source_manifest_sha256": _sha256(manifest_path),
        "files": exported,
    }
    (output_dir / "export-manifest.json").write_text(
        json.dumps(export_manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return export_manifest


def verify_loadable(output_dir: Path = DEFAULT_OUTPUT_DIR) -> dict[str, int]:
    """Load the exported Parquet files using the public consumer API."""
    files = {
        split: str(output_dir / "data" / f"{split}-00000-of-00001.parquet")
        for split in SPLITS
    }
    dataset = load_dataset("parquet", data_files=files)
    return {split: dataset[split].num_rows for split in SPLITS}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--split-dir", type=Path, default=DEFAULT_SPLIT_DIR)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    args = parser.parse_args()
    exported = export(args.split_dir, args.output_dir)
    loaded = verify_loadable(args.output_dir)
    print(json.dumps({"export": exported, "loaded_rows": loaded}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
