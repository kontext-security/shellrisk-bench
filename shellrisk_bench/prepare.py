"""Create the deterministic ShellRisk-Bench v0.1 train/test split."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Iterable

import numpy as np
from sklearn.model_selection import train_test_split

ROOT = Path(__file__).resolve().parent.parent
SOURCES = (
    "atomicredteam",
    "gtfobins",
    "nl2bash",
    "payloads",
    "swesmith",
    "terminalbench",
)
SEED = 13
DEFAULT_BENIGN_CAP = 20_000


def _rows(path: Path) -> Iterable[dict]:
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                yield json.loads(line)


def _stable_id(command: str) -> str:
    return "sha256:" + hashlib.sha256(command.encode("utf-8")).hexdigest()


def load_clean(normalized_dir: Path) -> tuple[dict[str, dict], dict]:
    """Load command rows, globally deduplicate, and drop label collisions."""
    label_of: dict[str, set[int]] = {}
    record_of: dict[str, dict] = {}
    source_counts: dict[str, int] = {}
    raw_rows = 0

    for source in SOURCES:
        path = normalized_dir / f"{source}.jsonl"
        if not path.exists():
            raise FileNotFoundError(f"missing {path}; run python -m shellrisk_bench.build")
        source_counts[source] = 0
        for instance in _rows(path):
            if instance.get("layer") != "command":
                continue
            raw_rows += 1
            source_counts[source] += 1
            command = instance["actions"][0]["content"].strip()
            label = 1 if instance["label"]["verdict"] == "deny" else 0
            label_of.setdefault(command, set()).add(label)
            record_of.setdefault(
                command,
                {
                    "source": source,
                    "upstream_id": instance["id"],
                    "label": label,
                },
            )

    collisions = {command for command, labels in label_of.items() if len(labels) > 1}
    clean = {
        command: record_of[command]
        for command, labels in label_of.items()
        if len(labels) == 1
    }
    stats = {
        "raw_command_rows": raw_rows,
        "unique_commands": len(label_of),
        "cross_label_collisions_dropped": len(collisions),
        "clean_unique_commands": len(clean),
        "source_command_rows": source_counts,
    }
    return clean, stats


def make_split(clean: dict[str, dict], benign_cap: int = DEFAULT_BENIGN_CAP) -> tuple[list[str], list[str]]:
    benign = [command for command, record in clean.items() if record["label"] == 0]
    risky = [command for command, record in clean.items() if record["label"] == 1]
    if benign_cap and len(benign) > benign_cap:
        benign = list(np.random.default_rng(SEED).choice(benign, benign_cap, replace=False))
    commands = benign + risky
    labels = [0] * len(benign) + [1] * len(risky)
    train, test, _, _ = train_test_split(
        commands,
        labels,
        test_size=0.2,
        random_state=SEED,
        stratify=labels,
    )
    return list(train), list(test)


def _prepared(command: str, record: dict) -> dict:
    return {
        "id": _stable_id(command),
        "source": record["source"],
        "upstream_id": record["upstream_id"],
        "command": command,
        "label": "risky" if record["label"] else "not_risky",
    }


def _write_jsonl(path: Path, rows: Iterable[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def prepare(normalized_dir: Path, output_dir: Path, benign_cap: int = DEFAULT_BENIGN_CAP) -> dict:
    clean, stats = load_clean(normalized_dir)
    train_commands, test_commands = make_split(clean, benign_cap)
    train_path = output_dir / "train.jsonl"
    test_path = output_dir / "test.jsonl"
    _write_jsonl(train_path, (_prepared(command, clean[command]) for command in train_commands))
    _write_jsonl(test_path, (_prepared(command, clean[command]) for command in test_commands))

    test_risky = sum(clean[command]["label"] for command in test_commands)
    train_risky = sum(clean[command]["label"] for command in train_commands)
    manifest = {
        "benchmark": "ShellRisk-Bench",
        "version": "0.1.0",
        "seed": SEED,
        "benign_cap": benign_cap,
        **stats,
        "train": {
            "n": len(train_commands),
            "risky": train_risky,
            "not_risky": len(train_commands) - train_risky,
            "sha256": _file_sha256(train_path),
        },
        "test": {
            "n": len(test_commands),
            "risky": test_risky,
            "not_risky": len(test_commands) - test_risky,
            "sha256": _file_sha256(test_path),
        },
    }
    manifest_path = output_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--normalized-dir", type=Path, default=ROOT / "data" / "normalized")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "data" / "splits")
    parser.add_argument("--benign-cap", type=int, default=DEFAULT_BENIGN_CAP)
    parser.add_argument(
        "--verify",
        action="store_true",
        help="compare the generated manifest with results/split-manifest.json",
    )
    args = parser.parse_args()
    manifest = prepare(args.normalized_dir, args.output_dir, args.benign_cap)
    if args.verify:
        expected_path = ROOT / "results" / "split-manifest.json"
        expected = json.loads(expected_path.read_text(encoding="utf-8"))
        if manifest != expected:
            raise SystemExit(f"split verification failed: generated manifest differs from {expected_path}")
        print(f"verified against {expected_path.relative_to(ROOT)}")
    print(json.dumps(manifest, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
