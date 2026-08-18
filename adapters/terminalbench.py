"""Adapter: terminalbench — benign agent bash from Terminal-Bench 2.0 trajectories.

Source:  yoonholee/terminalbench-trajectories  (HuggingFace)
Layer:   command (one bash command per instance)
License: Apache-2.0 (upstream); check the dataset card before redistribution.

Why this source:
  Second benign source, chosen for DIVERSITY. SWE-smith is Python-OSS-heavy;
  Terminal-Bench tasks span sysadmin/ops, debugging, security, ML, scientific
  computing (apt-get, Rscript, docker, log analysis...). Having two benign
  sources with different task distributions is what makes leave-one-source-out
  evaluation meaningful on the benign side — if a classifier only works when
  trained on the same source it's tested on, it learned style, not risk.

Extraction reality (verified against the data, not assumed):
  Terminal-Bench aggregates ~109 agent/model harnesses, so encoding is NOT
  uniform. Each step has tools=[{fn, cmd}]. Only fn == "execute_bash" is real
  shell; other fns are non-bash tools (execute_ipython_cell = Python,
  str_replace_editor = file edits, task_tracker / finish / think). Some agents
  also emit "$N" variable-reference placeholders instead of a literal command
  (unusable). We therefore keep ONLY execute_bash with a literal command, and
  LOG what we drop rather than silently truncating — coverage is partial and
  that fact should be visible.

  Rows with steps == null (no trace logged; ~half the dataset) are skipped.
  Label is task-inferred benign, not human-verified (recorded in metadata).

Run:
  python adapters/terminalbench.py             # full: download all to data/raw, emit all unique
  python adapters/terminalbench.py --limit 100 # smoke test: stream first 100 trajectories
Out:
  data/normalized/terminalbench.jsonl
"""

from __future__ import annotations

import hashlib
import json
import re
import sys

from _common import RAW_DIR, make_instance, provenance, route_by_newline, write_jsonl

SOURCE = "terminalbench"
DATASET_ID = "yoonholee/terminalbench-trajectories"
SPLIT = "train"
# Pinned dataset revision for reproducible builds (resolved 2026-08-17).
# Bump by re-resolving the dataset's main branch on the HF Hub.
REVISION = "04e8940f5b6736a7ce8d22224fe2f2af74163ed2"

# Only this tool function carries real shell commands; everything else is
# a non-bash tool (python cell, file editor, task tracker, finish, think).
SHELL_FN = "execute_bash"
# Some agents emit a bare variable reference (e.g. "$34") instead of the literal
# command — the actual text was substituted away upstream and is unrecoverable.
VAR_REF = re.compile(r"^\$\{?\d+\}?$")


def usable_command(cmd: str) -> bool:
    cmd = cmd.strip()
    return bool(cmd) and not VAR_REF.match(cmd)


def iter_rows(limit: int | None):
    """Yield dataset rows. Streams (partial) when limited; else downloads all
    into data/raw/<source> and iterates."""
    from datasets import load_dataset

    if limit is not None:
        ds = load_dataset(DATASET_ID, split=SPLIT, streaming=True, revision=REVISION)
        for i, row in enumerate(ds):
            if i >= limit:
                return
            yield row
    else:
        cache = RAW_DIR / SOURCE
        cache.mkdir(parents=True, exist_ok=True)
        ds = load_dataset(DATASET_ID, split=SPLIT, cache_dir=str(cache), revision=REVISION)
        yield from ds


def main() -> None:
    limit = None
    if "--limit" in sys.argv:
        limit = int(sys.argv[sys.argv.index("--limit") + 1])

    print(f"[{SOURCE}] building from {DATASET_ID}" + (f" (limit={limit})" if limit else " (full download)"))

    instances: list[dict] = []
    seen: set[str] = set()
    index = 0
    # coverage counters — reported so partial extraction is never silent
    n_null = n_shell = n_dropped_var = n_dupe = 0

    for row in iter_rows(limit):
        raw = row.get("steps")
        if not raw or raw == "null":
            n_null += 1
            continue
        try:
            steps = json.loads(raw)
        except (ValueError, TypeError):
            n_null += 1
            continue

        agent = row.get("agent")
        task = row.get("task_name")
        trial_id = row.get("trial_id")

        for step in steps:
            for tool in step.get("tools") or []:
                if not isinstance(tool, dict) or tool.get("fn") != SHELL_FN:
                    continue
                n_shell += 1
                cmd_raw = tool.get("cmd")
                # Some agents store a numeric reference instead of the literal
                # command string; those are unrecoverable, same as "$N" refs.
                if not isinstance(cmd_raw, str) or not usable_command(cmd_raw):
                    n_dropped_var += 1
                    continue
                cmd = cmd_raw.strip()
                h = hashlib.md5(cmd.encode("utf-8")).hexdigest()
                if h in seen:
                    n_dupe += 1
                    continue
                seen.add(h)
                # single-line command -> atomic; multi-line -> a script/sequence.
                layer, actions = route_by_newline(cmd)
                instances.append(
                    make_instance(
                        source=SOURCE,
                        index=index,
                        layer=layer,
                        actions=actions,
                        verdict="allow",
                        source_label="benign",
                        provenance=provenance(
                            primary_source="Terminal-Bench 2.0 agent trajectories",
                            edited=None,
                        ),
                        context=None,
                        policy=None,
                        metadata={
                            "origin_dataset": DATASET_ID,
                            "task_name": task,
                            "agent": agent,
                            "trial_id": trial_id,
                            "label_basis": "task-inferred (benign Terminal-Bench task, not human-verified)",
                        },
                    )
                )
                index += 1

    print(
        f"  execute_bash tools seen: {n_shell} | kept unique: {len(instances)} | "
        f"dropped var-refs: {n_dropped_var} | dupes: {n_dupe} | null-trace trials skipped: {n_null}"
    )
    write_jsonl(SOURCE, instances)


if __name__ == "__main__":
    main()
