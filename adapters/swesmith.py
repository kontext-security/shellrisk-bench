"""Adapter: swesmith — benign agent bash from SWE-smith mini-swe-agent rollouts.

Source:  Kwai-Klear/SWE-smith-mini_swe_agent_plus-trajectories-66k  (HuggingFace)
Layer:   command (one bash command per instance)
License: MIT (upstream dataset card at the pinned revision).

Why this source:
  We are short on *realistic, messy, benign* bash — the kind an agent actually
  emits while solving a legit coding task (find/grep/sed/heredocs/`cd && python`).
  These are agent rollouts on SWE-bench-style tasks in the mini-swe-agent format:
  each assistant turn is THOUGHT + exactly one ```bash ...``` block. The benign
  label comes *for free* from the source task being benign — no hand-labeling.

  This is the "benign" half of the command-layer classifier's data. It is
  deliberately in-distribution for an AI coding agent, unlike textbook NL->bash.

Caveats baked into this adapter:
  - Rollouts repeat boilerplate heavily (`cd . && python test_x.py` x20), so we
    DEDUPE on the exact command string. Without this the set is worthless.
  - The label is *task-inferred*, not human-verified. Recorded in metadata so a
    downstream audit can revisit it. A benign SWE task can still contain a
    genuinely destructive command; that's a known residual and a reason to keep
    the risky class from other sources rather than trusting this as ground truth.

Run:
  python adapters/swesmith.py            # full: download all to data/raw, emit all unique
  python adapters/swesmith.py --limit 50 # smoke test: stream first 50 trajectories only
Out:
  data/normalized/swesmith.jsonl
"""

from __future__ import annotations

import hashlib
import re
import sys

from _common import RAW_DIR, make_instance, provenance, route_by_newline, write_jsonl

SOURCE = "swesmith"
DATASET_ID = "Kwai-Klear/SWE-smith-mini_swe_agent_plus-trajectories-66k"
SPLIT = "train"
# Pinned dataset revision for reproducible builds (resolved 2026-08-17).
# Bump by re-resolving the dataset's main branch on the HF Hub.
REVISION = "750b2c11239fd5e32f97e6cfb9bf80fb9a9a2983"

# Each assistant turn: THOUGHT ... then exactly one fenced bash block.
FENCE = re.compile(r"```bash\s*\n(.*?)```", re.DOTALL)

# Default: keep at most this many commands per normalized shape. Exact dedup alone
# leaves 1.24M commands, but ~77% are just filename/line-number variants of the
# same shape (e.g. `sed -n '<range>' <file.py>` appears 95k times). Capping per
# shape collapses that boilerplate flood without losing genuine variety.
DEFAULT_CAP_PER_SHAPE = 5

# ~83% of swesmith commands are `cat <<'EOF' > test.py … EOF` heredocs whose body
# is Python code (89% contain python keywords) — it's a code-gen pipeline in a
# thin bash wrapper, only ~16% is genuine shell. A heredoc file-write IS a real
# command an agent would submit, so we keep a small sample, but cap it hard so
# the ~98k genuine-bash commands aren't drowned by Python bodies (pure style).
DEFAULT_HEREDOC_CAP = 2000

_NUM = re.compile(r"\d+")
_SQ = re.compile(r"'[^']*'")
_DQ = re.compile(r'"[^"]*"')
_FILE = re.compile(r"[\w./-]+\.[A-Za-z0-9]{1,5}")


def command_shape(cmd: str) -> str:
    """Normalize a command to its structural shape: collapse numbers, quoted
    strings, and file paths so filename/line-number variants share one shape."""
    s = _SQ.sub("Q", cmd)
    s = _DQ.sub("Q", s)
    s = _FILE.sub("F", s)
    s = _NUM.sub("N", s)
    return " ".join(s.split())[:120]


def extract_commands(content: str) -> list[str]:
    """Pull every bash command string out of one assistant message."""
    return [blk.strip() for blk in FENCE.findall(content) if blk.strip()]


def iter_rows(limit: int | None):
    """Yield dataset rows. Streams (cheap, partial) when a limit is given;
    otherwise downloads the whole dataset into data/raw/<source> and iterates."""
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
    cap = DEFAULT_CAP_PER_SHAPE
    if "--cap-per-shape" in sys.argv:
        cap = int(sys.argv[sys.argv.index("--cap-per-shape") + 1])  # 0 disables
    heredoc_cap = DEFAULT_HEREDOC_CAP
    if "--heredoc-cap" in sys.argv:
        heredoc_cap = int(sys.argv[sys.argv.index("--heredoc-cap") + 1])  # 0 = drop all

    print(f"[{SOURCE}] building from {DATASET_ID}"
          + (f" (limit={limit})" if limit else " (full download)")
          + (f", cap {cap}/shape" if cap else ", no shape cap")
          + f", heredoc cap {heredoc_cap}")

    instances: list[dict] = []
    seen: set[str] = set()          # md5 of command string -> exact dedupe
    shape_counts: dict[str, int] = {}   # normalized shape -> kept count
    index = 0
    seen_cmds = 0
    n_shape_capped = 0
    n_heredoc_dropped = 0
    n_heredoc_kept = 0

    for row in iter_rows(limit):
        instance_id = row.get("instance_id", "")
        for turn, msg in enumerate(row.get("messages", [])):
            if msg.get("role") != "assistant":
                continue
            for cmd in extract_commands(msg.get("content", "")):
                seen_cmds += 1
                h = hashlib.md5(cmd.encode("utf-8")).hexdigest()
                if h in seen:
                    continue
                # Heredoc file-writes are mostly Python bodies; keep only a small sample.
                if "<<" in cmd:
                    if n_heredoc_kept >= heredoc_cap:
                        n_heredoc_dropped += 1
                        continue
                    n_heredoc_kept += 1
                elif cap:
                    shape = command_shape(cmd)
                    if shape_counts.get(shape, 0) >= cap:
                        n_shape_capped += 1
                        continue
                    shape_counts[shape] = shape_counts.get(shape, 0) + 1
                seen.add(h)
                # single-line turn -> atomic command; multi-line turn -> a script.
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
                            primary_source="SWE-smith trajectories (mini-swe-agent rollouts)",
                            edited=None,  # verbatim agent output
                        ),
                        context=None,   # command layer is context-free by construction
                        policy=None,
                        metadata={
                            "origin_dataset": DATASET_ID,
                            "instance_id": instance_id,
                            "turn": turn,
                            "label_basis": "task-inferred (benign SWE task, not human-verified)",
                        },
                    )
                )
                index += 1

    exact_dupes = seen_cmds - len(instances) - n_shape_capped - n_heredoc_dropped
    print(f"  extracted {seen_cmds} commands -> {len(instances)} kept "
          f"({exact_dupes} exact dupes, {n_shape_capped} near-dupes capped, "
          f"{n_heredoc_dropped} heredocs dropped, {n_heredoc_kept} heredocs kept, "
          f"{len(shape_counts)} distinct shapes)")
    write_jsonl(SOURCE, instances)


if __name__ == "__main__":
    main()
