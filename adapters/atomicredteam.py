"""Adapter: atomicredteam — risky commands from Atomic Red Team.

Source:  redcanaryco/atomic-red-team  (GitHub, master tarball)
Layer:   command (one bash/sh command block per instance)
License: MIT (upstream).

Why this source:
  The risky half of the command-layer classifier. Atomic Red Team is a PRIMARY
  source: Red Canary authors atomic tests and indexes each to a MITRE ATT&CK
  technique. Malicious-by-construction, so the label is real (not inferred like
  the benign agent-bash sources). Only the sh/bash executors are relevant to a
  bash classifier; command_prompt / powershell / manual executors are skipped.

  These commands are DATA, never executed. We normalize the command text into
  the schema; nothing here runs.

What we do to the data (recorded as provenance.edited):
  Each executor.command contains #{arg} template placeholders. We substitute the
  default from input_arguments, so the emitted command is concrete. That is an
  edit to the raw text — hence edited != None.

Known confound: ART commands are curated attack one-liners; the benign sources
  are messy agent task bash. A classifier can separate them on *style*. That is
  exactly what leave-one-source-out eval exists to catch — do not read a high
  ART-vs-swesmith score as risk detection until LOSO confirms it.

Verdict mapping (benchmark-level decision):
  attack technique -> deny   (source_label keeps the technique id for traceability)

Run:  python adapters/atomicredteam.py
Out:  data/normalized/atomicredteam.jsonl
"""

from __future__ import annotations

import hashlib
import re
import tarfile

import yaml

from _common import RAW_DIR, download, make_instance, provenance, route_by_newline, write_jsonl

SOURCE = "atomicredteam"
# Pinned to a commit for reproducible builds (resolved 2026-08-17).
# Bump by re-resolving redcanaryco/atomic-red-team@master.
PIN = "5cdeb06642dbdfb3c595d4096cb9eea5f6434d8b"
TARBALL = f"https://codeload.github.com/redcanaryco/atomic-red-team/tar.gz/{PIN}"

SHELL_EXECUTORS = {"sh", "bash"}
# Technique yaml lives at atomics/<TID>/<TID>.yaml (skip .md, Indexes, src files).
YAML_MEMBER = re.compile(r"/atomics/(T[0-9A-Za-z.\-]+)/(T[0-9A-Za-z.\-]+)\.yaml$")
PLACEHOLDER = re.compile(r"#\{([^}]+)\}")


def substitute(command: str, input_arguments: dict) -> str:
    """Replace #{arg} with its declared default; leave unknown args untouched."""
    defaults = {k: str((v or {}).get("default", "")) for k, v in (input_arguments or {}).items()}
    return PLACEHOLDER.sub(lambda m: defaults.get(m.group(1), m.group(0)), command)


def iter_technique_yamls(tar_path):
    """Yield parsed technique yaml docs from the ART tarball."""
    with tarfile.open(tar_path, "r:gz") as tar:
        for member in tar:
            m = YAML_MEMBER.search(member.name)
            if not member.isfile() or not m or m.group(1) != m.group(2):
                continue
            fh = tar.extractfile(member)
            if fh is None:
                continue
            try:
                yield yaml.safe_load(fh.read().decode("utf-8", errors="replace"))
            except yaml.YAMLError:
                continue


def main() -> None:
    print(f"[{SOURCE}] building from {TARBALL}")
    tar_path = download(TARBALL, RAW_DIR / SOURCE / "atomic-red-team.tar.gz")

    instances: list[dict] = []
    seen: set[str] = set()
    index = 0
    n_tests = n_shell = n_dupe = 0

    for doc in iter_technique_yamls(tar_path):
        if not doc:
            continue
        technique = doc.get("attack_technique", "")
        display = doc.get("display_name", "")
        for test in doc.get("atomic_tests") or []:
            n_tests += 1
            executor = test.get("executor") or {}
            if executor.get("name") not in SHELL_EXECUTORS:
                continue
            command = (executor.get("command") or "").strip()
            if not command:
                continue
            n_shell += 1
            command = substitute(command, test.get("input_arguments")).strip()
            # (B) scrub ART self-identifying markers that leak the source (technique
            # IDs baked into filenames, "Atomic Red Team" test strings) — real
            # attacks don't label themselves. Build-time only.
            command = re.sub(r"\bT\d{4}(?:\.\d{3})?\b", "sample", command)
            command = re.sub(r"(?i)atomic[\s_-]?red[\s_-]?team", "test", command)
            command = re.sub(r"(?i)atomic", "test", command)
            h = hashlib.md5(command.encode("utf-8")).hexdigest()
            if h in seen:
                n_dupe += 1
                continue
            seen.add(h)
            # single-line test -> atomic command; multi-line test -> a script/sequence.
            layer, actions = route_by_newline(command)
            instances.append(
                make_instance(
                    source=SOURCE,
                    index=index,
                    layer=layer,
                    actions=actions,
                    verdict="deny",
                    source_label=technique,  # e.g. "T1548.001" — traceable to ATT&CK
                    provenance=provenance(
                        primary_source="Atomic Red Team (Red Canary)",
                        edited="#{args} substituted with input_arguments defaults",
                    ),
                    context=None,
                    policy=None,
                    metadata={
                        "origin_dataset": "redcanaryco/atomic-red-team",
                        "technique": technique,
                        "display_name": display,
                        "test_name": test.get("name"),
                        "executor": executor.get("name"),
                        "supported_platforms": test.get("supported_platforms"),
                        "elevation_required": executor.get("elevation_required", False),
                    },
                )
            )
            index += 1

    print(f"  atomic tests scanned: {n_tests} | sh/bash: {n_shell} | kept unique: {len(instances)} | dupes: {n_dupe}")
    write_jsonl(SOURCE, instances)


if __name__ == "__main__":
    main()
