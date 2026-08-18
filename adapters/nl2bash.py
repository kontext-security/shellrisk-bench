"""Adapter: nl2bash — benign command corpus (breadth source).

Source:  TellinaTool/nl2bash  (GitHub, data/bash/all.cm)
Layer:   command (one bash command per instance)
License: MIT for data/bash (upstream README).

Why this source:
  A THIRD benign source, added for *vocabulary breadth*, not realism. nl2bash is
  human-curated NL->bash pairs from StackOverflow — idealized, demonstrative
  one-liners. That's a different distribution from our agent-traffic sources
  (swesmith = coding-agent bash, terminalbench = ops-agent bash), which is
  exactly why it helps: three stylistically distinct benign sources make the
  leave-one-source-out benign transfer eval more meaningful.

  It is NOT a replacement for swesmith: nl2bash is what humans *document*, not
  what an agent *runs*, so it is intentionally distributionally distinct.
  Its value is the utilities the agent sources undersample (rsync/ssh/sudo/tar/
  diff/...). Caveat: heavily `find`-skewed (~60% find commands).

Run:  python adapters/nl2bash.py
Out:  data/normalized/nl2bash.jsonl
"""

from __future__ import annotations

import hashlib

from _common import RAW_DIR, download, make_instance, provenance, write_jsonl

SOURCE = "nl2bash"
# Pinned to a commit for reproducible builds (resolved 2026-08-17).
# Bump by re-resolving TellinaTool/nl2bash@master.
PIN = "d6b9f5bdff45621d190134e31ab63b7bf7002190"
CMD_URL = f"https://raw.githubusercontent.com/TellinaTool/nl2bash/{PIN}/data/bash/all.cm"


def main() -> None:
    print(f"[{SOURCE}] building from {CMD_URL}")
    path = download(CMD_URL, RAW_DIR / SOURCE / "all.cm")
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()

    instances: list[dict] = []
    seen: set[str] = set()
    index = 0
    n_lines = 0

    for line in lines:
        cmd = line.strip()
        if not cmd:
            continue
        n_lines += 1
        h = hashlib.md5(cmd.encode("utf-8")).hexdigest()
        if h in seen:
            continue
        seen.add(h)
        instances.append(
            make_instance(
                source=SOURCE,
                index=index,
                layer="command",
                actions=[{"type": "shell", "content": cmd}],
                verdict="allow",
                source_label="benign",
                provenance=provenance(
                    primary_source="nl2bash",
                    edited=None,  # verbatim command from the nl2bash corpus
                ),
                context=None,
                policy=None,
                metadata={
                    "origin_dataset": "TellinaTool/nl2bash",
                    "label_basis": "human-curated NL->bash (StackOverflow); benign by construction",
                },
            )
        )
        index += 1

    print(f"  {n_lines} commands -> {len(instances)} unique ({n_lines - len(instances)} dupes)")
    write_jsonl(SOURCE, instances)


if __name__ == "__main__":
    main()
