"""Adapter: gtfobins — risky "living-off-the-land" bash from GTFOBins.

Source:  GTFOBins/GTFOBins.github.io  (GitHub, master tarball, _gtfobins/ dir)
Layer:   command (one command per instance)
License: GPL-3.0 (upstream). We download and transform at build time; upstream
         content is git-ignored and is not redistributed in this repository.

Why this source:
  Third risky source, chosen for a genuinely DISTINCT style. GTFOBins catalogs
  how legitimate binaries can be abused to break out of restricted shells,
  escalate via SUID/sudo/capabilities, or read/write files with elevated privs
  (`find . -exec /bin/sh -p \\; -quit`, `vim -c ':!/bin/sh'`). This "LOLBin /
  privilege-abuse" style is covered by neither ATT&CK technique commands nor
  honeypot droppers, so it directly improves risky-side cross-source transfer
  and roughly doubles the risky class (moving imbalance ~107:1 -> ~50:1).

Structure (verified): one extensionless YAML file per binary under _gtfobins/.
  functions.<type>[] each have a `code:` block; nested contexts.<ctx> may carry a
  privileged variant under contexts.<ctx>.code. We emit both. The function type
  (shell / suid / sudo / file-read / file-write / capabilities / ...) is kept as
  source_label — it says WHICH capability is being abused.

  Commands contain GTFOBins template placeholders (`/path/to/input-file`, `DATA`,
  `...`) which we keep verbatim; they are part of the abuse pattern.

Verdict mapping: LOLBin/privilege-abuse -> deny. Commands are data, never run.

Run:  python adapters/gtfobins.py
Out:  data/normalized/gtfobins.jsonl
"""

from __future__ import annotations

import hashlib
import re
import tarfile

import yaml

from _common import RAW_DIR, download, make_instance, provenance, route_by_newline, write_jsonl

SOURCE = "gtfobins"
# Pinned to a commit for reproducible builds (resolved 2026-08-17).
# Bump by re-resolving GTFOBins/GTFOBins.github.io@master.
PIN = "acd524623f9c406acedd2754ebd9c2431f3675ad"
TARBALL = f"https://codeload.github.com/GTFOBins/GTFOBins.github.io/tar.gz/{PIN}"
# extensionless binary files live directly under _gtfobins/
ENTRY = re.compile(r"/_gtfobins/([^/]+)$")


def iter_commands(tar_path):
    """Yield (binary, function_type, context, command) from every GTFOBins entry."""
    with tarfile.open(tar_path, "r:gz") as tar:
        for member in tar:
            m = ENTRY.search(member.name)
            if not member.isfile() or not m:
                continue
            binary = m.group(1)
            fh = tar.extractfile(member)
            if fh is None:
                continue
            try:
                doc = yaml.safe_load(fh.read().decode("utf-8", errors="replace"))
            except yaml.YAMLError:
                continue
            if not isinstance(doc, dict):
                continue
            for func_type, entries in (doc.get("functions") or {}).items():
                for entry in entries or []:
                    if not isinstance(entry, dict):
                        continue
                    code = entry.get("code")
                    if isinstance(code, str) and code.strip():
                        yield binary, func_type, "default", code.strip()
                    # privileged variants nested under contexts.<ctx>.code
                    for ctx_name, ctx_val in (entry.get("contexts") or {}).items():
                        if isinstance(ctx_val, dict) and isinstance(ctx_val.get("code"), str):
                            yield binary, func_type, ctx_name, ctx_val["code"].strip()


def main() -> None:
    print(f"[{SOURCE}] building from {TARBALL}")
    tar_path = download(TARBALL, RAW_DIR / SOURCE / "gtfobins.tar.gz")

    instances: list[dict] = []
    seen: set[str] = set()
    index = 0
    n_raw = n_dupe = 0

    for binary, func_type, context, cmd in iter_commands(tar_path):
        n_raw += 1
        h = hashlib.md5(cmd.encode("utf-8")).hexdigest()
        if h in seen:
            n_dupe += 1
            continue
        seen.add(h)
        # (B) scrub GTFOBins template placeholders that never occur in real traffic
        # (/path/to/input-file, DATA, LFILE...) so the model can't key on "cheatsheet".
        cmd = re.sub(r"/path/to/\S+", "/tmp/file", cmd)
        cmd = re.sub(r"\bLFILE\b|\bLPATH\b", "/tmp/file", cmd)
        cmd = re.sub(r"\bLDIR\b", "/tmp/dir", cmd)
        cmd = re.sub(r"\bLSO\b", "/tmp/lib.so", cmd)
        cmd = re.sub(r"\bDATA\b", "data", cmd)
        # single-line snippet -> atomic command; multi-step recipe -> session.
        layer, actions = route_by_newline(cmd)
        instances.append(
            make_instance(
                source=SOURCE,
                index=index,
                layer=layer,
                actions=actions,
                verdict="deny",
                source_label=func_type,   # shell / suid / sudo / file-read / ...
                provenance=provenance(
                    primary_source="GTFOBins",
                    edited=None,  # verbatim (retains GTFOBins /path/to & DATA placeholders)
                ),
                context=None,
                policy=None,
                metadata={
                    "origin_dataset": "GTFOBins/GTFOBins.github.io",
                    "binary": binary,
                    "function": func_type,
                    "gtfobins_context": context,  # default / sudo / suid / capabilities / ...
                },
            )
        )
        index += 1

    print(f"  code blocks: {n_raw} | kept unique: {len(instances)} | dupes: {n_dupe}")
    write_jsonl(SOURCE, instances)


if __name__ == "__main__":
    main()
