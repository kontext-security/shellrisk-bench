"""Adapter: payloads — risky Linux one-liners from PayloadsAllTheThings.

Source:  swisskyrepo/InternalAllTheThings  (successor repo; PATT now points here)
Layer:   command (single-line) + session (multi-line) via route_by_newline
License: no license file declared in InternalAllTheThings at the pinned revision.
         Download-and-transform only; upstream content is not vendored here.

Why this source:
  The atomic risky class is under-sourced (ART+GTFOBins ~950). This adds curated
  offensive Linux one-liners — reverse/bind shells (bash/python/perl/ruby/php/nc/
  socat), privesc enumeration, evasion, persistence — a distinct "pentest
  cheatsheet" style. Supersedes slp's 123 (which was a subset of these roots).

Extraction reality (verified): commands live in fenced ```code``` blocks in
  markdown, interleaved with prose and mixed OS. Language tags exist but are
  unreliable (a Linux `socat` was tagged powershell; prose like "Victim:" sits
  inside fences). So we (1) keep only Linux/interpreter-tagged or untagged fences,
  (2) drop Windows/PowerShell by content, (3) strip shell prompts and prose lines.
  Coverage is partial and LOGGED — better to under-collect than to poison the
  risky class with PowerShell or prose.

Run:  python adapters/payloads.py
Out:  data/normalized/payloads.jsonl
"""

from __future__ import annotations

import hashlib
import re

from _common import RAW_DIR, download, make_instance, provenance, route_by_newline, write_jsonl

SOURCE = "payloads"
# Pinned to a commit for reproducible builds (resolved 2026-08-17).
# Bump by re-resolving swisskyrepo/InternalAllTheThings@main.
PIN = "203bb0c0b290bf7c9158c32d43523b8d66f292c1"
BASE = f"https://raw.githubusercontent.com/swisskyrepo/InternalAllTheThings/{PIN}"

# (path, source_label)
FILES = [
    ("docs/cheatsheets/shell-reverse-cheatsheet.md", "reverse-shell"),
    ("docs/cheatsheets/shell-bind-cheatsheet.md", "bind-shell"),
    ("docs/redteam/escalation/linux-privilege-escalation.md", "linux-privesc"),
    ("docs/redteam/evasion/linux-evasion.md", "linux-evasion"),
    ("docs/redteam/persistence/linux-persistence.md", "linux-persistence"),
]

FENCE = re.compile(r"```([a-zA-Z0-9+]*)\n(.*?)```", re.DOTALL)
INCLUDE_LANG = {"", "bash", "sh", "shell", "console", "python", "python3", "py", "perl", "ruby", "php", "awk"}
# content markers that mean Windows / PowerShell / not-a-Linux-shell-command
WINDOWS = re.compile(r"(?i)(IEX|Invoke-\w|New-Object|System\.|\.exe\b|cmd\.exe|C:\\\\|-nop\b|FromBase64String|powershell)")
PROMPT = re.compile(r"^\s*(?:[\w.\-]+@[\w.\-]+[:~][^\$#]*[#$]|[#$])\s+")
PROSE = re.compile(r"^\s*(Victim|Attacker|Target|Listener|On |In |Note|Example|Output|Server|Client|Step|Then|First|Now|Run|Start|Use)\b", re.IGNORECASE)


def clean_block(body: str) -> str | None:
    """Strip prompts/prose from a fenced block; return the cleaned command text
    (may be multi-line) or None if nothing command-like remains."""
    if WINDOWS.search(body):
        return None
    lines = []
    for ln in body.splitlines():
        ln = PROMPT.sub("", ln).rstrip()
        s = ln.strip()
        if not s or len(s) < 4:
            continue
        if s.endswith(":") or PROSE.search(s):   # prose heading / narration
            continue
        # bare placeholder token (e.g. "my-sneaky-command"): no shell structure
        if not any(c in s for c in " /|=><&"):
            continue
        lines.append(ln)
    return "\n".join(lines) if lines else None


def main() -> None:
    print(f"[{SOURCE}] building from InternalAllTheThings")
    instances: list[dict] = []
    seen: set[str] = set()
    index = 0
    n_fence = n_kept = n_dupe = 0

    for path, label in FILES:
        url = f"{BASE}/{path}"
        dest = download(url, RAW_DIR / SOURCE / path.replace("/", "__"))
        text = dest.read_text(encoding="utf-8", errors="replace")
        for lang, body in FENCE.findall(text):
            n_fence += 1
            if lang.lower() not in INCLUDE_LANG:
                continue
            cmd = clean_block(body)
            if not cmd:
                continue
            h = hashlib.md5(cmd.encode("utf-8")).hexdigest()
            if h in seen:
                n_dupe += 1
                continue
            seen.add(h)
            n_kept += 1
            layer, actions = route_by_newline(cmd)
            instances.append(
                make_instance(
                    source=SOURCE,
                    index=index,
                    layer=layer,
                    actions=actions,
                    verdict="deny",
                    source_label=label,
                    provenance=provenance(
                        primary_source="PayloadsAllTheThings / InternalAllTheThings",
                        edited=None,  # verbatim (example IPs/hosts as in source)
                    ),
                    context=None,
                    policy=None,
                    metadata={"origin_dataset": "swisskyrepo/InternalAllTheThings", "file": path},
                )
            )
            index += 1

    print(f"  fences scanned: {n_fence} | kept: {n_kept} | dupes: {n_dupe}")
    write_jsonl(SOURCE, instances)


if __name__ == "__main__":
    main()
