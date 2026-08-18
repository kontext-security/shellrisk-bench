"""Shared helpers for ShellRisk-Bench adapters.

Keep this small. Its only job is to make every adapter emit instances in the
same shape (see SCHEMA.md) and write them the same way.
"""

from __future__ import annotations

import json
import shutil
import time
import urllib.request
from urllib.error import HTTPError, URLError
from pathlib import Path

# Repo-root-relative data directories. Adapters live in adapters/, so root is one up.
ROOT = Path(__file__).resolve().parent.parent
RAW_DIR = ROOT / "data" / "raw"
NORMALIZED_DIR = ROOT / "data" / "normalized"

VERDICTS = {"allow", "deny", "ask"}
LAYERS = {"command", "session", "agentic"}


import re

# Shared normalization applied uniformly across every benchmark source.
# These substitutions prevent models from memorizing incidental attacker hosts or
# long encoded blobs while preserving the surrounding danger-bearing structure.
_URL = re.compile(r"https?://[^\s'\"`;|)]+", re.IGNORECASE)
_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_B64 = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/])")


def normalize_command(text: str) -> str:
    """Deterministic normalization applied during benchmark construction.
    URL -> example.com, IP -> 1.1.1.1, long base64 blob -> BASE64."""
    if not text:
        return text
    text = _URL.sub("http://example.com", text)
    text = _IP.sub("1.1.1.1", text)
    text = _B64.sub("BASE64", text)
    return text


def route_by_newline(content: str) -> tuple[str, list[dict]]:
    """Decide the layer + actions for a raw command string.

    A single-line input is one tool-call submission -> `command` (atomic), kept
    WHOLE even if it chains with pipes/&&/; (we label the submission, never split
    it). A multi-line input is a script/sequence -> `session`, with one action per
    line, order preserved. We never flatten a sequence into atomic labels.
    """
    lines = [ln.strip() for ln in content.splitlines() if ln.strip()]
    if len(lines) <= 1:
        return "command", [{"type": "shell", "content": content.strip()}]
    return "session", [{"type": "shell", "content": ln} for ln in lines]


def provenance(primary_source: str, edited: str | None = None) -> dict:
    """Standard provenance record for an instance's metadata.

    primary_source: the ROOT dataset this instance's data came from (e.g. "nl2bash"),
                    not necessarily the adapted source. See DATASETS.md.
    edited:         short description of any change the adapted source made to the raw
                    data (e.g. "IP/domain normalized"); None if the data is verbatim.
    """
    return {"primary_source": primary_source, "edited": edited}


def make_instance(
    *,
    source: str,
    index: int,
    layer: str,
    actions: list[dict],
    verdict: str,
    source_label: str,
    provenance: dict,
    context: dict | None = None,
    policy: dict | None = None,
    rationale: str | None = None,
    metadata: dict | None = None,
) -> dict:
    """Build one instance in the unified schema, validating the enums.

    `provenance` is required (see the provenance() helper): every instance must
    record where its data actually came from and whether it was edited.
    """
    if layer not in LAYERS:
        raise ValueError(f"bad layer {layer!r}; expected one of {sorted(LAYERS)}")
    if verdict not in VERDICTS:
        raise ValueError(f"bad verdict {verdict!r}; expected one of {sorted(VERDICTS)}")
    if not actions:
        raise ValueError("actions must be non-empty")
    if "primary_source" not in provenance:
        raise ValueError("provenance must include 'primary_source' (use the provenance() helper)")

    meta = dict(metadata or {})
    meta["provenance"] = provenance
    # (A) shared normalization applied to every command, uniformly across sources
    actions = [{**a, "content": normalize_command(a.get("content", ""))} for a in actions]
    return {
        "id": f"{source}-{index:06d}",
        "source": source,
        "layer": layer,
        "actions": actions,
        "context": context,
        "policy": policy,
        "label": {
            "verdict": verdict,
            "source_label": source_label,
            "rationale": rationale,
        },
        "metadata": meta,
    }


def download(url: str, dest: Path) -> Path:
    """Download `url` to `dest` unless it already exists. Returns the path."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists() and dest.stat().st_size > 0:
        print(f"  cached: {dest.relative_to(ROOT)}")
        return dest
    print(f"  fetching: {url}")
    partial = dest.with_suffix(dest.suffix + ".part")
    for attempt in range(1, 5):
        try:
            with (
                urllib.request.urlopen(url, timeout=120) as resp,  # noqa: S310 (trusted, pinned URLs)
                partial.open("wb") as handle,
            ):
                shutil.copyfileobj(resp, handle, length=1024 * 1024)
            partial.replace(dest)
            return dest
        except HTTPError as exc:
            if exc.code < 500 and exc.code != 429:
                raise
            error: Exception = exc
        except URLError as exc:
            error = exc
        partial.unlink(missing_ok=True)
        if attempt < 4:
            delay = 2 ** (attempt - 1)
            print(f"  transient download error ({error}); retrying in {delay}s")
            time.sleep(delay)
    raise error


def write_jsonl(source: str, instances: list[dict]) -> Path:
    """Write instances to data/normalized/<source>.jsonl. Returns the path."""
    NORMALIZED_DIR.mkdir(parents=True, exist_ok=True)
    out = NORMALIZED_DIR / f"{source}.jsonl"
    with out.open("w", encoding="utf-8") as f:
        for inst in instances:
            f.write(json.dumps(inst, ensure_ascii=False) + "\n")
    print(f"  wrote {len(instances)} instances -> {out.relative_to(ROOT)}")
    return out
