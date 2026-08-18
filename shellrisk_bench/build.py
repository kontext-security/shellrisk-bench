"""Build every pinned ShellRisk-Bench source adapter."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ADAPTERS = (
    "swesmith",
    "terminalbench",
    "nl2bash",
    "atomicredteam",
    "gtfobins",
    "payloads",
)


def main() -> None:
    for name in ADAPTERS:
        path = ROOT / "adapters" / f"{name}.py"
        print(f"\n== Building {name} ==", flush=True)
        subprocess.run([sys.executable, str(path)], cwd=ROOT, check=True)


if __name__ == "__main__":
    main()

