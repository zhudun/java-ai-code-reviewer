from __future__ import annotations

import subprocess
from pathlib import Path


def changed_files(root: Path, base: str | None, head: str | None = None) -> list[Path]:
    root = root.resolve()
    args = ["git", "-C", str(root), "diff", "--name-only", "--diff-filter=ACMR"]
    if base and head:
        args.extend([base, head])
    elif base:
        args.extend([base, "HEAD"])
    else:
        args.append("HEAD")
    try:
        output = subprocess.check_output(args, text=True, stderr=subprocess.DEVNULL)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []
    files: list[Path] = []
    for line in output.splitlines():
        path = root / line.strip()
        if path.exists() and path.suffix in {".java", ".xml"}:
            files.append(path)
    if files:
        return files
    # unstaged / untracked fallback
    try:
        status = subprocess.check_output(
            ["git", "-C", str(root), "status", "--porcelain"],
            text=True,
            stderr=subprocess.DEVNULL,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []
    for line in status.splitlines():
        rel = line[3:].strip().split(" -> ")[-1]
        path = root / rel
        if path.exists() and path.suffix in {".java", ".xml"}:
            files.append(path)
    return sorted(set(files))
