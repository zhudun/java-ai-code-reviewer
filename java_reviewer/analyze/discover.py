from __future__ import annotations

import fnmatch
import os
from pathlib import Path

from java_reviewer.config import ReviewConfig


def discover_files(root: Path, config: ReviewConfig) -> list[Path]:
    root = root.resolve()
    files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = Path(dirpath).resolve().relative_to(root).as_posix()
        if rel_dir == ".":
            rel_dir = ""
        dirnames[:] = [
            name
            for name in dirnames
            if not _excluded(f"{rel_dir}/{name}".lstrip("/") + "/", config.exclude)
        ]
        for name in filenames:
            rel = f"{rel_dir}/{name}".lstrip("/")
            path = Path(dirpath) / name
            if _excluded(rel, config.exclude):
                continue
            if any(_glob_match(rel, pattern) or _glob_match(name, pattern) for pattern in config.include):
                files.append(path)
    return sorted(files)


def _excluded(rel: str, patterns: list[str]) -> bool:
    return any(_glob_match(rel, pattern) or _glob_match(rel.rstrip("/"), pattern) for pattern in patterns)


def _glob_match(value: str, pattern: str) -> bool:
    if fnmatch.fnmatch(value, pattern):
        return True
    # allow **/*.java against nested paths
    if pattern.startswith("**/") and fnmatch.fnmatch(value, pattern[3:]):
        return True
    if "/" in value and fnmatch.fnmatch(value.split("/")[-1], pattern):
        return True
    return fnmatch.fnmatch("/" + value, pattern)
