#!/usr/bin/env python3
import os
from pathlib import Path

DEFAULT_MAX_LOC = 350
DEFAULT_EXCLUDED_DIRS = {"tests", "types", ".git", ".venv", "__pycache__", "venv"}


def count_loc(file_path: Path) -> int:
    return len(file_path.read_text().splitlines())


def collect_python_files(repo_root: Path) -> list[Path]:
    return sorted(repo_root.rglob("*.py"))


def check_loc(
    repo_root: Path,
    max_loc: int = DEFAULT_MAX_LOC,
    excluded_dirs: set[str] | None = None,
) -> list[dict]:
    excluded = excluded_dirs or DEFAULT_EXCLUDED_DIRS
    violations = []
    for file_path in collect_python_files(repo_root):
        if any(part in excluded for part in file_path.parts):
            continue
        loc = count_loc(file_path)
        if loc > max_loc:
            violations.append({
                "file": str(file_path.relative_to(repo_root)),
                "loc": loc,
                "max_loc": max_loc,
            })
    return violations


def main() -> int:
    repo_root = Path(os.environ.get("REPO_ROOT", ".")).resolve()
    max_loc = int(os.environ.get("MAX_LOC", DEFAULT_MAX_LOC))

    violations = check_loc(repo_root, max_loc=max_loc)

    if violations:
        print(f"{len(violations)} file(s) exceed {max_loc} LOC:")
        for violation in violations:
            print(f"  - {violation['file']}: {violation['loc']} LOC")
        return 1

    print(f"All source files are within {max_loc} LOC")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
