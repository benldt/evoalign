import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

import yaml


SUPPORTED_DATA_SUFFIXES = {".json", ".yaml", ".yml"}


def canonical_bytes(obj: Any) -> bytes:
    try:
        payload = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    except (TypeError, ValueError) as exc:
        raise ValueError("Object is not JSON-serializable") from exc
    return payload.encode("utf-8")


def sha256_canonical(obj: Any) -> str:
    digest = hashlib.sha256(canonical_bytes(obj)).hexdigest()
    return f"sha256:{digest}"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def load_data_file(path: Path) -> Any:
    if path.suffix == ".json":
        with path.open() as f:
            return json.load(f)
    if path.suffix in {".yaml", ".yml"}:
        with path.open() as f:
            return yaml.safe_load(f)
    raise ValueError(f"Unsupported data file suffix: {path.suffix}")


def sha256_data_file(path: Path) -> str:
    return sha256_canonical(load_data_file(path))


def normalize_hash(value: str | None) -> str:
    if not value:
        return ""
    return value.replace("sha256:", "")


def verify_hash(expected: str | None, actual: str | None) -> bool:
    if not expected or not actual:
        return False
    return normalize_hash(expected) == normalize_hash(actual)


def git_commit_exists(commit: str | None, repo_root: Path | None = None) -> bool:
    if not commit or not isinstance(commit, str):
        return False
    root = repo_root or Path.cwd()
    try:
        result = subprocess.run(
            ["git", "cat-file", "-e", commit],
            cwd=str(root),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except (OSError, ValueError):
        return False
    return result.returncode == 0
