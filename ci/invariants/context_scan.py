import json
from pathlib import Path
from typing import Any, Dict, Iterable, List

import yaml


SUPPORTED_SUFFIXES = {".json", ".yaml", ".yml"}


def _find_context_classes(obj: Any, path: str = "") -> List[Dict[str, str]]:
    results: List[Dict[str, str]] = []
    if isinstance(obj, dict):
        for key, value in obj.items():
            next_path = f"{path}.{key}" if path else key
            if key == "context_class" and isinstance(value, str):
                results.append({"context_class": value, "path": next_path})
            results.extend(_find_context_classes(value, next_path))
    elif isinstance(obj, list):
        for index, item in enumerate(obj):
            next_path = f"{path}[{index}]"
            results.extend(_find_context_classes(item, next_path))
    return results


def _load_file(file_path: Path) -> Any:
    if file_path.suffix == ".json":
        with file_path.open() as f:
            return json.load(f)
    with file_path.open() as f:
        return yaml.safe_load(f)


def scan_context_classes(repo_root: Path, search_paths: Iterable[str]) -> List[Dict[str, str]]:
    results: List[Dict[str, str]] = []
    for rel_path in search_paths:
        base_path = repo_root / rel_path
        if not base_path.exists():
            continue
        for file_path in base_path.rglob("*"):
            if not file_path.is_file():
                continue
            if file_path.suffix not in SUPPORTED_SUFFIXES:
                continue
            try:
                data = _load_file(file_path)
            except Exception:
                continue
            for entry in _find_context_classes(data):
                results.append({
                    "context_class": entry["context_class"],
                    "file": str(file_path.relative_to(repo_root)),
                    "path": entry["path"],
                })
    return results
