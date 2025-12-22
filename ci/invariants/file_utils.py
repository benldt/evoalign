import json
from pathlib import Path

import yaml

DATA_SUFFIXES = {".json", ".yaml", ".yml"}


def load_data_file(file_path: Path):
    if file_path.suffix == ".json":
        with file_path.open() as f:
            return json.load(f)
    with file_path.open() as f:
        return yaml.safe_load(f)


def iter_data_files(base_path: Path):
    if not base_path.exists():
        return []
    files = [
        path
        for path in base_path.rglob("*")
        if path.is_file() and path.suffix in DATA_SUFFIXES
    ]
    return sorted(files)
