from pathlib import Path
from typing import Any

from evoalign.provenance import sha256_canonical, sha256_data_file

from file_utils import iter_data_files, load_data_file


def compute_object_hash(obj: Any) -> str:
    return sha256_canonical(obj)


def load_registry(repo_root: Path) -> dict | None:
    registry_path = repo_root / "control_plane/evals/suites/registry.json"
    if not registry_path.exists():
        return None
    data = load_data_file(registry_path)
    if not isinstance(data, dict):
        return None
    return {
        "file": registry_path,
        "data": data,
        "hash": sha256_data_file(registry_path),
    }


def load_suite_sets(repo_root: Path) -> dict[str, dict]:
    sets_dir = repo_root / "control_plane/evals/suites/sets"
    suite_sets = {}
    for file_path in iter_data_files(sets_dir):
        if file_path.suffix != ".json":
            continue
        data = load_data_file(file_path)
        if not isinstance(data, dict):
            continue
        suite_set_id = data.get("suite_set_id")
        if not suite_set_id:
            continue
        suite_sets[suite_set_id] = {
            "file": file_path,
            "data": data,
            "hash": sha256_data_file(file_path),
        }
    return suite_sets


def load_dataset_manifests(repo_root: Path) -> dict[str, dict]:
    manifests_dir = repo_root / "control_plane/evals/datasets/manifests"
    datasets = {}
    for file_path in iter_data_files(manifests_dir):
        if file_path.suffix != ".json":
            continue
        data = load_data_file(file_path)
        if not isinstance(data, dict):
            continue
        dataset_id = data.get("dataset_id")
        if not dataset_id:
            continue
        datasets[dataset_id] = {
            "file": file_path,
            "data": data,
            "hash": sha256_data_file(file_path),
        }
    return datasets


def load_eval_runs(repo_root: Path) -> dict[str, dict]:
    runs_dir = repo_root / "control_plane/evals/runs"
    runs = {}
    for file_path in iter_data_files(runs_dir):
        if file_path.suffix != ".json":
            continue
        data = load_data_file(file_path)
        if not isinstance(data, dict):
            continue
        run_id = data.get("eval_run_id")
        if not run_id:
            continue
        runs[run_id] = {
            "file": file_path,
            "data": data,
            "hash": sha256_data_file(file_path),
        }
    return runs


def load_sweeps(repo_root: Path) -> dict[str, dict]:
    sweeps_dir = repo_root / "control_plane/governor/sweeps"
    sweeps = {}
    for file_path in iter_data_files(sweeps_dir):
        if file_path.suffix != ".json":
            continue
        data = load_data_file(file_path)
        if not isinstance(data, dict):
            continue
        sweep_id = data.get("sweep_id")
        if not sweep_id:
            continue
        sweeps[sweep_id] = {
            "file": file_path,
            "data": data,
            "hash": sha256_data_file(file_path),
        }
    return sweeps


def load_risk_fits(repo_root: Path) -> list[dict]:
    fits_dir = repo_root / "control_plane/governor/risk_fits"
    fits = []
    for file_path in iter_data_files(fits_dir):
        if file_path.suffix != ".json":
            continue
        data = load_data_file(file_path)
        if isinstance(data, list):
            items = data
        else:
            items = [data]
        for fit in items:
            if not isinstance(fit, dict):
                continue
            fits.append({"file": file_path, "data": fit})
    return fits


def load_oversight_plan_files(repo_root: Path) -> list[dict]:
    plans_dir = repo_root / "control_plane/governor/oversight_plans"
    plans = []
    for file_path in iter_data_files(plans_dir):
        if file_path.suffix != ".json":
            continue
        data = load_data_file(file_path)
        if not isinstance(data, dict):
            continue
        plans.append({"file": file_path, "data": data})
    return plans


def load_aars(repo_root: Path) -> list[dict]:
    aars_dir = repo_root / "aars"
    aars = []
    for file_path in iter_data_files(aars_dir):
        if file_path.suffix != ".json":
            continue
        data = load_data_file(file_path)
        if not isinstance(data, dict):
            continue
        aars.append({"file": file_path, "data": data})
    return aars
