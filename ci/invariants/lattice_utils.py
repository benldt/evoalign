from pathlib import Path
from typing import Any, Mapping

from evoalign.context_lattice import ContextLattice, ContextLatticeError
from evoalign.provenance import sha256_data_file

from file_utils import iter_data_files, load_data_file


def load_context_lattice(repo_root: Path) -> tuple[ContextLattice, Path]:
    lattice_dir = repo_root / "contracts/context_lattice"
    if not lattice_dir.exists():
        raise ContextLatticeError("Context lattice directory not found")
    lattice_files = [
        *sorted(lattice_dir.glob("*.yaml")),
        *sorted(lattice_dir.glob("*.yml")),
        *sorted(lattice_dir.glob("*.json")),
    ]
    if not lattice_files:
        raise ContextLatticeError("No context lattice files found")
    lattice_path = lattice_files[0]
    schema_path = repo_root / "schemas/ContextLattice.schema.json"
    return ContextLattice.load(lattice_path, schema_path=schema_path), lattice_path


def load_lattice_index(repo_root: Path) -> dict:
    lattice_dir = repo_root / "contracts/context_lattice"
    index = {}
    if not lattice_dir.exists():
        return index
    for file_path in iter_data_files(lattice_dir):
        data = load_data_file(file_path)
        if not isinstance(data, dict):
            continue
        version = data.get("version")
        if not version:
            raise ContextLatticeError(f"Lattice file missing version: {file_path}")
        if version in index:
            raise ContextLatticeError(f"Duplicate lattice version '{version}' in {file_path}")
        index[version] = {
            "path": file_path,
            "hash": sha256_data_file(file_path).replace("sha256:", ""),
        }
    return index


def load_safety_contracts(repo_root: Path) -> list:
    contracts = []
    for file_path in iter_data_files(repo_root / "contracts/safety_contracts"):
        try:
            data = load_data_file(file_path)
        except Exception:
            continue
        if isinstance(data, dict):
            contracts.append({"file": file_path, "data": data})
    return contracts


def extract_tolerances(contracts: list) -> list:
    tolerances = []
    for contract in contracts:
        for tol in contract["data"].get("tolerances", []) or []:
            if not isinstance(tol, dict):
                continue
            tolerances.append({
                "file": contract["file"],
                "hazard_id": tol.get("hazard_id"),
                "severity_id": tol.get("severity_id"),
                "context_class": tol.get("context_class"),
                "tau": tol.get("tau"),
            })
    return tolerances


def load_risk_fits(repo_root: Path) -> list:
    fits = []
    fits_dir = repo_root / "control_plane/governor/risk_fits"
    for file_path in iter_data_files(fits_dir):
        if file_path.suffix != ".json":
            continue
        try:
            data = load_data_file(file_path)
        except Exception:
            continue
        if isinstance(data, list):
            items = data
        else:
            items = [data]
        for fit in items:
            if not isinstance(fit, dict):
                continue
            fits.append({"file": file_path, "data": fit})
    return fits


def extract_plan_entries(data: object) -> list:
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        if "plans_by_context" in data:
            return data.get("plans_by_context") or []
        if "plans" in data:
            return data.get("plans") or []
        if "context_class" in data:
            return [data]
    return []


def load_oversight_plans(repo_root: Path) -> list:
    plans = []
    plans_dir = repo_root / "control_plane/governor/oversight_plans"
    for file_path in iter_data_files(plans_dir):
        try:
            data = load_data_file(file_path)
        except Exception:
            continue
        for entry in extract_plan_entries(data):
            if not isinstance(entry, dict):
                continue
            context_class = entry.get("context_class")
            if not context_class:
                continue
            channel_allocations = entry.get("channel_allocations") or {}
            plans.append({
                "file": file_path,
                "context_class": context_class,
                "plan_id": entry.get("plan_id"),
                "channel_allocations": channel_allocations,
            })
    return plans


def get_numeric(value, field_name: str, source: str) -> float:
    try:
        return float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid numeric '{field_name}' in {source}") from exc


def compute_fit_risk(fit: Mapping[str, Any], channel_allocations: dict | None) -> float:
    epsilon = fit.get("conservative_epsilon_high", fit.get("epsilon_high"))
    epsilon_value = get_numeric(epsilon, "conservative_epsilon_high", fit["file"])
    risk = epsilon_value

    if channel_allocations is None:
        return risk
    if not isinstance(channel_allocations, dict):
        raise ValueError(f"channel_allocations must be a dict in {fit['file']}")

    k_low_default = fit.get("conservative_k_low", fit.get("k_low"))
    k_low_by_channel = fit.get("k_low_by_channel") or {}

    for channel, allocation in channel_allocations.items():
        allocation_value = get_numeric(allocation, f"channel_allocations[{channel}]", fit["file"])
        if allocation_value <= 0:
            raise ValueError(f"channel_allocations[{channel}] must be > 0 in {fit['file']}")
        k_low = k_low_by_channel.get(channel, k_low_default)
        if k_low is None:
            continue
        risk += get_numeric(k_low, f"k_low[{channel}]", fit["file"]) / allocation_value

    return risk
