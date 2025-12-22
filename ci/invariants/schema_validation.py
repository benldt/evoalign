#!/usr/bin/env python3
import argparse
import json
from dataclasses import dataclass
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator, ValidationError, validate

from base import InvariantCheck, InvariantChecker, InvariantResult
from file_utils import iter_data_files


@dataclass(frozen=True)
class SchemaTarget:
    path: str
    schema: str
    allow_yaml: bool = False
    single_file: bool = False
    match_prefix: str | None = None


SCHEMA_TARGETS = [
    SchemaTarget(
        path="contracts/safety_contracts",
        schema="SafetyContract.schema.json",
        allow_yaml=True,
    ),
    SchemaTarget(
        path="contracts/context_lattice",
        schema="ContextLattice.schema.json",
        allow_yaml=True,
    ),
    SchemaTarget(
        path="control_plane/governor/risk_fits",
        schema="RiskCurveFit.schema.json",
    ),
    SchemaTarget(
        path="control_plane/governor/oversight_plans",
        schema="OversightPlan.schema.json",
    ),
    SchemaTarget(
        path="control_plane/governor/sweeps",
        schema="RiskSweepManifest.schema.json",
    ),
    SchemaTarget(
        path="control_plane/evals/suites/registry.json",
        schema="SuiteRegistry.schema.json",
        single_file=True,
    ),
    SchemaTarget(
        path="control_plane/evals/suites/hash_registries",
        schema="SecretSuiteHashRegistry.schema.json",
    ),
    SchemaTarget(
        path="control_plane/evals/suites/sets",
        schema="SuiteSet.schema.json",
    ),
    SchemaTarget(
        path="control_plane/evals/runs",
        schema="EvalRunManifest.schema.json",
    ),
    SchemaTarget(
        path="control_plane/evals/datasets/manifests",
        schema="DatasetManifest.schema.json",
    ),
    SchemaTarget(
        path="control_plane/runtime",
        schema="DampingConfig.schema.json",
        match_prefix="damping",
    ),
    SchemaTarget(
        path="control_plane/runtime",
        schema="MonitoringConfig.schema.json",
        match_prefix="monitoring",
    ),
    SchemaTarget(
        path="control_plane/keys",
        schema="PublicKeyRegistry.schema.json",
    ),
    SchemaTarget(
        path="aars",
        schema="AAR.schema.json",
    ),
    SchemaTarget(
        path="lineage",
        schema="LineageLedgerEntry.schema.json",
    ),
    SchemaTarget(
        path="chronicle",
        schema="ChronicleEntry.schema.json",
    ),
]


def load_schema(schema_path: Path) -> dict:
    with schema_path.open() as f:
        return json.load(f)


def load_data_file(file_path: Path, allow_yaml: bool):
    if file_path.suffix == ".json":
        with file_path.open() as f:
            return json.load(f)
    if file_path.suffix in {".yaml", ".yml"}:
        if not allow_yaml:
            raise ValueError("YAML not allowed for this schema target")
        with file_path.open() as f:
            return yaml.safe_load(f)
    raise ValueError(f"Unsupported data file suffix: {file_path.suffix}")


def iter_target_files(repo_root: Path, target: SchemaTarget) -> list[Path]:
    data_path = repo_root / target.path
    if not data_path.exists():
        return []
    if target.single_file or data_path.is_file():
        return [data_path]
    files = []
    for file_path in iter_data_files(data_path):
        if file_path.suffix in {".yaml", ".yml"} and not target.allow_yaml:
            continue
        if target.match_prefix and not file_path.name.startswith(target.match_prefix):
            continue
        files.append(file_path)
    return sorted(files)


def validate_schema_files(repo_root: Path) -> list[dict]:
    schemas_dir = repo_root / "schemas"
    if not schemas_dir.exists():
        return [{
            "file": str(schemas_dir),
            "reason": "schemas directory missing",
        }]

    errors = []
    for schema_file in sorted(schemas_dir.glob("*.schema.json")):
        try:
            schema = load_schema(schema_file)
            Draft202012Validator.check_schema(schema)
        except Exception as exc:
            errors.append({
                "file": str(schema_file.relative_to(repo_root)),
                "reason": str(exc),
            })
    return errors


def validate_data_files(repo_root: Path) -> tuple[int, list[dict]]:
    errors = []
    validated = 0

    for target in SCHEMA_TARGETS:
        data_path = repo_root / target.path
        if not data_path.exists():
            continue

        schema_path = repo_root / "schemas" / target.schema
        if not schema_path.exists():
            errors.append({
                "file": str(data_path.relative_to(repo_root)),
                "reason": f"schema missing: {target.schema}",
            })
            continue

        schema = load_schema(schema_path)
        for file_path in iter_target_files(repo_root, target):
            try:
                data = load_data_file(file_path, target.allow_yaml)
                validate(instance=data, schema=schema)
                validated += 1
            except ValidationError as exc:
                errors.append({
                    "file": str(file_path.relative_to(repo_root)),
                    "reason": exc.message,
                })
            except Exception as exc:
                errors.append({
                    "file": str(file_path.relative_to(repo_root)),
                    "reason": str(exc),
                })

    return validated, errors


class SchemaValidationInvariant(InvariantChecker):
    """Enforces: artifacts validate against their declared schemas."""

    def check(self) -> InvariantCheck:
        schema_errors = validate_schema_files(self.repo_root)
        validated, data_errors = validate_data_files(self.repo_root)

        failures = schema_errors + data_errors
        if failures:
            return InvariantCheck(
                name="SCHEMA_VALIDATION",
                result=InvariantResult.FAIL,
                message=f"{len(failures)} schema validation issue(s) detected",
                details={"failures": failures},
            )

        if validated == 0:
            return InvariantCheck(
                name="SCHEMA_VALIDATION",
                result=InvariantResult.SKIP,
                message="No data files found for schema validation",
            )

        return InvariantCheck(
            name="SCHEMA_VALIDATION",
            result=InvariantResult.PASS,
            message=f"Validated {validated} data file(s) against schemas",
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate schema syntax and data files.")
    parser.add_argument("--repo-root", default=".", help="Repo root (default: .)")
    args = parser.parse_args(argv)

    repo_root = Path(args.repo_root).resolve()
    result = SchemaValidationInvariant(repo_root).check()

    print(f"{result.name}: {result.result.value}")
    print(f"{result.message}")
    if result.details and result.details.get("failures"):
        for entry in result.details["failures"][:10]:
            print(f"- {entry.get('file')}: {entry.get('reason')}")
        remaining = len(result.details["failures"]) - 10
        if remaining > 0:
            print(f"... and {remaining} more")

    return 1 if result.result == InvariantResult.FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
