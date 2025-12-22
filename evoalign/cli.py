#!/usr/bin/env python3
import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from evoalign.provenance import SUPPORTED_DATA_SUFFIXES, sha256_data_file, sha256_file


EVIDENCE_INVARIANTS = [
    "fit_provenance_complete.FitProvenanceCompleteInvariant",
    "fit_provenance_integrity.FitProvenanceIntegrityInvariant",
    "fit_plan_aar_consistency.FitPlanAarConsistencyInvariant",
    "aar_evidence_chain.AarEvidenceChainInvariant",
    "lineage_integrity.LineageIntegrityInvariant",
    "tamper_evidence.TamperEvidenceInvariant",
]


def compute_file_hash(file_path: Path) -> str:
    if file_path.suffix in SUPPORTED_DATA_SUFFIXES:
        return sha256_data_file(file_path)
    return sha256_file(file_path)


def load_template(template_path: Path | None, repo_root: Path) -> dict:
    candidate = template_path or (repo_root / "aars" / "aar_v0_1.json")
    if candidate.exists():
        with candidate.open() as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
        raise ValueError("Template must be a JSON object")
    return {}


def iso_timestamp() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def scaffold_aar(
    repo_root: Path,
    output_path: Path,
    previous_hash: str | None,
    template_path: Path | None,
    aar_id: str | None,
    release_id: str | None,
) -> dict:
    data = load_template(template_path, repo_root)

    if aar_id:
        data["aar_id"] = aar_id
    elif "aar_id" not in data:
        data["aar_id"] = output_path.stem

    if release_id:
        data["release_id"] = release_id

    data["generated_at"] = iso_timestamp()

    if previous_hash:
        provenance = data.get("provenance")
        if not isinstance(provenance, dict):
            provenance = {}
        provenance["previous_aar_hash"] = previous_hash
        data["provenance"] = provenance

    return data


def load_invariant_classes(invariants_root: Path | None = None) -> tuple[list[type], type]:
    invariants_root = invariants_root or (Path(__file__).resolve().parents[1] / "ci" / "invariants")
    if not invariants_root.exists():
        raise RuntimeError("Invariant modules not found")

    if str(invariants_root) not in sys.path:
        sys.path.insert(0, str(invariants_root))

    from base import InvariantResult  # noqa: E402

    invariant_classes = []
    for spec in EVIDENCE_INVARIANTS:
        module_name, class_name = spec.rsplit(".", 1)
        module = __import__(module_name, fromlist=[class_name])
        invariant_classes.append(getattr(module, class_name))

    return invariant_classes, InvariantResult


def run_evidence_chain(repo_root: Path, invariants_root: Path | None = None) -> tuple[list, bool]:
    invariants_root = invariants_root or (repo_root / "ci" / "invariants")
    invariant_classes, invariant_result = load_invariant_classes(invariants_root)
    results = []
    all_passed = True

    for invariant_class in invariant_classes:
        checker = invariant_class(repo_root)
        result = checker.check()
        results.append(result)
        if result.result == invariant_result.FAIL:
            all_passed = False

    return results, all_passed


def command_hash(file_path: Path) -> int:
    if not file_path.exists():
        print(f"Error: file not found: {file_path}", file=sys.stderr)
        return 1
    print(compute_file_hash(file_path))
    return 0


def command_verify_chain(repo_root: Path, invariants_root: Path | None = None) -> int:
    if not repo_root.exists():
        print(f"Error: repo root not found: {repo_root}", file=sys.stderr)
        return 1

    try:
        results, all_passed = run_evidence_chain(repo_root, invariants_root=invariants_root)
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    status_icon = {
        "PASS": "✓",
        "FAIL": "✗",
        "WARN": "⚠",
        "SKIP": "○",
    }

    for result in results:
        icon = status_icon.get(result.result.value, "?")
        print(f"{icon} {result.name}: {result.result.value}")
        print(f"  {result.message}")

    if all_passed:
        print("Evidence chain verification PASSED")
        return 0
    print("Evidence chain verification FAILED")
    return 1


def command_new_aar(
    repo_root: Path,
    output_path: Path,
    previous_hash: str | None,
    template_path: Path | None,
    aar_id: str | None,
    release_id: str | None,
) -> int:
    data = scaffold_aar(repo_root, output_path, previous_hash, template_path, aar_id, release_id)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(data, indent=2, sort_keys=True))
    print(f"Wrote AAR scaffold: {output_path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="evoalign", description="EvoAlign CLI tooling")
    subparsers = parser.add_subparsers(dest="command", required=True)

    hash_parser = subparsers.add_parser("hash", help="Compute canonical hash for a file")
    hash_parser.add_argument("file", type=Path)

    verify_parser = subparsers.add_parser("verify-chain", help="Run evidence chain checks")
    verify_parser.add_argument("--repo-root", type=Path, default=Path("."))

    new_aar = subparsers.add_parser("new-aar", help="Scaffold a new AAR file")
    new_aar.add_argument("--repo-root", type=Path, default=Path("."))
    new_aar.add_argument("--output", type=Path, default=None)
    new_aar.add_argument("--previous", type=str, default=None)
    new_aar.add_argument("--template", type=Path, default=None)
    new_aar.add_argument("--aar-id", type=str, default=None)
    new_aar.add_argument("--release-id", type=str, default=None)

    args = parser.parse_args(argv)

    if args.command == "hash":
        return command_hash(args.file)
    if args.command == "verify-chain":
        return command_verify_chain(args.repo_root.resolve())

    output_path = args.output
    if output_path is None:
        timestamp = iso_timestamp().replace(":", "").replace("-", "")
        output_path = args.repo_root / "aars" / f"aar_{timestamp}.json"
    return command_new_aar(
        args.repo_root.resolve(),
        output_path,
        args.previous,
        args.template,
        args.aar_id,
        args.release_id,
    )


if __name__ == "__main__":
    raise SystemExit(main())
