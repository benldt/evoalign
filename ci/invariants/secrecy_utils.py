import hashlib
from pathlib import Path
from typing import Iterable

from evoalign.provenance import sha256_data_file, verify_hash
from evoalign.secrecy_fingerprints import SecrecyFingerprintError, load_hash_registry, scan_protected_paths

from file_utils import load_data_file


SUITE_REGISTRY_PATH = Path("control_plane/evals/suites/registry.json")
SECRET_HASH_REGISTRY_PATH = Path("control_plane/evals/suites/hash_registries/secret_suite_hashes_v1.json")


def load_suite_registry(repo_root: Path) -> tuple[dict, str]:
    registry_path = repo_root / SUITE_REGISTRY_PATH
    if not registry_path.exists():
        raise SecrecyFingerprintError("Suite registry not found")
    data = load_data_file(registry_path)
    if not isinstance(data, dict):
        raise SecrecyFingerprintError("Suite registry must be an object")
    return data, sha256_data_file(registry_path)


def get_secret_suites(registry: dict) -> dict[str, dict]:
    secret = {}
    for suite in registry.get("suites", []) or []:
        if isinstance(suite, dict) and suite.get("secrecy_level") == "secret":
            suite_id = suite.get("suite_id")
            if suite_id:
                secret[suite_id] = suite
    return secret


def load_secret_hash_registry(repo_root: Path) -> tuple[dict, object, str]:
    registry_path = repo_root / SECRET_HASH_REGISTRY_PATH
    data, scheme = load_hash_registry(registry_path)
    registry_hash = sha256_data_file(registry_path)
    return data, scheme, registry_hash


def compute_suite_fingerprint_root(fingerprints: Iterable[str]) -> str:
    payload = "\n".join(sorted(fingerprints)).encode("utf-8")
    digest = hashlib.sha256(payload).hexdigest()
    return f"sha256:{digest}"


def build_secret_fingerprint_index(secret_registry: dict) -> tuple[set[str], dict[str, set[str]]]:
    fingerprints: set[str] = set()
    index: dict[str, set[str]] = {}
    for suite in secret_registry.get("suites", []) or []:
        if not isinstance(suite, dict):
            continue
        suite_id = suite.get("suite_id")
        for fp in suite.get("test_case_fingerprints", []) or []:
            fingerprints.add(fp)
            if suite_id:
                index.setdefault(fp, set()).add(suite_id)
    return fingerprints, index


def build_secrecy_audit(
    repo_root: Path,
    protected_paths: Iterable[str] | None = None,
) -> dict:
    try:
        registry, registry_hash = load_suite_registry(repo_root)
    except SecrecyFingerprintError as exc:
        return {
            "status": "fail",
            "message": str(exc),
            "errors": [str(exc)],
        }

    secret_suites = get_secret_suites(registry)
    if not secret_suites:
        return {
            "status": "skip",
            "message": "No secret suites defined",
            "suite_registry_hash": registry_hash,
            "secret_suite_ids": [],
            "errors": [],
        }

    try:
        secret_registry, scheme, secret_registry_hash = load_secret_hash_registry(repo_root)
    except SecrecyFingerprintError as exc:
        return {
            "status": "fail",
            "message": str(exc),
            "suite_registry_hash": registry_hash,
            "secret_suite_ids": sorted(secret_suites.keys()),
            "errors": [str(exc)],
        }

    missing = sorted(set(secret_suites) - {s.get("suite_id") for s in secret_registry.get("suites", []) or []})
    errors: list[str] = []
    if not verify_hash(secret_registry.get("suite_registry_hash"), registry_hash):
        errors.append("suite_registry_hash mismatch")

    secret_fingerprints, fingerprint_index = build_secret_fingerprint_index(secret_registry)

    try:
        scan_result = scan_protected_paths(repo_root, scheme, protected_paths=protected_paths)
    except SecrecyFingerprintError as exc:
        return {
            "status": "fail",
            "message": str(exc),
            "suite_registry_hash": registry_hash,
            "secret_registry_hash": secret_registry_hash,
            "secret_suite_ids": sorted(secret_suites.keys()),
            "errors": [str(exc)],
        }

    errors.extend(scan_result.errors)

    leaks = []
    for fingerprint in sorted(secret_fingerprints & scan_result.fingerprints):
        leaks.append({
            "fingerprint": fingerprint,
            "suite_ids": sorted(fingerprint_index.get(fingerprint, [])),
            "files": sorted(scan_result.fingerprint_sources.get(fingerprint, [])),
        })

    status = "pass"
    message = "Secrecy hash check passed"
    if leaks or errors or missing:
        status = "fail"
        message = "Secrecy hash check failed"

    audit = {
        "status": status,
        "message": message,
        "suite_registry_hash": registry_hash,
        "secret_registry_hash": secret_registry_hash,
        "hashing_scheme": {
            "scheme_id": getattr(scheme, "scheme_id", None),
            "digest_prefix": getattr(scheme, "digest_prefix", None),
        },
        "secret_suite_ids": sorted(secret_suites.keys()),
        "missing_secret_suites": missing,
        "secret_fingerprint_count": len(secret_fingerprints),
        "scanned_fingerprint_count": len(scan_result.fingerprints),
        "scanned_files_count": len(scan_result.scanned_files),
        "leaks": leaks,
        "errors": errors,
    }

    return audit
