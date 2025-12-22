from base import InvariantCheck, InvariantChecker, InvariantResult
from evoalign.provenance import verify_hash
from evoalign.secrecy_fingerprints import SecrecyFingerprintError
from secrecy_utils import (
    compute_suite_fingerprint_root,
    get_secret_suites,
    load_secret_hash_registry,
    load_suite_registry,
)


class SecretRegistryIntegrityInvariant(InvariantChecker):
    """Enforces: secret hash registry is complete and consistent with suite registry."""

    SUPPORTED_SCHEMES = {"sha256-v1", "hmac-sha256-v1"}

    def check(self) -> InvariantCheck:
        try:
            suite_registry, suite_registry_hash = load_suite_registry(self.repo_root)
        except SecrecyFingerprintError as exc:
            return InvariantCheck(
                name="SECRET_REGISTRY_INTEGRITY",
                result=InvariantResult.FAIL,
                message=str(exc),
            )

        secret_suites = get_secret_suites(suite_registry)
        if not secret_suites:
            return InvariantCheck(
                name="SECRET_REGISTRY_INTEGRITY",
                result=InvariantResult.SKIP,
                message="No secret suites defined",
            )

        try:
            secret_registry, scheme, _ = load_secret_hash_registry(self.repo_root)
        except SecrecyFingerprintError as exc:
            return InvariantCheck(
                name="SECRET_REGISTRY_INTEGRITY",
                result=InvariantResult.FAIL,
                message=str(exc),
            )

        failures = []
        scheme_id = getattr(scheme, "scheme_id", None)
        if scheme_id not in self.SUPPORTED_SCHEMES:
            failures.append({
                "reason": f"Unsupported hashing scheme '{scheme_id}'",
            })

        registry_hash = secret_registry.get("suite_registry_hash")
        if not verify_hash(registry_hash, suite_registry_hash):
            failures.append({
                "reason": "suite_registry_hash mismatch",
                "expected": suite_registry_hash,
                "found": registry_hash,
            })

        secret_entries = {entry.get("suite_id"): entry for entry in secret_registry.get("suites", []) if isinstance(entry, dict)}
        for suite_id in secret_suites:
            if suite_id not in secret_entries:
                failures.append({
                    "suite_id": suite_id,
                    "reason": "Secret suite missing from hash registry",
                })

        for suite_id, entry in secret_entries.items():
            fingerprints = entry.get("test_case_fingerprints") or []
            if len(fingerprints) != len(set(fingerprints)):
                failures.append({
                    "suite_id": suite_id,
                    "reason": "Duplicate fingerprints in registry entry",
                })
            n_cases = entry.get("n_test_cases")
            if n_cases is not None and n_cases != len(fingerprints):
                failures.append({
                    "suite_id": suite_id,
                    "reason": "n_test_cases does not match fingerprint count",
                })
            expected_root = compute_suite_fingerprint_root(fingerprints)
            if entry.get("suite_fingerprint_root") != expected_root:
                failures.append({
                    "suite_id": suite_id,
                    "reason": "suite_fingerprint_root mismatch",
                })

        if failures:
            return InvariantCheck(
                name="SECRET_REGISTRY_INTEGRITY",
                result=InvariantResult.FAIL,
                message=f"{len(failures)} registry integrity issue(s) detected",
                details={"failures": failures},
            )

        return InvariantCheck(
            name="SECRET_REGISTRY_INTEGRITY",
            result=InvariantResult.PASS,
            message="Secret hash registry integrity verified",
        )
