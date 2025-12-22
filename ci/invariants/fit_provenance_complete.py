from base import InvariantCheck, InvariantChecker, InvariantResult
from provenance_utils import load_risk_fits


class FitProvenanceCompleteInvariant(InvariantChecker):
    """Enforces: risk fit provenance fields are present and non-placeholder."""

    REQUIRED_FIELDS = [
        "provenance_version",
        "rfc_reference",
        "approvals",
        "fit_generator_commit",
        "eval_run_id",
        "eval_run_hash",
        "sweep_id",
        "sweep_hash",
        "suite_set_id",
        "suite_set_hash",
        "suite_registry_hash",
        "config_hash",
        "dataset_hashes",
        "random_seeds",
    ]

    PLACEHOLDERS = {"", "deadbeef", "0000000", "placeholder", "tbd"}

    def _is_placeholder(self, value) -> bool:
        if value is None:
            return True
        if isinstance(value, str):
            return value.strip().lower() in self.PLACEHOLDERS
        return False

    def check(self) -> InvariantCheck:
        fits = load_risk_fits(self.repo_root)
        if not fits:
            return InvariantCheck(
                name="FIT_PROVENANCE_COMPLETE",
                result=InvariantResult.SKIP,
                message="No risk fits found",
            )

        failures = []
        for fit in fits:
            fit_data = fit["data"]
            fit_id = fit_data.get("fit_id")
            provenance = fit_data.get("provenance")
            if not isinstance(provenance, dict):
                failures.append({
                    "fit_id": fit_id,
                    "file": str(fit["file"].relative_to(self.repo_root)),
                    "reason": "Missing provenance block",
                })
                continue

            for field in self.REQUIRED_FIELDS:
                value = provenance.get(field)
                if self._is_placeholder(value):
                    failures.append({
                        "fit_id": fit_id,
                        "file": str(fit["file"].relative_to(self.repo_root)),
                        "reason": f"Missing or placeholder '{field}'",
                    })

            dataset_hashes = provenance.get("dataset_hashes")
            if not isinstance(dataset_hashes, dict) or not dataset_hashes:
                failures.append({
                    "fit_id": fit_id,
                    "file": str(fit["file"].relative_to(self.repo_root)),
                    "reason": "dataset_hashes must be a non-empty object",
                })

            random_seeds = provenance.get("random_seeds")
            if not isinstance(random_seeds, list) or not random_seeds:
                failures.append({
                    "fit_id": fit_id,
                    "file": str(fit["file"].relative_to(self.repo_root)),
                    "reason": "random_seeds must be a non-empty array",
                })

            approvals = provenance.get("approvals")
            if not isinstance(approvals, list) or not approvals:
                failures.append({
                    "fit_id": fit_id,
                    "file": str(fit["file"].relative_to(self.repo_root)),
                    "reason": "approvals must be a non-empty array",
                })

        if failures:
            return InvariantCheck(
                name="FIT_PROVENANCE_COMPLETE",
                result=InvariantResult.FAIL,
                message=f"{len(failures)} fit provenance issue(s) detected",
                details={"failures": failures},
            )

        return InvariantCheck(
            name="FIT_PROVENANCE_COMPLETE",
            result=InvariantResult.PASS,
            message=f"Verified provenance completeness for {len(fits)} fit(s)",
        )
