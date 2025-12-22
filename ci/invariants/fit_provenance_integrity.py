from base import InvariantCheck, InvariantChecker, InvariantResult
from evoalign.provenance import git_commit_exists, verify_hash
from provenance_utils import (
    load_dataset_manifests,
    load_eval_runs,
    load_registry,
    load_risk_fits,
    load_suite_sets,
    load_sweeps,
)


class FitProvenanceIntegrityInvariant(InvariantChecker):
    """Enforces: fit provenance references exist and hashes match manifests."""

    def check(self) -> InvariantCheck:
        fits = load_risk_fits(self.repo_root)
        if not fits:
            return InvariantCheck(
                name="FIT_PROVENANCE_INTEGRITY",
                result=InvariantResult.SKIP,
                message="No risk fits found",
            )

        registry = load_registry(self.repo_root)
        suite_sets = load_suite_sets(self.repo_root)
        datasets = load_dataset_manifests(self.repo_root)
        eval_runs = load_eval_runs(self.repo_root)
        sweeps = load_sweeps(self.repo_root)

        failures = []
        registry_suites = None
        registry_hash = None
        registry_missing = registry is None
        if registry:
            registry_suites = {suite.get("suite_id") for suite in registry["data"].get("suites", [])}
            registry_hash = registry["hash"]

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

            if registry_missing:
                failures.append({
                    "fit_id": fit_id,
                    "file": str(fit["file"].relative_to(self.repo_root)),
                    "reason": "Suite registry manifest missing",
                })

            commit = provenance.get("fit_generator_commit")
            if not git_commit_exists(commit, self.repo_root):
                failures.append({
                    "fit_id": fit_id,
                    "file": str(fit["file"].relative_to(self.repo_root)),
                    "reason": f"fit_generator_commit not found: {commit}",
                })

            eval_run_id = provenance.get("eval_run_id")
            eval_run = eval_runs.get(eval_run_id)
            if not eval_run:
                failures.append({
                    "fit_id": fit_id,
                    "file": str(fit["file"].relative_to(self.repo_root)),
                    "reason": f"Missing eval_run manifest '{eval_run_id}'",
                })
                continue

            if not verify_hash(provenance.get("eval_run_hash"), eval_run["hash"]):
                failures.append({
                    "fit_id": fit_id,
                    "file": str(fit["file"].relative_to(self.repo_root)),
                    "reason": "eval_run_hash mismatch",
                })

            sweep_id = provenance.get("sweep_id")
            sweep = sweeps.get(sweep_id)
            if not sweep:
                failures.append({
                    "fit_id": fit_id,
                    "file": str(fit["file"].relative_to(self.repo_root)),
                    "reason": f"Missing sweep manifest '{sweep_id}'",
                })
            else:
                if not verify_hash(provenance.get("sweep_hash"), sweep["hash"]):
                    failures.append({
                        "fit_id": fit_id,
                        "file": str(fit["file"].relative_to(self.repo_root)),
                        "reason": "sweep_hash mismatch",
                    })
                if sweep["data"].get("hazard_id") != fit_data.get("hazard_id"):
                    failures.append({
                        "fit_id": fit_id,
                        "file": str(fit["file"].relative_to(self.repo_root)),
                        "reason": "sweep hazard_id mismatch",
                    })
                if sweep["data"].get("severity_id") != fit_data.get("severity_id"):
                    failures.append({
                        "fit_id": fit_id,
                        "file": str(fit["file"].relative_to(self.repo_root)),
                        "reason": "sweep severity_id mismatch",
                    })
                if sweep["data"].get("context_class") != fit_data.get("context_class"):
                    failures.append({
                        "fit_id": fit_id,
                        "file": str(fit["file"].relative_to(self.repo_root)),
                        "reason": "sweep context_class mismatch",
                    })
                if eval_run_id not in (sweep["data"].get("eval_run_ids") or []):
                    failures.append({
                        "fit_id": fit_id,
                        "file": str(fit["file"].relative_to(self.repo_root)),
                        "reason": "sweep missing eval_run_id reference",
                    })
                sweep_hashes = sweep["data"].get("eval_run_hashes") or {}
                if eval_run_id and not verify_hash(eval_run["hash"], sweep_hashes.get(eval_run_id)):
                    failures.append({
                        "fit_id": fit_id,
                        "file": str(fit["file"].relative_to(self.repo_root)),
                        "reason": "sweep eval_run_hash mismatch",
                    })

            suite_set_id = provenance.get("suite_set_id")
            suite_set = suite_sets.get(suite_set_id)
            if not suite_set:
                failures.append({
                    "fit_id": fit_id,
                    "file": str(fit["file"].relative_to(self.repo_root)),
                    "reason": f"Missing suite_set manifest '{suite_set_id}'",
                })
            else:
                if not verify_hash(provenance.get("suite_set_hash"), suite_set["hash"]):
                    failures.append({
                        "fit_id": fit_id,
                        "file": str(fit["file"].relative_to(self.repo_root)),
                        "reason": "suite_set_hash mismatch",
                    })
                if registry_hash and not verify_hash(suite_set["data"].get("registry_hash"), registry_hash):
                    failures.append({
                        "fit_id": fit_id,
                        "file": str(fit["file"].relative_to(self.repo_root)),
                        "reason": "suite_set registry_hash mismatch",
                    })
                if registry_suites is not None:
                    suite_ids = set(suite_set["data"].get("suite_ids") or [])
                    if not suite_ids.issubset(registry_suites):
                        failures.append({
                            "fit_id": fit_id,
                            "file": str(fit["file"].relative_to(self.repo_root)),
                            "reason": "suite_set references unknown suite_id",
                        })

            if registry_hash and not verify_hash(provenance.get("suite_registry_hash"), registry_hash):
                failures.append({
                    "fit_id": fit_id,
                    "file": str(fit["file"].relative_to(self.repo_root)),
                    "reason": "suite_registry_hash mismatch",
                })

            eval_run_data = eval_run["data"]
            if eval_run_data.get("suite_set_id") != suite_set_id:
                failures.append({
                    "fit_id": fit_id,
                    "file": str(fit["file"].relative_to(self.repo_root)),
                    "reason": "eval_run suite_set_id mismatch",
                })
            if not verify_hash(provenance.get("suite_set_hash"), eval_run_data.get("suite_set_hash")):
                failures.append({
                    "fit_id": fit_id,
                    "file": str(fit["file"].relative_to(self.repo_root)),
                    "reason": "eval_run suite_set_hash mismatch",
                })
            if not verify_hash(provenance.get("config_hash"), eval_run_data.get("config_hash")):
                failures.append({
                    "fit_id": fit_id,
                    "file": str(fit["file"].relative_to(self.repo_root)),
                    "reason": "config_hash mismatch",
                })

            random_seeds = provenance.get("random_seeds") or []
            run_seeds = eval_run_data.get("random_seeds") or []
            if sorted(random_seeds) != sorted(run_seeds):
                failures.append({
                    "fit_id": fit_id,
                    "file": str(fit["file"].relative_to(self.repo_root)),
                    "reason": "random_seeds mismatch",
                })

            dataset_hashes = provenance.get("dataset_hashes") or {}
            run_dataset_hashes = eval_run_data.get("dataset_hashes") or {}
            for dataset_id, hash_value in dataset_hashes.items():
                manifest = datasets.get(dataset_id)
                if not manifest:
                    failures.append({
                        "fit_id": fit_id,
                        "file": str(fit["file"].relative_to(self.repo_root)),
                        "reason": f"Missing dataset manifest '{dataset_id}'",
                    })
                    continue
                dataset_hash = manifest["data"].get("dataset_hash")
                if not verify_hash(hash_value, dataset_hash):
                    failures.append({
                        "fit_id": fit_id,
                        "file": str(fit["file"].relative_to(self.repo_root)),
                        "reason": f"dataset_hash mismatch for '{dataset_id}'",
                    })
                if not verify_hash(hash_value, run_dataset_hashes.get(dataset_id)):
                    failures.append({
                        "fit_id": fit_id,
                        "file": str(fit["file"].relative_to(self.repo_root)),
                        "reason": f"eval_run dataset_hash mismatch for '{dataset_id}'",
                    })

        if failures:
            return InvariantCheck(
                name="FIT_PROVENANCE_INTEGRITY",
                result=InvariantResult.FAIL,
                message=f"{len(failures)} provenance integrity issue(s) detected",
                details={"failures": failures},
            )

        return InvariantCheck(
            name="FIT_PROVENANCE_INTEGRITY",
            result=InvariantResult.PASS,
            message=f"Verified provenance integrity for {len(fits)} fit(s)",
        )
