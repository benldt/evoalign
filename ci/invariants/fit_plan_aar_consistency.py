from base import InvariantCheck, InvariantChecker, InvariantResult
from evoalign.provenance import git_commit_exists, sha256_data_file, verify_hash
from file_utils import iter_data_files
from provenance_utils import (
    compute_object_hash,
    load_aars,
    load_eval_runs,
    load_oversight_plan_files,
    load_registry,
    load_risk_fits,
    load_suite_sets,
    load_sweeps,
)


class FitPlanAarConsistencyInvariant(InvariantChecker):
    """Enforces: plans and AARs bind to fit hashes and provenance artifacts."""

    def _load_contract_hashes(self) -> list[str]:
        contracts_dir = self.repo_root / "contracts/safety_contracts"
        hashes = []
        for file_path in iter_data_files(contracts_dir):
            hashes.append(sha256_data_file(file_path))
        return hashes

    def _load_lattice_hashes(self) -> list[str]:
        lattice_dir = self.repo_root / "contracts/context_lattice"
        hashes = []
        for file_path in iter_data_files(lattice_dir):
            hashes.append(sha256_data_file(file_path))
        return hashes

    def check(self) -> InvariantCheck:
        fits = load_risk_fits(self.repo_root)
        plans = load_oversight_plan_files(self.repo_root)
        aars = load_aars(self.repo_root)

        if not plans:
            return InvariantCheck(
                name="FIT_PLAN_AAR_CONSISTENCY",
                result=InvariantResult.SKIP,
                message="No oversight plans found",
            )

        if not fits:
            return InvariantCheck(
                name="FIT_PLAN_AAR_CONSISTENCY",
                result=InvariantResult.FAIL,
                message="Oversight plans exist but no risk fits found",
            )

        failures = []
        fit_hashes = {}
        fit_provenances = {}
        for fit in fits:
            fit_data = fit["data"]
            fit_id = fit_data.get("fit_id")
            if not fit_id:
                continue
            fit_hash = compute_object_hash(fit_data)
            if fit_id in fit_hashes and fit_hashes[fit_id] != fit_hash:
                failures.append({
                    "fit_id": fit_id,
                    "file": str(fit["file"].relative_to(self.repo_root)),
                    "reason": "Duplicate fit_id with different hash",
                })
            fit_hashes[fit_id] = fit_hash
            fit_provenances.setdefault(fit_id, fit_data.get("provenance") or {})

        registry = load_registry(self.repo_root)
        registry_hash = registry["hash"] if registry else None
        contract_hashes = self._load_contract_hashes()
        lattice_hashes = self._load_lattice_hashes()

        plan_hashes = {}
        for plan in plans:
            plan_data = plan["data"]
            computed_refs = plan_data.get("computed_from_fit_hashes")
            if not isinstance(computed_refs, list) or not computed_refs:
                failures.append({
                    "file": str(plan["file"].relative_to(self.repo_root)),
                    "reason": "computed_from_fit_hashes missing or empty",
                })
            else:
                for entry in computed_refs:
                    if not isinstance(entry, dict):
                        failures.append({
                            "file": str(plan["file"].relative_to(self.repo_root)),
                            "reason": "computed_from_fit_hashes entry must be object",
                        })
                        continue
                    fit_id = entry.get("fit_id")
                    fit_hash = entry.get("fit_hash")
                    expected_hash = fit_hashes.get(fit_id)
                    if not expected_hash:
                        failures.append({
                            "file": str(plan["file"].relative_to(self.repo_root)),
                            "reason": f"Unknown fit_id in computed_from_fit_hashes: {fit_id}",
                        })
                        continue
                    if not verify_hash(fit_hash, expected_hash):
                        failures.append({
                            "file": str(plan["file"].relative_to(self.repo_root)),
                            "reason": f"fit_hash mismatch for {fit_id}",
                        })

            provenance = plan_data.get("provenance")
            if not isinstance(provenance, dict):
                failures.append({
                    "file": str(plan["file"].relative_to(self.repo_root)),
                    "reason": "Missing plan provenance",
                })
            else:
                governor_commit = provenance.get("governor_commit")
                if not git_commit_exists(governor_commit, self.repo_root):
                    failures.append({
                        "file": str(plan["file"].relative_to(self.repo_root)),
                        "reason": f"governor_commit not found: {governor_commit}",
                    })
                contract_hash = provenance.get("contract_hash")
                if contract_hashes and not any(verify_hash(contract_hash, h) for h in contract_hashes):
                    failures.append({
                        "file": str(plan["file"].relative_to(self.repo_root)),
                        "reason": "contract_hash does not match any Safety Contract",
                    })
                if registry_hash and not verify_hash(provenance.get("suite_registry_hash"), registry_hash):
                    failures.append({
                        "file": str(plan["file"].relative_to(self.repo_root)),
                        "reason": "suite_registry_hash mismatch",
                    })
                if lattice_hashes and not any(
                    verify_hash(provenance.get("context_lattice_hash"), h) for h in lattice_hashes
                ):
                    failures.append({
                        "file": str(plan["file"].relative_to(self.repo_root)),
                        "reason": "context_lattice_hash mismatch",
                    })

            plan_hash = compute_object_hash(plan_data)
            for entry in plan_data.get("plans_by_context", []) or []:
                if not isinstance(entry, dict):
                    continue
                plan_id = entry.get("plan_id")
                if plan_id:
                    plan_hashes[plan_id] = plan_hash

        if aars:
            sweeps = load_sweeps(self.repo_root)
            eval_runs = load_eval_runs(self.repo_root)
            suite_sets = load_suite_sets(self.repo_root)

            for aar in aars:
                data = aar["data"]
                repro = data.get("reproducibility", {})
                referenced_fit_ids = set()
                risk_fit_artifacts = data.get("risk_modeling", {}).get("risk_fit_artifacts")
                if not isinstance(risk_fit_artifacts, list):
                    failures.append({
                        "file": str(aar["file"].relative_to(self.repo_root)),
                        "reason": "risk_fit_artifacts missing or invalid",
                    })
                else:
                    for entry in risk_fit_artifacts:
                        if not isinstance(entry, dict):
                            failures.append({
                                "file": str(aar["file"].relative_to(self.repo_root)),
                                "reason": "risk_fit_artifacts entry must be object",
                            })
                            continue
                        fit_id = entry.get("fit_id")
                        fit_hash = entry.get("fit_hash")
                        expected_hash = fit_hashes.get(fit_id)
                        if not expected_hash:
                            failures.append({
                                "file": str(aar["file"].relative_to(self.repo_root)),
                                "reason": f"Unknown fit_id in AAR: {fit_id}",
                            })
                        elif not verify_hash(fit_hash, expected_hash):
                            failures.append({
                                "file": str(aar["file"].relative_to(self.repo_root)),
                                "reason": f"AAR fit_hash mismatch for {fit_id}",
                            })
                        else:
                            referenced_fit_ids.add(fit_id)

                        sweep = sweeps.get(entry.get("sweep_id"))
                        if not sweep or not verify_hash(entry.get("sweep_hash"), sweep["hash"]):
                            failures.append({
                                "file": str(aar["file"].relative_to(self.repo_root)),
                                "reason": "AAR sweep hash mismatch",
                            })

                        run = eval_runs.get(entry.get("eval_run_id"))
                        if not run or not verify_hash(entry.get("eval_run_hash"), run["hash"]):
                            failures.append({
                                "file": str(aar["file"].relative_to(self.repo_root)),
                                "reason": "AAR eval_run hash mismatch",
                            })

                if referenced_fit_ids:
                    fit_commits = set()
                    fit_configs = set()
                    for fit_id in referenced_fit_ids:
                        provenance = fit_provenances.get(fit_id) or {}
                        commit = provenance.get("fit_generator_commit")
                        if not commit:
                            failures.append({
                                "file": str(aar["file"].relative_to(self.repo_root)),
                                "reason": f"Missing fit_generator_commit for {fit_id} in AAR binding",
                            })
                        else:
                            fit_commits.add(commit)

                        config_hash = provenance.get("config_hash")
                        if not config_hash:
                            failures.append({
                                "file": str(aar["file"].relative_to(self.repo_root)),
                                "reason": f"Missing config_hash for {fit_id} in AAR binding",
                            })
                        else:
                            fit_configs.add(config_hash)

                    if len(fit_commits) > 1:
                        failures.append({
                            "file": str(aar["file"].relative_to(self.repo_root)),
                            "reason": "AAR references multiple fit_generator_commit values",
                        })
                    if len(fit_configs) > 1:
                        failures.append({
                            "file": str(aar["file"].relative_to(self.repo_root)),
                            "reason": "AAR references multiple fit config_hash values",
                        })

                    aar_commit = repro.get("code_commit")
                    if fit_commits and aar_commit not in fit_commits:
                        failures.append({
                            "file": str(aar["file"].relative_to(self.repo_root)),
                            "reason": "AAR code_commit does not match fit_generator_commit",
                        })

                    aar_config = repro.get("config_hash")
                    if fit_configs and not any(verify_hash(aar_config, cfg) for cfg in fit_configs):
                        failures.append({
                            "file": str(aar["file"].relative_to(self.repo_root)),
                            "reason": "AAR config_hash does not match fit config_hash",
                        })

                for entry in data.get("oversight_policy", {}).get("plans_by_context", []) or []:
                    if not isinstance(entry, dict):
                        continue
                    plan_id = entry.get("plan_id")
                    expected_hash = plan_hashes.get(plan_id)
                    if not expected_hash:
                        failures.append({
                            "file": str(aar["file"].relative_to(self.repo_root)),
                            "reason": f"Unknown plan_id in AAR: {plan_id}",
                        })
                        continue
                    if not verify_hash(entry.get("plan_hash"), expected_hash):
                        failures.append({
                            "file": str(aar["file"].relative_to(self.repo_root)),
                            "reason": f"AAR plan_hash mismatch for {plan_id}",
                        })

                if registry_hash and not verify_hash(repro.get("suite_registry_hash"), registry_hash):
                    failures.append({
                        "file": str(aar["file"].relative_to(self.repo_root)),
                        "reason": "AAR suite_registry_hash mismatch",
                    })
                if lattice_hashes and not any(
                    verify_hash(repro.get("context_lattice_hash"), h) for h in lattice_hashes
                ):
                    failures.append({
                        "file": str(aar["file"].relative_to(self.repo_root)),
                        "reason": "AAR context_lattice_hash mismatch",
                    })

                suite_set_hashes = repro.get("suite_set_hashes") or {}
                for suite_set_id, suite_set_hash in suite_set_hashes.items():
                    suite_set = suite_sets.get(suite_set_id)
                    if not suite_set or not verify_hash(suite_set_hash, suite_set["hash"]):
                        failures.append({
                            "file": str(aar["file"].relative_to(self.repo_root)),
                            "reason": f"AAR suite_set_hash mismatch for {suite_set_id}",
                        })

        if failures:
            return InvariantCheck(
                name="FIT_PLAN_AAR_CONSISTENCY",
                result=InvariantResult.FAIL,
                message=f"{len(failures)} fit/plan/AAR consistency issue(s) detected",
                details={"failures": failures},
            )

        return InvariantCheck(
            name="FIT_PLAN_AAR_CONSISTENCY",
            result=InvariantResult.PASS,
            message=f"Verified fit/plan consistency for {len(plans)} plan(s)",
        )
