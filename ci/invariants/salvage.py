import json

from base import InvariantCheck, InvariantChecker, InvariantResult


class SalvageInvariant(InvariantChecker):
    """
    Enforces: Salvage artifacts can only be used if:
    - Quarantine protocol was followed
    - Transfer tests passed and logged
    - Taint tracking is present
    """

    def get_salvage_usages(self) -> list:
        usages = []

        deploy_paths = [
            "deployments/",
            "releases/",
            "training/pipeline/",
        ]

        for path in deploy_paths:
            full_path = self.repo_root / path
            if not full_path.exists():
                continue

            for config_file in full_path.rglob("*.json"):
                try:
                    with open(config_file) as f:
                        config = json.load(f)
                        salvage_refs = self._find_salvage_refs(config)
                        if salvage_refs:
                            usages.append({
                                "file": str(config_file.relative_to(self.repo_root)),
                                "salvage_refs": salvage_refs,
                            })
                except (json.JSONDecodeError, IOError):
                    continue

        return usages

    def _find_salvage_refs(self, obj, path="") -> list:
        refs = []

        if isinstance(obj, dict):
            if "salvage_artifact_id" in obj or "salvage_artifacts" in obj:
                refs.append({
                    "path": path,
                    "artifact_ids": obj.get("salvage_artifact_id") or obj.get("salvage_artifacts"),
                })
            for k, v in obj.items():
                refs.extend(self._find_salvage_refs(v, f"{path}.{k}"))
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                refs.extend(self._find_salvage_refs(item, f"{path}[{i}]"))

        return refs

    def validate_salvage_usage(self, usage: dict) -> tuple[bool, str]:
        for ref in usage["salvage_refs"]:
            artifact_ids = ref["artifact_ids"]
            if isinstance(artifact_ids, str):
                artifact_ids = [artifact_ids]

            for artifact_id in artifact_ids:
                certified = self._check_salvage_certified(artifact_id)
                if not certified:
                    return False, (
                        f"Salvage artifact {artifact_id} not certified (transfer tests not passed or logged)"
                    )

        return True, "Valid"

    def _check_salvage_certified(self, artifact_id: str) -> bool:
        ledger_path = self.repo_root / "control_plane/ledger/"

        if not ledger_path.exists():
            return False

        for entry_file in ledger_path.rglob("*.json"):
            try:
                with open(entry_file) as f:
                    entry = json.load(f)
                    for salvage in entry.get("salvage_artifacts", []):
                        if salvage.get("artifact_id") == artifact_id:
                            if not salvage.get("quarantine_certified"):
                                return False
                            tests = salvage.get("transfer_tests_passed", [])
                            if not tests or not all(t.get("passed") for t in tests):
                                return False
                            if not salvage.get("taint_tags"):
                                return False
                            return True
            except (json.JSONDecodeError, IOError):
                continue

        return False

    def check(self) -> InvariantCheck:
        usages = self.get_salvage_usages()

        if not usages:
            return InvariantCheck(
                name="SALVAGE",
                result=InvariantResult.SKIP,
                message="No salvage artifacts in deployable configs",
            )

        failures = []
        for usage in usages:
            valid, reason = self.validate_salvage_usage(usage)
            if not valid:
                failures.append({
                    "file": usage["file"],
                    "reason": reason,
                })

        if failures:
            return InvariantCheck(
                name="SALVAGE",
                result=InvariantResult.FAIL,
                message=f"{len(failures)} uncertified salvage usage(s)",
                details={"failures": failures},
            )

        return InvariantCheck(
            name="SALVAGE",
            result=InvariantResult.PASS,
            message=f"Verified {len(usages)} salvage usage(s) properly certified",
        )
