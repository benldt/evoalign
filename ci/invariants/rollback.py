import json

from base import InvariantCheck, InvariantChecker, InvariantResult


class RollbackInvariant(InvariantChecker):
    """
    Enforces: Every deployment config must specify a rollback target
    that has been certified.
    """

    def get_deployment_configs(self) -> list:
        configs = []
        deploy_path = self.repo_root / "deployments/"

        if not deploy_path.exists():
            return configs

        for config_file in deploy_path.rglob("*.json"):
            try:
                with open(config_file) as f:
                    config = json.load(f)
                    configs.append({
                        "file": str(config_file.relative_to(self.repo_root)),
                        "config": config,
                    })
            except (json.JSONDecodeError, IOError):
                continue

        return configs

    def validate_rollback(self, deployment: dict) -> tuple[bool, str]:
        config = deployment["config"]

        rollback = config.get("rollback", {})
        if not rollback:
            return False, "No rollback configuration"

        target = rollback.get("rollback_target")
        if not target:
            return False, "No rollback_target specified"

        if not rollback.get("rollback_target_certified"):
            return False, f"Rollback target {target} not certified"

        return True, "Valid"

    def check(self) -> InvariantCheck:
        configs = self.get_deployment_configs()

        if not configs:
            return InvariantCheck(
                name="ROLLBACK",
                result=InvariantResult.SKIP,
                message="No deployment configs found",
            )

        failures = []
        for config in configs:
            valid, reason = self.validate_rollback(config)
            if not valid:
                failures.append({
                    "file": config["file"],
                    "reason": reason,
                })

        if failures:
            return InvariantCheck(
                name="ROLLBACK",
                result=InvariantResult.FAIL,
                message=f"{len(failures)} deployment(s) missing certified rollback",
                details={"failures": failures},
            )

        return InvariantCheck(
            name="ROLLBACK",
            result=InvariantResult.PASS,
            message=f"Verified {len(configs)} deployment(s) have certified rollback",
        )
