"""Runtime Config Invariant: validates damping and monitoring configs match AAR claims."""

from base import InvariantCheck, InvariantChecker, InvariantResult
from file_utils import iter_data_files, load_data_file
from provenance_utils import load_aars


class RuntimeConfigInvariant(InvariantChecker):
    """Enforces: runtime configs are consistent with AAR claims."""

    def _load_runtime_configs(self) -> list[dict]:
        runtime_dir = self.repo_root / "control_plane/runtime"
        configs = []
        for file_path in iter_data_files(runtime_dir):
            data = load_data_file(file_path)
            if isinstance(data, dict):
                configs.append({"file": file_path, "data": data})
        return configs

    def _check_damping_consistency(self, config: dict, aar_data: dict, failures: list, file_path: str) -> None:
        aar_policy = (aar_data.get("stability_controls") or {}).get("update_policy") or {}
        config_policy = config.get("update_policy") or {}

        # Check delta_max
        aar_delta = aar_policy.get("delta_max")
        config_delta = config_policy.get("delta_max")
        if aar_delta is not None and config_delta is not None and aar_delta != config_delta:
            failures.append({
                "file": file_path,
                "reason": f"delta_max mismatch: AAR={aar_delta}, config={config_delta}",
            })

        # Check n_min
        aar_n_min = aar_policy.get("n_min")
        config_n_min = config_policy.get("n_min")
        if aar_n_min is not None and config_n_min is not None and aar_n_min != config_n_min:
            failures.append({
                "file": file_path,
                "reason": f"n_min mismatch: AAR={aar_n_min}, config={config_n_min}",
            })

        # Check cadence
        aar_cadence = aar_policy.get("cadence")
        config_cadence = config_policy.get("cadence")
        if aar_cadence and config_cadence and aar_cadence != config_cadence:
            failures.append({
                "file": file_path,
                "reason": f"cadence mismatch: AAR={aar_cadence}, config={config_cadence}",
            })

    def _check_monitoring_consistency(self, config: dict, aar_data: dict, failures: list, file_path: str) -> None:
        aar_monitoring = (aar_data.get("operational_controls") or {}).get("monitoring") or {}
        config_metrics = (config.get("metrics") or {}).get("collected") or []
        aar_metrics = aar_monitoring.get("metrics_collected") or []

        # Check metrics are superset of AAR claims
        if aar_metrics:
            missing = set(aar_metrics) - set(config_metrics)
            if missing:
                failures.append({
                    "file": file_path,
                    "reason": f"Config missing AAR-claimed metrics: {sorted(missing)}",
                })

        # Check alerting thresholds
        aar_thresholds = aar_monitoring.get("alerting_thresholds") or []
        config_thresholds = (config.get("alerting") or {}).get("thresholds") or []

        for aar_thresh in aar_thresholds:
            if not isinstance(aar_thresh, dict):
                continue
            metric = aar_thresh.get("metric")
            aar_value = aar_thresh.get("threshold")
            if not metric or aar_value is None:
                continue

            # Find matching config threshold
            config_match = None
            for ct in config_thresholds:
                if isinstance(ct, dict) and ct.get("metric") == metric:
                    config_match = ct
                    break

            if config_match is None:
                failures.append({
                    "file": file_path,
                    "reason": f"Config missing threshold for AAR-claimed metric: {metric}",
                })
            elif config_match.get("threshold") != aar_value:
                failures.append({
                    "file": file_path,
                    "reason": f"Threshold mismatch for {metric}: AAR={aar_value}, config={config_match.get('threshold')}",
                })

    def check(self) -> InvariantCheck:
        configs = self._load_runtime_configs()
        if not configs:
            return InvariantCheck(
                name="RUNTIME_CONFIG",
                result=InvariantResult.SKIP,
                message="No runtime configs found",
            )

        aars = load_aars(self.repo_root)
        aar_index = {aar["data"].get("aar_id"): aar["data"] for aar in aars if aar["data"].get("aar_id")}

        failures = []
        for config in configs:
            data = config["data"]
            file_path = str(config["file"].relative_to(self.repo_root))
            aar_ref = data.get("aar_reference")

            if aar_ref:
                if aar_ref not in aar_index:
                    failures.append({
                        "file": file_path,
                        "reason": f"aar_reference '{aar_ref}' not found",
                    })
                    continue

                aar_data = aar_index[aar_ref]

                # Determine config type and check consistency
                if "update_policy" in data:
                    self._check_damping_consistency(data, aar_data, failures, file_path)
                if "metrics" in data or "alerting" in data:
                    self._check_monitoring_consistency(data, aar_data, failures, file_path)

        if failures:
            return InvariantCheck(
                name="RUNTIME_CONFIG",
                result=InvariantResult.FAIL,
                message=f"{len(failures)} runtime config issue(s) detected",
                details={"failures": failures},
            )

        return InvariantCheck(
            name="RUNTIME_CONFIG",
            result=InvariantResult.PASS,
            message=f"Verified {len(configs)} runtime config(s)",
        )

