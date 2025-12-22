#!/usr/bin/env python3
"""Tests for Runtime Config invariant."""
import json
import shutil
import tempfile
import unittest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "ci" / "invariants"))

from base import InvariantResult  # noqa: E402
from runtime_config import RuntimeConfigInvariant  # noqa: E402


def write_json(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2))


class TestRuntimeConfigInvariant(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def _write_config(self, name: str, payload: dict) -> Path:
        path = self.test_dir / "control_plane/runtime" / name
        write_json(path, payload)
        return path

    def _write_aar(self, aar_id: str, stability_controls: dict = None, operational_controls: dict = None) -> None:
        payload = {"aar_id": aar_id}
        if stability_controls:
            payload["stability_controls"] = stability_controls
        if operational_controls:
            payload["operational_controls"] = operational_controls
        write_json(self.test_dir / "aars" / f"{aar_id}.json", payload)

    def test_skip_no_configs(self):
        result = RuntimeConfigInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.SKIP)

    def test_pass_config_without_aar_ref(self):
        self._write_config("damping.json", {
            "config_version": "1.0",
            "update_policy": {"cadence": "monthly", "delta_max": 0.1, "n_min": 5},
        })
        result = RuntimeConfigInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.PASS)

    def test_fail_aar_reference_not_found(self):
        self._write_config("damping.json", {
            "config_version": "1.0",
            "update_policy": {"cadence": "monthly", "delta_max": 0.1, "n_min": 5},
            "aar_reference": "aar_missing",
        })
        result = RuntimeConfigInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_pass_damping_matches_aar(self):
        self._write_aar("aar_v1", stability_controls={
            "update_policy": {"cadence": "quarterly", "delta_max": 0.1, "n_min": 5}
        })
        self._write_config("damping.json", {
            "config_version": "1.0",
            "update_policy": {"cadence": "quarterly", "delta_max": 0.1, "n_min": 5},
            "aar_reference": "aar_v1",
        })
        result = RuntimeConfigInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.PASS)

    def test_fail_damping_delta_max_mismatch(self):
        self._write_aar("aar_v1", stability_controls={
            "update_policy": {"delta_max": 0.1}
        })
        self._write_config("damping.json", {
            "config_version": "1.0",
            "update_policy": {"delta_max": 0.2},
            "aar_reference": "aar_v1",
        })
        result = RuntimeConfigInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_fail_damping_n_min_mismatch(self):
        self._write_aar("aar_v1", stability_controls={
            "update_policy": {"n_min": 5}
        })
        self._write_config("damping.json", {
            "config_version": "1.0",
            "update_policy": {"n_min": 10},
            "aar_reference": "aar_v1",
        })
        result = RuntimeConfigInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_fail_damping_cadence_mismatch(self):
        self._write_aar("aar_v1", stability_controls={
            "update_policy": {"cadence": "quarterly"}
        })
        self._write_config("damping.json", {
            "config_version": "1.0",
            "update_policy": {"cadence": "monthly"},
            "aar_reference": "aar_v1",
        })
        result = RuntimeConfigInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_pass_monitoring_matches_aar(self):
        self._write_aar("aar_v1", operational_controls={
            "monitoring": {
                "metrics_collected": ["incident_rate"],
                "alerting_thresholds": [{"metric": "incident_rate", "threshold": 0.01}],
            }
        })
        self._write_config("monitoring.json", {
            "config_version": "1.0",
            "metrics": {"collected": ["incident_rate", "extra_metric"]},
            "alerting": {"thresholds": [{"metric": "incident_rate", "threshold": 0.01}]},
            "aar_reference": "aar_v1",
        })
        result = RuntimeConfigInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.PASS)

    def test_fail_monitoring_missing_metric(self):
        self._write_aar("aar_v1", operational_controls={
            "monitoring": {"metrics_collected": ["incident_rate", "jailbreak_rate"]}
        })
        self._write_config("monitoring.json", {
            "config_version": "1.0",
            "metrics": {"collected": ["incident_rate"]},
            "aar_reference": "aar_v1",
        })
        result = RuntimeConfigInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_fail_monitoring_missing_threshold(self):
        self._write_aar("aar_v1", operational_controls={
            "monitoring": {
                "alerting_thresholds": [{"metric": "incident_rate", "threshold": 0.01}]
            }
        })
        self._write_config("monitoring.json", {
            "config_version": "1.0",
            "alerting": {"thresholds": []},
            "aar_reference": "aar_v1",
        })
        result = RuntimeConfigInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_fail_monitoring_threshold_value_mismatch(self):
        self._write_aar("aar_v1", operational_controls={
            "monitoring": {
                "alerting_thresholds": [{"metric": "incident_rate", "threshold": 0.01}]
            }
        })
        self._write_config("monitoring.json", {
            "config_version": "1.0",
            "alerting": {"thresholds": [{"metric": "incident_rate", "threshold": 0.05}]},
            "aar_reference": "aar_v1",
        })
        result = RuntimeConfigInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_pass_empty_aar_claims(self):
        self._write_aar("aar_v1")  # No stability or operational claims
        self._write_config("damping.json", {
            "config_version": "1.0",
            "update_policy": {"cadence": "monthly", "delta_max": 0.5, "n_min": 10},
            "aar_reference": "aar_v1",
        })
        result = RuntimeConfigInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.PASS)

    def test_skip_non_dict_config(self):
        # Write a non-dict config - should be skipped
        path = self.test_dir / "control_plane/runtime" / "list.json"
        write_json(path, ["not", "a", "dict"])
        result = RuntimeConfigInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.SKIP)

    def test_skip_invalid_aar_threshold_entry(self):
        # AAR has invalid threshold entry (not a dict)
        self._write_aar("aar_v1", operational_controls={
            "monitoring": {
                "alerting_thresholds": ["not-a-dict", {"metric": "incident_rate", "threshold": 0.01}]
            }
        })
        self._write_config("monitoring.json", {
            "config_version": "1.0",
            "alerting": {"thresholds": [{"metric": "incident_rate", "threshold": 0.01}]},
            "aar_reference": "aar_v1",
        })
        result = RuntimeConfigInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.PASS)

    def test_skip_incomplete_aar_threshold(self):
        # AAR threshold without metric or threshold value
        self._write_aar("aar_v1", operational_controls={
            "monitoring": {
                "alerting_thresholds": [{"metric": "incident_rate"}]  # missing threshold
            }
        })
        self._write_config("monitoring.json", {
            "config_version": "1.0",
            "alerting": {"thresholds": [{"metric": "incident_rate", "threshold": 0.01}]},
            "aar_reference": "aar_v1",
        })
        result = RuntimeConfigInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.PASS)

    def test_skip_invalid_config_threshold_entry(self):
        # Config has invalid threshold entry (not a dict) - should skip it and keep searching
        self._write_aar("aar_v1", operational_controls={
            "monitoring": {
                "alerting_thresholds": [{"metric": "incident_rate", "threshold": 0.01}]
            }
        })
        self._write_config("monitoring.json", {
            "config_version": "1.0",
            "alerting": {"thresholds": [
                "not-a-dict",
                {"metric": "incident_rate", "threshold": 0.01}
            ]},
            "aar_reference": "aar_v1",
        })
        result = RuntimeConfigInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.PASS)


if __name__ == "__main__":
    unittest.main()

