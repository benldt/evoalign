#!/usr/bin/env python3
"""Tests for Lineage Integrity and Chronicle Governance invariants."""
import json
import shutil
import tempfile
import unittest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "ci" / "invariants"))

from base import InvariantResult  # noqa: E402
from chronicle_governance import ChronicleGovernanceInvariant  # noqa: E402
from lineage_integrity import LineageIntegrityInvariant  # noqa: E402


def write_json(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2))


class TestLineageIntegrityInvariant(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def _write_entry(self, name: str, payload: dict) -> Path:
        path = self.test_dir / "lineage" / name
        write_json(path, payload)
        return path

    def test_skip_no_entries(self):
        result = LineageIntegrityInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.SKIP)

    def test_pass_valid_entry(self):
        self._write_entry("entry_001.json", {
            "entry_id": "e1",
            "lineage_id": "lin_v1",
            "entry_type": "creation",
            "timestamp": "2025-01-01T00:00:00Z",
            "stage": "dev",
            "provenance": {
                "rfc_reference": "RFC-001",
                "approvals": [{"role": "Lead", "signature": "sig", "timestamp": "2025-01-01T00:00:00Z"}],
            },
        })
        result = LineageIntegrityInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.PASS)

    def test_fail_missing_provenance(self):
        self._write_entry("entry_001.json", {
            "entry_id": "e1",
            "lineage_id": "lin_v1",
            "entry_type": "creation",
        })
        result = LineageIntegrityInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_fail_missing_rfc(self):
        self._write_entry("entry_001.json", {
            "entry_id": "e1",
            "lineage_id": "lin_v1",
            "entry_type": "creation",
            "provenance": {"approvals": [{"role": "Lead", "signature": "sig", "timestamp": "2025-01-01T00:00:00Z"}]},
        })
        result = LineageIntegrityInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_fail_missing_approvals(self):
        self._write_entry("entry_001.json", {
            "entry_id": "e1",
            "lineage_id": "lin_v1",
            "entry_type": "creation",
            "provenance": {"rfc_reference": "RFC-001"},
        })
        result = LineageIntegrityInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_fail_promotion_missing_gate_evidence(self):
        self._write_entry("entry_001.json", {
            "entry_id": "e1",
            "lineage_id": "lin_v1",
            "entry_type": "promotion",
            "stage": "canary",
            "previous_stage": "dev",
            "provenance": {
                "rfc_reference": "RFC-001",
                "approvals": [{"role": "Lead", "signature": "sig", "timestamp": "2025-01-01T00:00:00Z"}],
            },
        })
        result = LineageIntegrityInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_pass_promotion_with_gate_evidence(self):
        self._write_entry("entry_001.json", {
            "entry_id": "e1",
            "lineage_id": "lin_v1",
            "entry_type": "promotion",
            "stage": "canary",
            "previous_stage": "dev",
            "gate_evidence": {"aar_id": "aar_v1", "aar_hash": "sha256:abc"},
            "provenance": {
                "rfc_reference": "RFC-001",
                "approvals": [{"role": "Lead", "signature": "sig", "timestamp": "2025-01-01T00:00:00Z"}],
            },
        })
        result = LineageIntegrityInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.PASS)

    def test_fail_previous_entry_hash_not_found(self):
        self._write_entry("entry_001.json", {
            "entry_id": "e1",
            "lineage_id": "lin_v1",
            "entry_type": "creation",
            "previous_entry_hash": "sha256:missing",
            "provenance": {
                "rfc_reference": "RFC-001",
                "approvals": [{"role": "Lead", "signature": "sig", "timestamp": "2025-01-01T00:00:00Z"}],
            },
        })
        result = LineageIntegrityInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_skip_non_dict_data(self):
        # Write a file that is not a dict (e.g., a list) - should be skipped
        path = self.test_dir / "lineage" / "entry_list.json"
        write_json(path, ["not", "a", "dict"])
        result = LineageIntegrityInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.SKIP)

    def test_pass_valid_chain(self):
        from evoalign.provenance import sha256_canonical
        entry1 = {
            "entry_id": "e1",
            "lineage_id": "lin_v1",
            "entry_type": "creation",
            "provenance": {
                "rfc_reference": "RFC-001",
                "approvals": [{"role": "Lead", "signature": "sig", "timestamp": "2025-01-01T00:00:00Z"}],
            },
        }
        self._write_entry("entry_001.json", entry1)
        entry1_hash = sha256_canonical(entry1)

        self._write_entry("entry_002.json", {
            "entry_id": "e2",
            "lineage_id": "lin_v1",
            "entry_type": "promotion",
            "gate_evidence": {"aar_id": "aar_v1"},
            "previous_entry_hash": entry1_hash,
            "provenance": {
                "rfc_reference": "RFC-001",
                "approvals": [{"role": "Lead", "signature": "sig", "timestamp": "2025-01-01T00:00:00Z"}],
            },
        })
        result = LineageIntegrityInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.PASS)


class TestChronicleGovernanceInvariant(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def _write_entry(self, name: str, payload: dict) -> Path:
        path = self.test_dir / "chronicle/events" / name
        write_json(path, payload)
        return path

    def _write_aar(self, aar_id: str) -> None:
        path = self.test_dir / "aars" / f"{aar_id}.json"
        write_json(path, {"aar_id": aar_id})

    def test_skip_no_entries(self):
        result = ChronicleGovernanceInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.SKIP)

    def test_pass_valid_entry(self):
        self._write_entry("event_001.json", {
            "entry_id": "c1",
            "event_type": "anomaly_detected",
            "release_id": "release_v1",
            "severity": "warning",
            "timestamp": "2025-01-01T00:00:00Z",
        })
        result = ChronicleGovernanceInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.PASS)

    def test_fail_missing_release_id(self):
        self._write_entry("event_001.json", {
            "entry_id": "c1",
            "event_type": "anomaly_detected",
            "severity": "warning",
        })
        result = ChronicleGovernanceInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_fail_missing_severity(self):
        self._write_entry("event_001.json", {
            "entry_id": "c1",
            "event_type": "anomaly_detected",
            "release_id": "release_v1",
        })
        result = ChronicleGovernanceInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_fail_critical_without_response(self):
        self._write_entry("event_001.json", {
            "entry_id": "c1",
            "event_type": "incident",
            "release_id": "release_v1",
            "severity": "critical",
        })
        result = ChronicleGovernanceInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_pass_critical_with_response(self):
        self._write_entry("event_001.json", {
            "entry_id": "c1",
            "event_type": "incident",
            "release_id": "release_v1",
            "severity": "critical",
            "response_actions": [{"action": "Rollback initiated"}],
        })
        result = ChronicleGovernanceInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.PASS)

    def test_fail_aar_reference_not_found(self):
        self._write_entry("event_001.json", {
            "entry_id": "c1",
            "event_type": "anomaly_detected",
            "release_id": "release_v1",
            "severity": "warning",
            "aar_reference": "aar_missing",
        })
        result = ChronicleGovernanceInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_pass_valid_aar_reference(self):
        self._write_aar("aar_v1")
        self._write_entry("event_001.json", {
            "entry_id": "c1",
            "event_type": "anomaly_detected",
            "release_id": "release_v1",
            "severity": "warning",
            "aar_reference": "aar_v1",
        })
        result = ChronicleGovernanceInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.PASS)

    def test_skip_non_dict_data(self):
        # Write a file that is not a dict (e.g., a list) - should be skipped
        path = self.test_dir / "chronicle/events" / "event_list.json"
        write_json(path, ["not", "a", "dict"])
        result = ChronicleGovernanceInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.SKIP)


if __name__ == "__main__":
    unittest.main()

