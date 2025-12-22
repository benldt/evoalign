#!/usr/bin/env python3
"""Tests for Tamper Evidence invariant."""
import json
import shutil
import tempfile
import unittest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "ci" / "invariants"))

from base import InvariantResult  # noqa: E402
from evoalign.merkle import compute_artifact_merkle_root, merkle_root  # noqa: E402
from evoalign.provenance import sha256_canonical  # noqa: E402
from tamper_evidence import (  # noqa: E402
    TamperEvidenceInvariant,
    load_key_registry,
    load_lineage_entry_hashes,
)


def write_json(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2))


class TestHelpers(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_load_key_registry_missing(self):
        result = load_key_registry(self.test_dir)
        self.assertIsNone(result)

    def test_load_key_registry_present(self):
        write_json(self.test_dir / "control_plane/keys/registry.json", {
            "registry_version": "1.0",
            "keys": [{"key_id": "k1", "role": "Lead"}],
        })
        result = load_key_registry(self.test_dir)
        self.assertIsNotNone(result)
        self.assertEqual(len(result["data"]["keys"]), 1)

    def test_load_key_registry_skips_non_key_files(self):
        # Write a file without "keys" field - should be skipped
        write_json(self.test_dir / "control_plane/keys/other.json", {"not_keys": []})
        result = load_key_registry(self.test_dir)
        self.assertIsNone(result)

    def test_load_lineage_entry_hashes_empty(self):
        result = load_lineage_entry_hashes(self.test_dir)
        self.assertEqual(result, [])

    def test_load_lineage_entry_hashes_with_entries(self):
        write_json(self.test_dir / "lineage/e1.json", {"entry_id": "e1"})
        write_json(self.test_dir / "lineage/e2.json", {"entry_id": "e2"})
        result = load_lineage_entry_hashes(self.test_dir)
        self.assertEqual(len(result), 2)

    def test_load_lineage_skips_non_dict(self):
        write_json(self.test_dir / "lineage/list.json", ["not", "dict"])
        result = load_lineage_entry_hashes(self.test_dir)
        self.assertEqual(result, [])


class TestTamperEvidenceInvariant(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def _write_aar(self, name: str, payload: dict) -> Path:
        path = self.test_dir / "aars" / name
        write_json(path, payload)
        return path

    def _write_key_registry(self, keys: list) -> None:
        write_json(self.test_dir / "control_plane/keys/registry.json", {
            "registry_version": "1.0",
            "keys": keys,
        })

    def _write_lineage_entry(self, name: str, payload: dict) -> None:
        write_json(self.test_dir / "lineage" / name, payload)

    def test_skip_no_aars_no_keys(self):
        result = TamperEvidenceInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.SKIP)

    def test_pass_aar_only(self):
        self._write_aar("aar.json", {"aar_id": "a1"})
        result = TamperEvidenceInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.PASS)

    def test_pass_key_registry_only(self):
        self._write_key_registry([{"key_id": "k1", "role": "Lead", "revoked": False}])
        result = TamperEvidenceInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.PASS)

    def test_pass_valid_merkle_root(self):
        artifacts = [
            {"fit_hash": "sha256:aaa"},
            {"fit_hash": "sha256:bbb"},
        ]
        computed_root = compute_artifact_merkle_root(artifacts, hash_field="fit_hash")

        self._write_aar("aar.json", {
            "aar_id": "a1",
            "provenance": {"merkle_root": computed_root},
            "risk_modeling": {"risk_fit_artifacts": artifacts},
        })
        result = TamperEvidenceInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.PASS)

    def test_fail_merkle_root_mismatch(self):
        artifacts = [{"fit_hash": "sha256:aaa"}]

        self._write_aar("aar.json", {
            "aar_id": "a1",
            "provenance": {"merkle_root": "sha256:wrongroot"},
            "risk_modeling": {"risk_fit_artifacts": artifacts},
        })
        result = TamperEvidenceInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_pass_valid_ledger_root(self):
        entry1 = {"entry_id": "e1"}
        entry2 = {"entry_id": "e2"}
        self._write_lineage_entry("e1.json", entry1)
        self._write_lineage_entry("e2.json", entry2)

        hashes = sorted([sha256_canonical(entry1), sha256_canonical(entry2)])
        computed_root = merkle_root(hashes)

        self._write_aar("aar.json", {
            "aar_id": "a1",
            "lineage_references": {"ledger_root_hash": computed_root, "lineage_ids": []},
        })
        result = TamperEvidenceInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.PASS)

    def test_fail_ledger_root_no_entries(self):
        self._write_aar("aar.json", {
            "aar_id": "a1",
            "lineage_references": {"ledger_root_hash": "sha256:claimed", "lineage_ids": []},
        })
        result = TamperEvidenceInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_fail_ledger_root_mismatch(self):
        self._write_lineage_entry("e1.json", {"entry_id": "e1"})

        self._write_aar("aar.json", {
            "aar_id": "a1",
            "lineage_references": {"ledger_root_hash": "sha256:wrongroot", "lineage_ids": []},
        })
        result = TamperEvidenceInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_fail_unknown_key_reference(self):
        self._write_key_registry([{"key_id": "valid-key", "role": "Lead", "revoked": False}])

        self._write_aar("aar.json", {
            "aar_id": "a1",
            "governance": {
                "approvals": [{"signature": "key:unknown-key"}],
            },
        })
        result = TamperEvidenceInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_pass_valid_key_reference(self):
        self._write_key_registry([{"key_id": "valid-key", "role": "Lead", "revoked": False}])

        self._write_aar("aar.json", {
            "aar_id": "a1",
            "governance": {
                "approvals": [{"signature": "key:valid-key"}],
            },
        })
        result = TamperEvidenceInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.PASS)

    def test_revoked_keys_excluded_from_validation(self):
        # Registry has both revoked and active keys
        self._write_key_registry([
            {"key_id": "revoked-key", "role": "Lead", "revoked": True},
            {"key_id": "active-key", "role": "Lead", "revoked": False},
        ])

        # Reference to revoked key should fail
        self._write_aar("aar.json", {
            "aar_id": "a1",
            "governance": {
                "approvals": [{"signature": "key:revoked-key"}],
            },
        })
        result = TamperEvidenceInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_non_key_signatures_ignored(self):
        self._write_key_registry([{"key_id": "k1", "role": "Lead", "revoked": False}])

        self._write_aar("aar.json", {
            "aar_id": "a1",
            "governance": {
                "approvals": [{"signature": "sig_regular_signature"}],
            },
        })
        result = TamperEvidenceInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.PASS)

    def test_invalid_approval_entry_skipped(self):
        self._write_key_registry([{"key_id": "k1", "role": "Lead", "revoked": False}])

        self._write_aar("aar.json", {
            "aar_id": "a1",
            "governance": {
                "approvals": ["not-a-dict", {"signature": "key:k1"}],
            },
        })
        result = TamperEvidenceInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.PASS)

    def test_key_without_key_id_ignored(self):
        # Key entry without key_id should not be added to key_ids set
        self._write_key_registry([
            {"role": "Lead", "revoked": False},  # no key_id
            {"key_id": "valid-key", "role": "Lead", "revoked": False},
        ])

        self._write_aar("aar.json", {
            "aar_id": "a1",
            "governance": {
                "approvals": [{"signature": "key:valid-key"}],
            },
        })
        result = TamperEvidenceInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.PASS)

    def test_merkle_root_no_artifacts(self):
        # AAR claims merkle_root but has no risk_fit_artifacts
        self._write_aar("aar.json", {
            "aar_id": "a1",
            "provenance": {"merkle_root": "sha256:claimed"},
            "risk_modeling": {"risk_fit_artifacts": []},
        })
        result = TamperEvidenceInvariant(self.test_dir).check()
        # Should pass because we can't verify without artifacts
        self.assertEqual(result.result, InvariantResult.PASS)


if __name__ == "__main__":
    unittest.main()

