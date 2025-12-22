#!/usr/bin/env python3
"""
Tests for EvoAlign CI Invariant Checks
======================================
These tests verify that the invariant checkers correctly detect violations.
"""

import json
import os
import shutil
import stat
import tempfile
import unittest
from pathlib import Path

# Import the invariant checkers
import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "ci" / "invariants"))
from base import InvariantResult  # noqa: E402
from evoalign.provenance import sha256_data_file  # noqa: E402
from evoalign.secrecy_fingerprints import HashingScheme, fingerprint_item  # noqa: E402
from contract import ContractInvariant  # noqa: E402
from promotion import PromotionInvariant  # noqa: E402
from rollback import RollbackInvariant  # noqa: E402
from salvage import SalvageInvariant  # noqa: E402
from secrecy import SecrecyInvariant  # noqa: E402
from secrecy_utils import compute_suite_fingerprint_root  # noqa: E402


class TestSecrecyInvariant(unittest.TestCase):
    """Tests for the SECRECY invariant."""

    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def _write_suite_registry(self, suites):
        registry_path = self.test_dir / "control_plane/evals/suites/registry.json"
        registry_path.parent.mkdir(parents=True, exist_ok=True)
        registry_path.write_text(json.dumps({
            "registry_version": "0.2.0",
            "generated_at": "2025-01-01T00:00:00Z",
            "suites": suites,
        }))
        return registry_path

    def _write_secret_registry(self, suite_registry_hash, suites):
        registry_path = self.test_dir / "control_plane/evals/suites/hash_registries/secret_suite_hashes_v1.json"
        registry_path.parent.mkdir(parents=True, exist_ok=True)
        registry_path.write_text(json.dumps({
            "registry_version": "1.0",
            "hashing_scheme": {
                "scheme_id": "sha256-v1",
                "normalization": "json_canonical_v1",
                "digest_prefix": "sha256:",
            },
            "generated_at": "2025-01-01T00:00:00Z",
            "suite_registry_hash": suite_registry_hash,
            "suites": suites,
        }))
        return registry_path

    def test_missing_registry_fails(self):
        result = SecrecyInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_no_secret_suites_skips(self):
        self._write_suite_registry([{
            "suite_id": "suite_public_v1",
            "suite_type": "baseline",
            "suite_version": "1.0.0",
            "secrecy_level": "public",
            "n_test_cases": 1,
            "last_updated": "2025-01-01T00:00:00Z",
            "suite_hash": "sha256:abc",
        }])
        result = SecrecyInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.SKIP)

    def test_missing_secret_hash_registry_fails(self):
        self._write_suite_registry([{
            "suite_id": "suite_secret_v1",
            "suite_type": "adversarial",
            "suite_version": "1.0.0",
            "secrecy_level": "secret",
            "n_test_cases": 1,
            "last_updated": "2025-01-01T00:00:00Z",
            "suite_hash": "sha256:abc",
        }])
        result = SecrecyInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_detects_leak_in_training_data(self):
        suites = [{
            "suite_id": "suite_secret_v1",
            "suite_type": "adversarial",
            "suite_version": "1.0.0",
            "secrecy_level": "secret",
            "n_test_cases": 1,
            "last_updated": "2025-01-01T00:00:00Z",
            "suite_hash": "sha256:abc",
        }]
        registry_path = self._write_suite_registry(suites)
        suite_registry_hash = sha256_data_file(registry_path)

        scheme = HashingScheme(
            scheme_id="sha256-v1",
            normalization="json_canonical_v1",
            digest_prefix="sha256:",
        )
        secret_item = {"prompt": "secret_autonomy_case_1", "expected": "refuse"}
        secret_fp = fingerprint_item(secret_item, scheme)
        secret_root = compute_suite_fingerprint_root([secret_fp])
        suites_entry = [{
            "suite_id": "suite_secret_v1",
            "suite_version": "1.0.0",
            "suite_fingerprint_root": secret_root,
            "n_test_cases": 1,
            "test_case_fingerprints": [secret_fp],
        }]
        self._write_secret_registry(suite_registry_hash, suites_entry)

        training_dir = self.test_dir / "training/data"
        training_dir.mkdir(parents=True)
        (training_dir / "leaked.json").write_text(json.dumps([secret_item]))

        checker = SecrecyInvariant(self.test_dir)
        result = checker.check()
        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_passes_when_no_leak(self):
        suites = [{
            "suite_id": "suite_secret_v1",
            "suite_type": "adversarial",
            "suite_version": "1.0.0",
            "secrecy_level": "secret",
            "n_test_cases": 1,
            "last_updated": "2025-01-01T00:00:00Z",
            "suite_hash": "sha256:abc",
        }]
        registry_path = self._write_suite_registry(suites)
        suite_registry_hash = sha256_data_file(registry_path)

        scheme = HashingScheme(
            scheme_id="sha256-v1",
            normalization="json_canonical_v1",
            digest_prefix="sha256:",
        )
        secret_item = {"prompt": "secret_autonomy_case_1", "expected": "refuse"}
        secret_fp = fingerprint_item(secret_item, scheme)
        secret_root = compute_suite_fingerprint_root([secret_fp])
        suites_entry = [{
            "suite_id": "suite_secret_v1",
            "suite_version": "1.0.0",
            "suite_fingerprint_root": secret_root,
            "n_test_cases": 1,
            "test_case_fingerprints": [
                secret_fp
            ],
        }]
        self._write_secret_registry(suite_registry_hash, suites_entry)

        training_dir = self.test_dir / "training/data"
        training_dir.mkdir(parents=True)
        (training_dir / "clean.json").write_text(json.dumps([
            {"prompt": "clean_case", "expected": "allow"}
        ]))

        checker = SecrecyInvariant(self.test_dir)
        result = checker.check()
        self.assertEqual(result.result, InvariantResult.PASS)

    def test_scan_error_fails(self):
        suites = [{
            "suite_id": "suite_secret_v1",
            "suite_type": "adversarial",
            "suite_version": "1.0.0",
            "secrecy_level": "secret",
            "n_test_cases": 1,
            "last_updated": "2025-01-01T00:00:00Z",
            "suite_hash": "sha256:abc",
        }]
        registry_path = self._write_suite_registry(suites)
        suite_registry_hash = sha256_data_file(registry_path)

        scheme = HashingScheme(
            scheme_id="sha256-v1",
            normalization="json_canonical_v1",
            digest_prefix="sha256:",
        )
        secret_item = {"prompt": "secret_autonomy_case_1", "expected": "refuse"}
        secret_fp = fingerprint_item(secret_item, scheme)
        secret_root = compute_suite_fingerprint_root([secret_fp])
        suites_entry = [{
            "suite_id": "suite_secret_v1",
            "suite_version": "1.0.0",
            "suite_fingerprint_root": secret_root,
            "n_test_cases": 1,
            "test_case_fingerprints": [
                secret_fp
            ],
        }]
        self._write_secret_registry(suite_registry_hash, suites_entry)

        training_dir = self.test_dir / "training/data"
        training_dir.mkdir(parents=True)
        unreadable = training_dir / "unreadable.json"
        unreadable.write_text("secret")
        unreadable.chmod(0)

        try:
            checker = SecrecyInvariant(self.test_dir)
            result = checker.check()
            self.assertEqual(result.result, InvariantResult.FAIL)
        finally:
            unreadable.chmod(stat.S_IRUSR | stat.S_IWUSR)


class TestPromotionInvariant(unittest.TestCase):
    """Tests for the PROMOTION invariant."""
    
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp())
        
    def tearDown(self):
        shutil.rmtree(self.test_dir)
        
    def test_no_promotions_skips(self):
        """When no promotions exist, should skip."""
        checker = PromotionInvariant(self.test_dir)
        result = checker.check()
        self.assertEqual(result.result, InvariantResult.SKIP)
        
    def test_promotion_without_gates_fails(self):
        """Promotion without gates_passed should fail."""
        ledger_dir = self.test_dir / "control_plane/ledger"
        ledger_dir.mkdir(parents=True)
        
        (ledger_dir / "entry.json").write_text(json.dumps({
            "lineage_id": "L-2025-01-0001",
            "entry_type": "promotion",
            "timestamp": "2025-01-15T00:00:00Z",
            "status": "active",
            "training_config_hash": "sha256:abc",
            "contract_version": "0.4.0"
            # Missing gates_passed!
        }))
        
        checker = PromotionInvariant(self.test_dir)
        result = checker.check()
        
        self.assertEqual(result.result, InvariantResult.FAIL)
        
    def test_promotion_with_failed_tolerance_fails(self):
        """Promotion where tolerances not met should fail."""
        ledger_dir = self.test_dir / "control_plane/ledger"
        ledger_dir.mkdir(parents=True)
        
        (ledger_dir / "entry.json").write_text(json.dumps({
            "lineage_id": "L-2025-01-0001",
            "entry_type": "promotion",
            "timestamp": "2025-01-15T00:00:00Z",
            "status": "active",
            "training_config_hash": "sha256:abc",
            "contract_version": "0.4.0",
            "gates_passed": [{
                "suite_set_id": "core_v3",
                "result_hash": "sha256:def",
                "timestamp": "2025-01-14T00:00:00Z",
                "tolerances_met": False  # Failed!
            }]
        }))
        
        checker = PromotionInvariant(self.test_dir)
        result = checker.check()
        
        self.assertEqual(result.result, InvariantResult.FAIL)
        
    def test_valid_promotion_passes(self):
        """Valid promotion with gates should pass."""
        ledger_dir = self.test_dir / "control_plane/ledger"
        ledger_dir.mkdir(parents=True)
        
        (ledger_dir / "entry.json").write_text(json.dumps({
            "lineage_id": "L-2025-01-0001",
            "entry_type": "promotion",
            "timestamp": "2025-01-15T00:00:00Z",
            "status": "active",
            "training_config_hash": "sha256:abc",
            "contract_version": "0.4.0",
            "gates_passed": [{
                "suite_set_id": "core_v3",
                "result_hash": "sha256:def",
                "timestamp": "2025-01-14T00:00:00Z",
                "tolerances_met": True
            }]
        }))
        
        checker = PromotionInvariant(self.test_dir)
        result = checker.check()
        
        self.assertEqual(result.result, InvariantResult.PASS)

    def test_promotion_missing_suite_set_id_fails(self):
        ledger_dir = self.test_dir / "control_plane/ledger"
        ledger_dir.mkdir(parents=True)

        (ledger_dir / "entry.json").write_text(json.dumps({
            "lineage_id": "L-2025-01-0002",
            "entry_type": "promotion",
            "gates_passed": [{
                "result_hash": "sha256:def",
                "tolerances_met": True
            }]
        }))

        checker = PromotionInvariant(self.test_dir)
        result = checker.check()

        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_promotion_missing_result_hash_fails(self):
        ledger_dir = self.test_dir / "control_plane/ledger"
        ledger_dir.mkdir(parents=True)

        (ledger_dir / "entry.json").write_text(json.dumps({
            "lineage_id": "L-2025-01-0003",
            "entry_type": "promotion",
            "gates_passed": [{
                "suite_set_id": "core_v3",
                "tolerances_met": True
            }]
        }))

        checker = PromotionInvariant(self.test_dir)
        result = checker.check()

        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_high_risk_stage_missing_approval_fails(self):
        ledger_dir = self.test_dir / "control_plane/ledger"
        ledger_dir.mkdir(parents=True)

        (ledger_dir / "entry.json").write_text(json.dumps({
            "lineage_id": "L-2025-01-0004",
            "entry_type": "promotion",
            "stage": "full_autonomy",
            "gates_passed": [{
                "suite_set_id": "core_v3",
                "result_hash": "sha256:def",
                "tolerances_met": True
            }],
            "approvals": []
        }))

        checker = PromotionInvariant(self.test_dir)
        result = checker.check()

        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_high_risk_stage_with_approval_passes(self):
        ledger_dir = self.test_dir / "control_plane/ledger"
        ledger_dir.mkdir(parents=True)

        (ledger_dir / "entry.json").write_text(json.dumps({
            "lineage_id": "L-2025-01-0005",
            "entry_type": "promotion",
            "stage": "full_autonomy",
            "gates_passed": [{
                "suite_set_id": "core_v3",
                "result_hash": "sha256:def",
                "tolerances_met": True
            }],
            "approvals": [{
                "approved": True,
                "signature": "sig_ok"
            }]
        }))

        checker = PromotionInvariant(self.test_dir)
        result = checker.check()

        self.assertEqual(result.result, InvariantResult.PASS)

    def test_invalid_promotion_json_ignored(self):
        ledger_dir = self.test_dir / "control_plane/ledger"
        ledger_dir.mkdir(parents=True)
        (ledger_dir / "entry.json").write_text("{not-json")

        checker = PromotionInvariant(self.test_dir)
        result = checker.check()

        self.assertEqual(result.result, InvariantResult.SKIP)

    def test_non_promotion_entry_ignored(self):
        ledger_dir = self.test_dir / "control_plane/ledger"
        ledger_dir.mkdir(parents=True)
        (ledger_dir / "entry.json").write_text(json.dumps({
            "entry_type": "other",
            "lineage_id": "L-2025-01-0006"
        }))

        checker = PromotionInvariant(self.test_dir)
        result = checker.check()

        self.assertEqual(result.result, InvariantResult.SKIP)


class TestSalvageInvariant(unittest.TestCase):
    """Tests for the SALVAGE invariant."""
    
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp())
        
    def tearDown(self):
        shutil.rmtree(self.test_dir)
        
    def test_no_salvage_skips(self):
        """When no salvage used, should skip."""
        checker = SalvageInvariant(self.test_dir)
        result = checker.check()
        self.assertEqual(result.result, InvariantResult.SKIP)
        
    def test_uncertified_salvage_fails(self):
        """Using salvage without certification should fail."""
        deploy_dir = self.test_dir / "deployments"
        deploy_dir.mkdir(parents=True)
        
        (deploy_dir / "config.json").write_text(json.dumps({
            "model_id": "model_001",
            "salvage_artifact_id": "salvage_uncertified"
        }))
        
        checker = SalvageInvariant(self.test_dir)
        result = checker.check()
        
        self.assertEqual(result.result, InvariantResult.FAIL)
        
    def test_certified_salvage_passes(self):
        """Using properly certified salvage should pass."""
        # Create deployment config
        deploy_dir = self.test_dir / "deployments"
        deploy_dir.mkdir(parents=True)
        (deploy_dir / "config.json").write_text(json.dumps({
            "model_id": "model_001",
            "salvage_artifact_id": "salvage_certified"
        }))
        
        # Create ledger entry certifying the salvage
        ledger_dir = self.test_dir / "control_plane/ledger"
        ledger_dir.mkdir(parents=True)
        (ledger_dir / "salvage_entry.json").write_text(json.dumps({
            "lineage_id": "L-2025-01-0001",
            "entry_type": "salvage",
            "timestamp": "2025-01-15T00:00:00Z",
            "status": "retired",
            "training_config_hash": "sha256:abc",
            "contract_version": "0.4.0",
            "salvage_artifacts": [{
                "artifact_id": "salvage_certified",
                "artifact_type": "capability_dataset",
                "taint_tags": ["retired_for_H2_violation"],
                "quarantine_certified": True,
                "transfer_tests_passed": [
                    {"test_id": "transfer_H2_v1", "passed": True},
                    {"test_id": "transfer_rotation_v1", "passed": True}
                ]
            }]
        }))
        
        checker = SalvageInvariant(self.test_dir)
        result = checker.check()
        
        self.assertEqual(result.result, InvariantResult.PASS)

    def test_salvage_list_reference_fails(self):
        deploy_dir = self.test_dir / "deployments"
        deploy_dir.mkdir(parents=True)
        (deploy_dir / "config.json").write_text(json.dumps({
            "items": [
                {"salvage_artifacts": ["salvage_list"]}
            ]
        }))

        checker = SalvageInvariant(self.test_dir)
        result = checker.check()

        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_salvage_missing_quarantine_fails(self):
        deploy_dir = self.test_dir / "deployments"
        deploy_dir.mkdir(parents=True)
        (deploy_dir / "config.json").write_text(json.dumps({
            "model_id": "model_002",
            "salvage_artifact_id": "salvage_no_quarantine"
        }))

        ledger_dir = self.test_dir / "control_plane/ledger"
        ledger_dir.mkdir(parents=True)
        (ledger_dir / "entry.json").write_text(json.dumps({
            "salvage_artifacts": [{
                "artifact_id": "salvage_no_quarantine",
                "quarantine_certified": False,
                "transfer_tests_passed": [{"test_id": "t1", "passed": True}],
                "taint_tags": ["tag"]
            }]
        }))

        checker = SalvageInvariant(self.test_dir)
        result = checker.check()

        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_salvage_missing_tests_fails(self):
        deploy_dir = self.test_dir / "deployments"
        deploy_dir.mkdir(parents=True)
        (deploy_dir / "config.json").write_text(json.dumps({
            "model_id": "model_003",
            "salvage_artifact_id": "salvage_no_tests"
        }))

        ledger_dir = self.test_dir / "control_plane/ledger"
        ledger_dir.mkdir(parents=True)
        (ledger_dir / "entry.json").write_text(json.dumps({
            "salvage_artifacts": [{
                "artifact_id": "salvage_no_tests",
                "quarantine_certified": True,
                "transfer_tests_passed": [],
                "taint_tags": ["tag"]
            }]
        }))

        checker = SalvageInvariant(self.test_dir)
        result = checker.check()

        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_salvage_failed_tests_fails(self):
        deploy_dir = self.test_dir / "deployments"
        deploy_dir.mkdir(parents=True)
        (deploy_dir / "config.json").write_text(json.dumps({
            "model_id": "model_004",
            "salvage_artifact_id": "salvage_failed_tests"
        }))

        ledger_dir = self.test_dir / "control_plane/ledger"
        ledger_dir.mkdir(parents=True)
        (ledger_dir / "entry.json").write_text(json.dumps({
            "salvage_artifacts": [{
                "artifact_id": "salvage_failed_tests",
                "quarantine_certified": True,
                "transfer_tests_passed": [{"test_id": "t1", "passed": False}],
                "taint_tags": ["tag"]
            }]
        }))

        checker = SalvageInvariant(self.test_dir)
        result = checker.check()

        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_salvage_missing_taint_tags_fails(self):
        deploy_dir = self.test_dir / "deployments"
        deploy_dir.mkdir(parents=True)
        (deploy_dir / "config.json").write_text(json.dumps({
            "model_id": "model_005",
            "salvage_artifact_id": "salvage_no_tags"
        }))

        ledger_dir = self.test_dir / "control_plane/ledger"
        ledger_dir.mkdir(parents=True)
        (ledger_dir / "entry.json").write_text(json.dumps({
            "salvage_artifacts": [{
                "artifact_id": "salvage_no_tags",
                "quarantine_certified": True,
                "transfer_tests_passed": [{"test_id": "t1", "passed": True}],
                "taint_tags": []
            }]
        }))

        checker = SalvageInvariant(self.test_dir)
        result = checker.check()

        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_salvage_invalid_ledger_json_fails(self):
        deploy_dir = self.test_dir / "deployments"
        deploy_dir.mkdir(parents=True)
        (deploy_dir / "config.json").write_text(json.dumps({
            "model_id": "model_006",
            "salvage_artifact_id": "salvage_invalid_ledger"
        }))

        ledger_dir = self.test_dir / "control_plane/ledger"
        ledger_dir.mkdir(parents=True)
        (ledger_dir / "entry.json").write_text("{not-json")

        checker = SalvageInvariant(self.test_dir)
        result = checker.check()

        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_salvage_config_without_refs_skips(self):
        deploy_dir = self.test_dir / "deployments"
        deploy_dir.mkdir(parents=True)
        (deploy_dir / "config.json").write_text(json.dumps({
            "model_id": "model_007"
        }))

        checker = SalvageInvariant(self.test_dir)
        result = checker.check()

        self.assertEqual(result.result, InvariantResult.SKIP)

    def test_salvage_invalid_config_json_skips(self):
        deploy_dir = self.test_dir / "deployments"
        deploy_dir.mkdir(parents=True)
        (deploy_dir / "config.json").write_text("{not-json")

        checker = SalvageInvariant(self.test_dir)
        result = checker.check()

        self.assertEqual(result.result, InvariantResult.SKIP)

    def test_salvage_non_matching_ledger_entry_fails(self):
        deploy_dir = self.test_dir / "deployments"
        deploy_dir.mkdir(parents=True)
        (deploy_dir / "config.json").write_text(json.dumps({
            "model_id": "model_008",
            "salvage_artifact_id": "salvage_missing"
        }))

        ledger_dir = self.test_dir / "control_plane/ledger"
        ledger_dir.mkdir(parents=True)
        (ledger_dir / "entry.json").write_text(json.dumps({
            "salvage_artifacts": [{
                "artifact_id": "other",
                "quarantine_certified": True,
                "transfer_tests_passed": [{"test_id": "t1", "passed": True}],
                "taint_tags": ["tag"]
            }]
        }))

        checker = SalvageInvariant(self.test_dir)
        result = checker.check()

        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_salvage_empty_ledger_entries_fails(self):
        deploy_dir = self.test_dir / "deployments"
        deploy_dir.mkdir(parents=True)
        (deploy_dir / "config.json").write_text(json.dumps({
            "model_id": "model_009",
            "salvage_artifact_id": "salvage_empty_ledger"
        }))

        ledger_dir = self.test_dir / "control_plane/ledger"
        ledger_dir.mkdir(parents=True)
        (ledger_dir / "entry.json").write_text(json.dumps({
            "salvage_artifacts": []
        }))

        checker = SalvageInvariant(self.test_dir)
        result = checker.check()

        self.assertEqual(result.result, InvariantResult.FAIL)


class TestRollbackInvariant(unittest.TestCase):
    """Tests for the ROLLBACK invariant."""
    
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp())
        
    def tearDown(self):
        shutil.rmtree(self.test_dir)
        
    def test_no_deployments_skips(self):
        """When no deployments exist, should skip."""
        checker = RollbackInvariant(self.test_dir)
        result = checker.check()
        self.assertEqual(result.result, InvariantResult.SKIP)
        
    def test_missing_rollback_fails(self):
        """Deployment without rollback target should fail."""
        deploy_dir = self.test_dir / "deployments"
        deploy_dir.mkdir(parents=True)
        
        (deploy_dir / "config.json").write_text(json.dumps({
            "model_id": "model_001"
            # Missing rollback!
        }))
        
        checker = RollbackInvariant(self.test_dir)
        result = checker.check()
        
        self.assertEqual(result.result, InvariantResult.FAIL)
        
    def test_uncertified_rollback_fails(self):
        """Deployment with uncertified rollback target should fail."""
        deploy_dir = self.test_dir / "deployments"
        deploy_dir.mkdir(parents=True)
        
        (deploy_dir / "config.json").write_text(json.dumps({
            "model_id": "model_001",
            "rollback": {
                "rollback_target": "model_000",
                "rollback_target_certified": False  # Not certified!
            }
        }))
        
        checker = RollbackInvariant(self.test_dir)
        result = checker.check()
        
        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_missing_rollback_target_fails(self):
        deploy_dir = self.test_dir / "deployments"
        deploy_dir.mkdir(parents=True)

        (deploy_dir / "config.json").write_text(json.dumps({
            "model_id": "model_002",
            "rollback": {
                "rollback_target_certified": True
            }
        }))

        checker = RollbackInvariant(self.test_dir)
        result = checker.check()

        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_invalid_deployment_json_skips(self):
        deploy_dir = self.test_dir / "deployments"
        deploy_dir.mkdir(parents=True)
        (deploy_dir / "config.json").write_text("{not-json")

        checker = RollbackInvariant(self.test_dir)
        result = checker.check()

        self.assertEqual(result.result, InvariantResult.SKIP)
        
    def test_certified_rollback_passes(self):
        """Deployment with certified rollback should pass."""
        deploy_dir = self.test_dir / "deployments"
        deploy_dir.mkdir(parents=True)
        
        (deploy_dir / "config.json").write_text(json.dumps({
            "model_id": "model_001",
            "rollback": {
                "rollback_target": "model_000",
                "rollback_target_certified": True
            }
        }))
        
        checker = RollbackInvariant(self.test_dir)
        result = checker.check()
        
        self.assertEqual(result.result, InvariantResult.PASS)


class TestContractInvariant(unittest.TestCase):
    """Tests for the CONTRACT invariant."""
    
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp())
        
    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def _write_lattice(self, version: str = "0.1.0") -> tuple[Path, str]:
        lattice_dir = self.test_dir / "contracts/context_lattice"
        lattice_dir.mkdir(parents=True, exist_ok=True)
        lattice_path = lattice_dir / "context_lattice_v0_1.yaml"
        lattice_path.write_text(
            "\n".join([
                f"version: \"{version}\"",
                "dimensions:",
                "  tool_access:",
                "    type: set",
                "    atoms: [\"web\"]",
                "    top: \"*\"",
                "    bottom: []",
                "contexts:",
                "  any:",
                "    tool_access: \"*\"",
                "metadata:",
                "  created_at: \"2025-01-15T00:00:00Z\"",
                "  rfc_reference: \"RFC-CTX-0001\"",
                "  approvals:",
                "    - role: \"Technical Safety Lead\"",
                "      signature: \"sig_ctx\"",
                "      timestamp: \"2025-01-15T00:00:00Z\"",
            ])
        )
        lattice_hash = sha256_data_file(lattice_path).replace("sha256:", "")
        return lattice_path, lattice_hash
        
    def test_no_contracts_skips(self):
        """When no contracts exist, should skip."""
        checker = ContractInvariant(self.test_dir)
        result = checker.check()
        self.assertEqual(result.result, InvariantResult.SKIP)
        
    def test_contract_without_rfc_fails(self):
        """Contract without RFC reference should fail."""
        contract_dir = self.test_dir / "contracts/safety_contracts"
        contract_dir.mkdir(parents=True)
        
        (contract_dir / "contract.json").write_text(json.dumps({
            "version": "0.4.0",
            "metadata": {
                # Missing rfc_reference!
                "approvals": []
            }
        }))
        
        checker = ContractInvariant(self.test_dir)
        result = checker.check()
        
        self.assertEqual(result.result, InvariantResult.FAIL)
        
    def test_contract_without_signatures_fails(self):
        """Contract without signed approvals should fail."""
        contract_dir = self.test_dir / "contracts/safety_contracts"
        contract_dir.mkdir(parents=True)
        
        (contract_dir / "contract.json").write_text(json.dumps({
            "version": "0.4.0",
            "metadata": {
                "rfc_reference": "RFC-2025-001",
                "approvals": [
                    {"role": "Lead", "approved": True}
                    # Missing signature!
                ]
            }
        }))
        
        checker = ContractInvariant(self.test_dir)
        result = checker.check()
        
        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_contract_without_approvals_fails(self):
        self._write_lattice()
        contract_dir = self.test_dir / "contracts/safety_contracts"
        contract_dir.mkdir(parents=True)

        (contract_dir / "contract.json").write_text(json.dumps({
            "version": "0.4.0",
            "metadata": {
                "rfc_reference": "RFC-2025-001",
                "context_lattice_version": "0.1.0",
                "context_lattice_hash": "abc",
                "approvals": []
            }
        }))

        result = ContractInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_contract_missing_lattice_version_fails(self):
        self._write_lattice()
        contract_dir = self.test_dir / "contracts/safety_contracts"
        contract_dir.mkdir(parents=True)

        (contract_dir / "contract.json").write_text(json.dumps({
            "version": "0.4.0",
            "metadata": {
                "rfc_reference": "RFC-2025-001",
                "context_lattice_hash": "abc",
                "approvals": [{"role": "Lead", "signature": "sig"}]
            }
        }))

        result = ContractInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_contract_missing_lattice_hash_fails(self):
        self._write_lattice()
        contract_dir = self.test_dir / "contracts/safety_contracts"
        contract_dir.mkdir(parents=True)

        (contract_dir / "contract.json").write_text(json.dumps({
            "version": "0.4.0",
            "metadata": {
                "rfc_reference": "RFC-2025-001",
                "context_lattice_version": "0.1.0",
                "approvals": [{"role": "Lead", "signature": "sig"}]
            }
        }))

        result = ContractInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_contract_unknown_lattice_version_fails(self):
        self._write_lattice()
        contract_dir = self.test_dir / "contracts/safety_contracts"
        contract_dir.mkdir(parents=True)

        (contract_dir / "contract.json").write_text(json.dumps({
            "version": "0.4.0",
            "metadata": {
                "rfc_reference": "RFC-2025-001",
                "context_lattice_version": "9.9.9",
                "context_lattice_hash": "abc",
                "approvals": [{"role": "Lead", "signature": "sig"}]
            }
        }))

        result = ContractInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_contract_hash_mismatch_fails(self):
        self._write_lattice()
        contract_dir = self.test_dir / "contracts/safety_contracts"
        contract_dir.mkdir(parents=True)

        (contract_dir / "contract.json").write_text(json.dumps({
            "version": "0.4.0",
            "metadata": {
                "rfc_reference": "RFC-2025-001",
                "context_lattice_version": "0.1.0",
                "context_lattice_hash": "deadbeef",
                "approvals": [{"role": "Lead", "signature": "sig"}]
            }
        }))

        result = ContractInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_contract_without_lattice_registry_fails(self):
        contract_dir = self.test_dir / "contracts/safety_contracts"
        contract_dir.mkdir(parents=True)

        (contract_dir / "contract.json").write_text(json.dumps({
            "version": "0.4.0",
            "metadata": {
                "rfc_reference": "RFC-2025-001",
                "context_lattice_version": "0.1.0",
                "context_lattice_hash": "abc",
                "approvals": [{"role": "Lead", "signature": "sig"}]
            }
        }))

        result = ContractInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_contract_parse_error_fails(self):
        contract_dir = self.test_dir / "contracts/safety_contracts"
        contract_dir.mkdir(parents=True)
        (contract_dir / "contract.json").write_text("{not-json")

        result = ContractInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_contract_missing_file_fails(self):
        lattice_index = {}
        checker = ContractInvariant(self.test_dir)
        valid, reason = checker.validate_contract_change({"file": "missing.json"}, lattice_index)

        self.assertFalse(valid)
        self.assertEqual(reason, "Contract file not found")

    def test_contract_changes_filtering(self):
        contract_dir = self.test_dir / "contracts/safety_contracts"
        contract_dir.mkdir(parents=True)
        checker = ContractInvariant(self.test_dir)
        changes = checker.get_contract_changes(changed_files=[
            "contracts/safety_contracts/contract.yaml",
            "docs/readme.md",
        ])

        self.assertEqual(len(changes), 1)
        self.assertIn("contract.yaml", changes[0]["file"])

    def test_contract_lattice_index_missing_version_fails(self):
        lattice_dir = self.test_dir / "contracts/context_lattice"
        lattice_dir.mkdir(parents=True)
        (lattice_dir / "context_lattice.yaml").write_text("dimensions: {}")

        contract_dir = self.test_dir / "contracts/safety_contracts"
        contract_dir.mkdir(parents=True)
        (contract_dir / "contract.json").write_text(json.dumps({
            "version": "0.4.0",
            "metadata": {
                "rfc_reference": "RFC-2025-001",
                "context_lattice_version": "0.1.0",
                "context_lattice_hash": "abc",
                "approvals": [{"role": "Lead", "signature": "sig"}]
            }
        }))

        result = ContractInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.FAIL)
        
    def test_valid_contract_passes(self):
        """Contract with RFC and signatures should pass."""
        _, lattice_hash = self._write_lattice()

        contract_dir = self.test_dir / "contracts/safety_contracts"
        contract_dir.mkdir(parents=True)
        
        (contract_dir / "contract.json").write_text(json.dumps({
            "version": "0.4.0",
            "metadata": {
                "rfc_reference": "RFC-2025-001",
                "context_lattice_version": "0.1.0",
                "context_lattice_hash": lattice_hash,
                "approvals": [
                    {
                        "role": "Technical Safety Lead",
                        "approved": True,
                        "signature": "sig_abc123",
                        "timestamp": "2025-01-15T00:00:00Z"
                    }
                ]
            }
        }))
        
        checker = ContractInvariant(self.test_dir)
        result = checker.check()
        
        self.assertEqual(result.result, InvariantResult.PASS)

    def test_contract_hash_prefix_passes(self):
        _, lattice_hash = self._write_lattice()
        contract_dir = self.test_dir / "contracts/safety_contracts"
        contract_dir.mkdir(parents=True)

        (contract_dir / "contract.json").write_text(json.dumps({
            "version": "0.4.0",
            "metadata": {
                "rfc_reference": "RFC-2025-001",
                "context_lattice_version": "0.1.0",
                "context_lattice_hash": f"sha256:{lattice_hash}",
                "approvals": [
                    {
                        "role": "Technical Safety Lead",
                        "approved": True,
                        "signature": "sig_abc123",
                        "timestamp": "2025-01-15T00:00:00Z"
                    }
                ]
            }
        }))

        result = ContractInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.PASS)

    def test_yaml_contract_passes(self):
        _, lattice_hash = self._write_lattice()
        contract_dir = self.test_dir / "contracts/safety_contracts"
        contract_dir.mkdir(parents=True)
        (contract_dir / "contract.yaml").write_text("\n".join([
            "version: \"0.4.0\"",
            "metadata:",
            "  rfc_reference: \"RFC-2025-001\"",
            "  context_lattice_version: \"0.1.0\"",
            f"  context_lattice_hash: \"{lattice_hash}\"",
            "  approvals:",
            "    - role: \"Lead\"",
            "      signature: \"sig\"",
            "      timestamp: \"2025-01-15T00:00:00Z\"",
        ]))

        result = ContractInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.PASS)


if __name__ == "__main__":
    unittest.main()
