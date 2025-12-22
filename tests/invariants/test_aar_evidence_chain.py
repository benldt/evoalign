#!/usr/bin/env python3
import json
import shutil
import tempfile
import unittest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "ci" / "invariants"))

from aar_evidence_chain import AarEvidenceChainInvariant  # noqa: E402
from base import InvariantResult  # noqa: E402
from evoalign.provenance import sha256_canonical, sha256_data_file  # noqa: E402


def write_json(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2))


class TestAarEvidenceChainInvariant(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def _write_contract(self) -> str:
        path = self.test_dir / "contracts/safety_contracts/contract.json"
        write_json(path, {"version": "0.1.0"})
        return sha256_data_file(path)

    def _write_secret_registry(self) -> str:
        path = self.test_dir / "control_plane/evals/suites/hash_registries/secret_suite_hashes_v1.json"
        write_json(path, {"registry_version": "1.0", "suites": []})
        return sha256_data_file(path)

    def _write_aar(self, name: str, payload: dict) -> Path:
        path = self.test_dir / "aars" / name
        write_json(path, payload)
        return path

    def test_skip_no_aars(self):
        result = AarEvidenceChainInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.SKIP)

    def test_pass_with_valid_hashes_and_previous(self):
        contract_hash = self._write_contract()
        secret_hash = self._write_secret_registry()

        aar_one = {
            "aar_id": "a1",
            "safety_contract": {"contract_hash": contract_hash},
            "reproducibility": {"secret_hash_registry_hash": secret_hash},
        }
        self._write_aar("aar_one.json", aar_one)
        previous_hash = sha256_canonical(aar_one)

        aar_two = {
            "aar_id": "a2",
            "safety_contract": {"contract_hash": contract_hash},
            "reproducibility": {"secret_hash_registry_hash": secret_hash},
            "provenance": {"previous_aar_hash": previous_hash},
        }
        self._write_aar("aar_two.json", aar_two)

        result = AarEvidenceChainInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.PASS)

    def test_fail_contract_missing(self):
        self._write_aar("aar.json", {
            "aar_id": "a1",
            "safety_contract": {"contract_hash": "sha256:missing"},
        })
        result = AarEvidenceChainInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_fail_contract_mismatch(self):
        self._write_contract()
        self._write_aar("aar.json", {
            "aar_id": "a1",
            "safety_contract": {"contract_hash": "sha256:bad"},
            "reproducibility": {"secret_hash_registry_hash": ""},
        })
        result = AarEvidenceChainInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_fail_secret_registry_missing(self):
        contract_hash = self._write_contract()
        self._write_aar("aar.json", {
            "aar_id": "a1",
            "safety_contract": {"contract_hash": contract_hash},
            "reproducibility": {"secret_hash_registry_hash": "sha256:missing"},
        })
        result = AarEvidenceChainInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_fail_secret_registry_mismatch(self):
        contract_hash = self._write_contract()
        self._write_secret_registry()
        self._write_aar("aar.json", {
            "aar_id": "a1",
            "safety_contract": {"contract_hash": contract_hash},
            "reproducibility": {"secret_hash_registry_hash": "sha256:bad"},
        })
        result = AarEvidenceChainInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_fail_previous_hash_missing(self):
        self._write_aar("aar.json", {
            "aar_id": "a1",
            "provenance": {"previous_aar_hash": "sha256:missing"},
        })
        result = AarEvidenceChainInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_optional_missing_claims(self):
        self._write_aar("aar.json", {"aar_id": "a1"})
        result = AarEvidenceChainInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.PASS)


if __name__ == "__main__":
    unittest.main()
