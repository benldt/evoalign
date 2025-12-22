#!/usr/bin/env python3
import json
import shutil
import tempfile
import unittest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "ci" / "invariants"))

from base import InvariantResult  # noqa: E402
from evoalign.provenance import sha256_data_file  # noqa: E402
from secret_registry_integrity import SecretRegistryIntegrityInvariant  # noqa: E402
from secrecy_utils import compute_suite_fingerprint_root  # noqa: E402


def write_json(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2))


class TestSecretRegistryIntegrityInvariant(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def _write_suite_registry(self, suites):
        path = self.test_dir / "control_plane/evals/suites/registry.json"
        payload = {
            "registry_version": "0.2.0",
            "generated_at": "2025-01-01T00:00:00Z",
            "suites": suites,
        }
        write_json(path, payload)
        return sha256_data_file(path)

    def _write_secret_registry(self, suite_registry_hash, suites, scheme_id="sha256-v1"):
        path = self.test_dir / "control_plane/evals/suites/hash_registries/secret_suite_hashes_v1.json"
        payload = {
            "registry_version": "1.0",
            "hashing_scheme": {
                "scheme_id": scheme_id,
                "normalization": "json_canonical_v1",
                "digest_prefix": "sha256:",
            },
            "generated_at": "2025-01-01T00:00:00Z",
            "suite_registry_hash": suite_registry_hash,
            "suites": suites,
        }
        write_json(path, payload)

    def test_missing_suite_registry_fails(self):
        result = SecretRegistryIntegrityInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_no_secret_suites_skips(self):
        self._write_suite_registry([
            {"suite_id": "public", "secrecy_level": "public"}
        ])
        result = SecretRegistryIntegrityInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.SKIP)

    def test_missing_secret_registry_fails(self):
        self._write_suite_registry([
            {"suite_id": "secret", "secrecy_level": "secret"}
        ])
        result = SecretRegistryIntegrityInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_integrity_failures(self):
        self._write_suite_registry([
            {"suite_id": "secret", "secrecy_level": "secret"}
        ])
        fingerprints = ["sha256:a", "sha256:a"]
        suites = [{
            "suite_id": "other",
            "suite_version": "1.0.0",
            "suite_fingerprint_root": "sha256:bad",
            "n_test_cases": 3,
            "test_case_fingerprints": fingerprints,
        }]
        self._write_secret_registry("sha256:bad", suites, scheme_id="bad-scheme")

        result = SecretRegistryIntegrityInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.FAIL)
        failures = result.details.get("failures", [])
        reasons = {failure.get("reason") for failure in failures}
        self.assertIn("suite_registry_hash mismatch", reasons)
        self.assertIn("Duplicate fingerprints in registry entry", reasons)
        self.assertIn("suite_fingerprint_root mismatch", reasons)

    def test_pass(self):
        suite_registry_hash = self._write_suite_registry([
            {"suite_id": "secret", "secrecy_level": "secret"}
        ])
        fingerprints = ["sha256:a", "sha256:b"]
        suites = [{
            "suite_id": "secret",
            "suite_version": "1.0.0",
            "suite_fingerprint_root": compute_suite_fingerprint_root(fingerprints),
            "n_test_cases": len(fingerprints),
            "test_case_fingerprints": fingerprints,
        }]
        self._write_secret_registry(suite_registry_hash, suites)

        result = SecretRegistryIntegrityInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.PASS)


if __name__ == "__main__":
    unittest.main()
