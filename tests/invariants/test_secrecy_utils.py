#!/usr/bin/env python3
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "ci" / "invariants"))

from evoalign.provenance import sha256_data_file  # noqa: E402
from evoalign.secrecy_fingerprints import HashingScheme, SecrecyFingerprintError, fingerprint_item  # noqa: E402
from secrecy_utils import (  # noqa: E402
    build_secret_fingerprint_index,
    build_secrecy_audit,
    compute_suite_fingerprint_root,
    get_secret_suites,
    load_secret_hash_registry,
    load_suite_registry,
)


def write_json(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2))


class TestSecrecyUtils(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp())
        self.scheme = HashingScheme(
            scheme_id="sha256-v1",
            normalization="json_canonical_v1",
            digest_prefix="sha256:",
        )

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

    def _write_secret_registry(self, suite_registry_hash, suites, scheme=None):
        scheme_data = scheme or {
            "scheme_id": "sha256-v1",
            "normalization": "json_canonical_v1",
            "digest_prefix": "sha256:",
        }
        payload = {
            "registry_version": "1.0",
            "hashing_scheme": scheme_data,
            "generated_at": "2025-01-01T00:00:00Z",
            "suite_registry_hash": suite_registry_hash,
            "suites": suites,
        }
        path = self.test_dir / "control_plane/evals/suites/hash_registries/secret_suite_hashes_v1.json"
        write_json(path, payload)
        return path

    def test_load_suite_registry_missing(self):
        with self.assertRaises(SecrecyFingerprintError):
            load_suite_registry(self.test_dir)

    def test_load_suite_registry_invalid(self):
        path = self.test_dir / "control_plane/evals/suites/registry.json"
        write_json(path, [])
        with self.assertRaises(SecrecyFingerprintError):
            load_suite_registry(self.test_dir)

    def test_load_suite_registry_success(self):
        registry_hash = self._write_suite_registry([])
        registry, loaded_hash = load_suite_registry(self.test_dir)
        self.assertEqual(registry_hash, loaded_hash)
        self.assertIsInstance(registry, dict)

    def test_get_secret_suites(self):
        registry = {
            "suites": [
                {"suite_id": "secret1", "secrecy_level": "secret"},
                {"secrecy_level": "secret"},
                {"suite_id": "public", "secrecy_level": "public"},
                "bad",
            ]
        }
        secret = get_secret_suites(registry)
        self.assertEqual(list(secret), ["secret1"])

    def test_load_secret_hash_registry(self):
        registry_hash = self._write_suite_registry([])
        path = self._write_secret_registry(registry_hash, [])
        data, scheme, loaded_hash = load_secret_hash_registry(self.test_dir)
        self.assertEqual(data["registry_version"], "1.0")
        self.assertEqual(scheme.scheme_id, "sha256-v1")
        self.assertEqual(loaded_hash, sha256_data_file(path))

    def test_compute_suite_fingerprint_root(self):
        fps = ["sha256:b", "sha256:a"]
        root1 = compute_suite_fingerprint_root(fps)
        root2 = compute_suite_fingerprint_root(list(reversed(fps)))
        self.assertEqual(root1, root2)

    def test_build_secret_fingerprint_index(self):
        secret_registry = {
            "suites": [
                {
                    "suite_id": "suite1",
                    "test_case_fingerprints": ["sha256:a", "sha256:b"],
                },
                {"test_case_fingerprints": ["sha256:c"]},
                "bad",
            ]
        }
        fingerprints, index = build_secret_fingerprint_index(secret_registry)
        self.assertIn("sha256:a", fingerprints)
        self.assertIn("sha256:c", fingerprints)
        self.assertIn("suite1", index["sha256:a"])
        self.assertNotIn("sha256:c", index)

    def test_build_secrecy_audit_missing_registry(self):
        audit = build_secrecy_audit(self.test_dir)
        self.assertEqual(audit["status"], "fail")
        self.assertTrue(audit["errors"])

    def test_build_secrecy_audit_no_secret_suites(self):
        registry_hash = self._write_suite_registry([
            {"suite_id": "public", "secrecy_level": "public"}
        ])
        audit = build_secrecy_audit(self.test_dir)
        self.assertEqual(audit["status"], "skip")
        self.assertEqual(audit["suite_registry_hash"], registry_hash)

    def test_build_secrecy_audit_missing_secret_registry(self):
        self._write_suite_registry([
            {"suite_id": "secret", "secrecy_level": "secret"}
        ])
        audit = build_secrecy_audit(self.test_dir)
        self.assertEqual(audit["status"], "fail")
        self.assertTrue(audit["errors"])

    def test_build_secrecy_audit_mismatch_and_missing(self):
        self._write_suite_registry([
            {"suite_id": "secret", "secrecy_level": "secret"}
        ])
        self._write_secret_registry("sha256:bad", [])
        audit = build_secrecy_audit(self.test_dir)
        self.assertEqual(audit["status"], "fail")
        self.assertIn("secret", audit["missing_secret_suites"])
        self.assertIn("suite_registry_hash mismatch", audit["errors"])

    def test_build_secrecy_audit_leak(self):
        registry_hash = self._write_suite_registry([
            {"suite_id": "secret", "secrecy_level": "secret"}
        ])
        secret_item = {"prompt": "secret"}
        fingerprint = fingerprint_item(secret_item, self.scheme)
        suites = [{
            "suite_id": "secret",
            "suite_version": "1.0.0",
            "suite_fingerprint_root": compute_suite_fingerprint_root([fingerprint]),
            "n_test_cases": 1,
            "test_case_fingerprints": [fingerprint],
        }]
        self._write_secret_registry(registry_hash, suites)

        training_dir = self.test_dir / "training/data"
        training_dir.mkdir(parents=True)
        (training_dir / "leak.json").write_text(json.dumps([secret_item]))

        audit = build_secrecy_audit(self.test_dir, protected_paths=["training/data"])
        self.assertEqual(audit["status"], "fail")
        self.assertTrue(audit["leaks"])

    def test_build_secrecy_audit_scan_exception(self):
        registry_hash = self._write_suite_registry([
            {"suite_id": "secret", "secrecy_level": "secret"}
        ])
        suites = [{
            "suite_id": "secret",
            "suite_version": "1.0.0",
            "suite_fingerprint_root": "sha256:dead",
            "n_test_cases": 0,
            "test_case_fingerprints": [],
        }]
        self._write_secret_registry(registry_hash, suites)

        with mock.patch("secrecy_utils.scan_protected_paths", side_effect=SecrecyFingerprintError("boom")):
            audit = build_secrecy_audit(self.test_dir)
        self.assertEqual(audit["status"], "fail")
        self.assertIn("boom", audit["message"])

    def test_build_secrecy_audit_pass(self):
        registry_hash = self._write_suite_registry([
            {"suite_id": "secret", "secrecy_level": "secret"}
        ])
        fingerprint = fingerprint_item({"prompt": "secret"}, self.scheme)
        suites = [{
            "suite_id": "secret",
            "suite_version": "1.0.0",
            "suite_fingerprint_root": compute_suite_fingerprint_root([fingerprint]),
            "n_test_cases": 1,
            "test_case_fingerprints": [fingerprint],
        }]
        self._write_secret_registry(registry_hash, suites)

        training_dir = self.test_dir / "training/data"
        training_dir.mkdir(parents=True)
        (training_dir / "clean.json").write_text(json.dumps([{"prompt": "clean"}]))

        audit = build_secrecy_audit(self.test_dir, protected_paths=["training/data"])
        self.assertEqual(audit["status"], "pass")
        self.assertEqual(audit["leaks"], [])


if __name__ == "__main__":
    unittest.main()
