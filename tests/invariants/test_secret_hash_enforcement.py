#!/usr/bin/env python3
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from evoalign.secrecy_fingerprints import (
    HashingScheme,
    SecrecyFingerprintError,
    canonicalize_item,
    fingerprint_item,
    fingerprint_text_block,
    load_hash_registry,
    scan_file,
    scan_protected_paths,
)


class TestHashingScheme(unittest.TestCase):
    def test_from_dict_validation(self):
        with self.assertRaises(SecrecyFingerprintError):
            HashingScheme.from_dict("bad")
        with self.assertRaises(SecrecyFingerprintError):
            HashingScheme.from_dict({"scheme_id": "sha256-v1"})

        scheme = HashingScheme.from_dict({
            "scheme_id": "sha256-v1",
            "normalization": "json_canonical_v1",
            "digest_prefix": "sha256:",
        })
        self.assertFalse(scheme.uses_hmac())

        hmac_scheme = HashingScheme.from_dict({
            "scheme_id": "hmac-sha256-v1",
            "normalization": "json_canonical_v1",
            "digest_prefix": "hmacsha256:",
        })
        self.assertTrue(hmac_scheme.uses_hmac())


class TestFingerprinting(unittest.TestCase):
    def test_canonicalize_item(self):
        payload = {"b": 1, "a": 2}
        self.assertEqual(canonicalize_item(payload), b"{\"a\":2,\"b\":1}")
        with self.assertRaises(SecrecyFingerprintError):
            canonicalize_item({"bad": {1, 2}})

    def test_fingerprint_item_and_text(self):
        scheme = HashingScheme(
            scheme_id="sha256-v1",
            normalization="json_canonical_v1",
            digest_prefix="sha256:",
        )
        digest = fingerprint_item({"a": 1}, scheme)
        self.assertTrue(digest.startswith("sha256:"))

        self.assertIsNone(fingerprint_text_block("   ", scheme))
        text_digest = fingerprint_text_block("hello", scheme)
        self.assertTrue(text_digest.startswith("sha256:"))

    def test_hmac_key_resolution(self):
        scheme = HashingScheme(
            scheme_id="hmac-sha256-v1",
            normalization="json_canonical_v1",
            digest_prefix="hmacsha256:",
            key_id="github_actions_secret:TEST_HMAC_KEY",
        )
        os.environ["TEST_HMAC_KEY"] = "secret"
        digest = fingerprint_item({"a": 1}, scheme)
        self.assertTrue(digest.startswith("hmacsha256:"))
        os.environ.pop("TEST_HMAC_KEY", None)

        digest_override = fingerprint_item({"a": 1}, scheme, hmac_key=b"override")
        self.assertTrue(digest_override.startswith("hmacsha256:"))

        with self.assertRaises(SecrecyFingerprintError):
            fingerprint_item({"a": 1}, scheme)

        os.environ["HMAC_ENV"] = "secret"
        scheme_env = HashingScheme(
            scheme_id="hmac-sha256-v1",
            normalization="json_canonical_v1",
            digest_prefix="hmacsha256:",
            key_id="HMAC_ENV",
        )
        digest_env = fingerprint_item({"a": 1}, scheme_env)
        self.assertTrue(digest_env.startswith("hmacsha256:"))
        os.environ.pop("HMAC_ENV", None)


class TestRegistryLoading(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_load_hash_registry_errors(self):
        missing = self.test_dir / "missing.json"
        with self.assertRaises(SecrecyFingerprintError):
            load_hash_registry(missing)

        bad_path = self.test_dir / "bad.json"
        bad_path.write_text("[]")
        with self.assertRaises(SecrecyFingerprintError):
            load_hash_registry(bad_path)

        partial = self.test_dir / "partial.json"
        partial.write_text(json.dumps({"registry_version": "1.0"}))
        with self.assertRaises(SecrecyFingerprintError):
            load_hash_registry(partial)

    def test_load_hash_registry_success(self):
        registry = {
            "registry_version": "1.0",
            "hashing_scheme": {
                "scheme_id": "sha256-v1",
                "normalization": "json_canonical_v1",
                "digest_prefix": "sha256:",
            },
            "generated_at": "2025-01-01T00:00:00Z",
            "suite_registry_hash": "sha256:abc",
            "suites": [],
        }
        path = self.test_dir / "registry.json"
        path.write_text(json.dumps(registry))
        data, scheme = load_hash_registry(path)
        self.assertEqual(data["registry_version"], "1.0")
        self.assertEqual(scheme.scheme_id, "sha256-v1")


class TestScanning(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp())
        self.scheme = HashingScheme(
            scheme_id="sha256-v1",
            normalization="json_canonical_v1",
            digest_prefix="sha256:",
        )

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_scan_file_and_paths(self):
        training_dir = self.test_dir / "training/data"
        training_dir.mkdir(parents=True)

        list_items = [{"prompt": "alpha"}, {"prompt": "beta"}]
        (training_dir / "list.json").write_text(json.dumps(list_items))

        (training_dir / "items.yaml").write_text("items:\n  - one\n  - two\n")

        object_item = {"prompt": "gamma"}
        (training_dir / "object.json").write_text(json.dumps(object_item))

        (training_dir / "string.json").write_text(json.dumps("plain"))

        (training_dir / "null.json").write_text("null")

        (training_dir / "data.jsonl").write_text(
            "{\"prompt\": \"delta\"}\n\nnot json\n"
        )

        (training_dir / "notes.txt").write_text("para one\n\npara two\n")

        (training_dir / "skip.bin").write_bytes(b"skip")

        (training_dir / "bad.json").write_text("{bad json")

        (training_dir / "subdir").mkdir()

        scan_result = scan_protected_paths(
            self.test_dir,
            self.scheme,
            protected_paths=["missing", "training/data"],
        )

        expected = {
            fingerprint_item(list_items[0], self.scheme),
            fingerprint_item(list_items[1], self.scheme),
            fingerprint_item(object_item, self.scheme),
            fingerprint_text_block("plain", self.scheme),
            fingerprint_item({"prompt": "delta"}, self.scheme),
            fingerprint_text_block("not json", self.scheme),
            fingerprint_text_block("para one", self.scheme),
            fingerprint_text_block("para two", self.scheme),
            fingerprint_text_block("para one\n\npara two", self.scheme),
            fingerprint_text_block("one", self.scheme),
            fingerprint_text_block("two", self.scheme),
        }

        self.assertTrue(expected.issubset(scan_result.fingerprints))
        self.assertIn("training/data/list.json", scan_result.scanned_files)
        self.assertIn("training/data/data.jsonl", scan_result.scanned_files)
        self.assertTrue(scan_result.errors)

        unsupported = self.test_dir / "unsupported.bin"
        unsupported.write_bytes(b"skip")
        fingerprints, errors = scan_file(unsupported, self.scheme)
        self.assertEqual(fingerprints, [])
        self.assertEqual(errors, [])

        bad_file = training_dir / "broken.json"
        bad_file.write_text("{broken")
        fingerprints, errors = scan_file(bad_file, self.scheme)
        self.assertEqual(fingerprints, [])
        self.assertTrue(errors)

    def test_scan_text_blocks_empty_fingerprint(self):
        text_path = self.test_dir / "notes.txt"
        text_path.write_text("para one\n\npara two\n")
        with mock.patch("evoalign.secrecy_fingerprints.fingerprint_text_block", return_value=None):
            fingerprints, errors = scan_file(text_path, self.scheme)
        self.assertEqual(fingerprints, [])
        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
