#!/usr/bin/env python3
import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from evoalign import provenance


class TestProvenance(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_canonical_bytes(self):
        payload = {"b": 1, "a": 2}
        self.assertEqual(provenance.canonical_bytes(payload), b"{\"a\":2,\"b\":1}")

    def test_canonical_bytes_invalid(self):
        with self.assertRaises(ValueError):
            provenance.canonical_bytes({"bad": {1, 2}})

    def test_sha256_canonical(self):
        value = {"a": 1}
        expected = hashlib.sha256(b"{\"a\":1}").hexdigest()
        self.assertEqual(provenance.sha256_canonical(value), f"sha256:{expected}")

    def test_sha256_file_and_load_data(self):
        data_path = self.test_dir / "data.txt"
        data_path.write_text("data")
        expected = hashlib.sha256(b"data").hexdigest()
        self.assertEqual(provenance.sha256_file(data_path), f"sha256:{expected}")

        json_path = self.test_dir / "data.json"
        json_path.write_text(json.dumps({"a": 1}))
        yaml_path = self.test_dir / "data.yaml"
        yaml_path.write_text("a: 1\n")

        self.assertEqual(provenance.load_data_file(json_path), {"a": 1})
        self.assertEqual(provenance.load_data_file(yaml_path), {"a": 1})

        expected_hash = provenance.sha256_canonical({"a": 1})
        self.assertEqual(provenance.sha256_data_file(json_path), expected_hash)
        self.assertEqual(provenance.sha256_data_file(yaml_path), expected_hash)

    def test_load_data_file_invalid_suffix(self):
        bad_path = self.test_dir / "data.txt"
        bad_path.write_text("data")
        with self.assertRaises(ValueError):
            provenance.load_data_file(bad_path)

    def test_normalize_and_verify(self):
        self.assertEqual(provenance.normalize_hash("sha256:abc"), "abc")
        self.assertEqual(provenance.normalize_hash(""), "")
        self.assertEqual(provenance.normalize_hash(None), "")

        self.assertTrue(provenance.verify_hash("sha256:abc", "abc"))
        self.assertFalse(provenance.verify_hash("sha256:abc", "sha256:def"))
        self.assertFalse(provenance.verify_hash(None, "sha256:abc"))

    def test_git_commit_exists(self):
        with mock.patch("subprocess.run") as mocked:
            mocked.return_value.returncode = 0
            self.assertTrue(provenance.git_commit_exists("HEAD", self.test_dir))
            mocked.return_value.returncode = 1
            self.assertFalse(provenance.git_commit_exists("HEAD", self.test_dir))

        with mock.patch("subprocess.run", side_effect=OSError):
            self.assertFalse(provenance.git_commit_exists("HEAD", self.test_dir))

        self.assertFalse(provenance.git_commit_exists(None, self.test_dir))


if __name__ == "__main__":
    unittest.main()
