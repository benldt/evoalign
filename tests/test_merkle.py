#!/usr/bin/env python3
"""Tests for Merkle tree utilities."""
import unittest

from evoalign.merkle import (
    compute_artifact_merkle_root,
    merkle_root,
    sha256_bytes,
    sha256_str,
    verify_merkle_inclusion,
)


class TestMerkleBasics(unittest.TestCase):
    def test_sha256_bytes(self):
        result = sha256_bytes(b"hello")
        self.assertTrue(result.startswith("sha256:"))
        self.assertEqual(len(result), 7 + 64)  # prefix + hex

    def test_sha256_str(self):
        result = sha256_str("hello")
        self.assertTrue(result.startswith("sha256:"))
        # Should match sha256_bytes with utf-8 encoding
        self.assertEqual(result, sha256_bytes(b"hello"))

    def test_merkle_root_empty(self):
        result = merkle_root([])
        self.assertEqual(result, "")

    def test_merkle_root_single(self):
        leaf = "sha256:abc123"
        result = merkle_root([leaf])
        self.assertTrue(result.startswith("sha256:"))
        # Single leaf should be the root (after normalization)
        self.assertEqual(result, "sha256:abc123")

    def test_merkle_root_two_leaves(self):
        leaves = ["sha256:aaa", "sha256:bbb"]
        result = merkle_root(leaves)
        self.assertTrue(result.startswith("sha256:"))
        # Root should be hash of concatenated leaves
        self.assertNotEqual(result, leaves[0])
        self.assertNotEqual(result, leaves[1])

    def test_merkle_root_odd_leaves(self):
        leaves = ["sha256:aaa", "sha256:bbb", "sha256:ccc"]
        result = merkle_root(leaves)
        self.assertTrue(result.startswith("sha256:"))

    def test_merkle_root_deterministic(self):
        leaves = ["sha256:aaa", "sha256:bbb", "sha256:ccc", "sha256:ddd"]
        result1 = merkle_root(leaves)
        result2 = merkle_root(leaves)
        self.assertEqual(result1, result2)

    def test_merkle_root_order_matters(self):
        leaves1 = ["sha256:aaa", "sha256:bbb"]
        leaves2 = ["sha256:bbb", "sha256:aaa"]
        result1 = merkle_root(leaves1)
        result2 = merkle_root(leaves2)
        self.assertNotEqual(result1, result2)


class TestMerkleProof(unittest.TestCase):
    def test_verify_empty_leaf(self):
        result = verify_merkle_inclusion("", [], "sha256:root")
        self.assertFalse(result)

    def test_verify_empty_root(self):
        result = verify_merkle_inclusion("sha256:leaf", [], "")
        self.assertFalse(result)

    def test_verify_no_proof_single_leaf(self):
        # Single leaf tree: leaf IS the root
        leaf = "sha256:abc123"
        result = verify_merkle_inclusion(leaf, [], leaf)
        self.assertTrue(result)

    def test_verify_with_proof_left(self):
        # Build a simple 2-leaf tree and verify
        import hashlib
        left = "abc"
        right = "def"
        root_hash = hashlib.sha256((left + right).encode("utf-8")).hexdigest()

        proof = [{"hash": f"sha256:{right}", "position": "right"}]
        result = verify_merkle_inclusion(f"sha256:{left}", proof, f"sha256:{root_hash}")
        self.assertTrue(result)

    def test_verify_with_proof_right(self):
        import hashlib
        left = "abc"
        right = "def"
        root_hash = hashlib.sha256((left + right).encode("utf-8")).hexdigest()

        proof = [{"hash": f"sha256:{left}", "position": "left"}]
        result = verify_merkle_inclusion(f"sha256:{right}", proof, f"sha256:{root_hash}")
        self.assertTrue(result)

    def test_verify_invalid_position(self):
        proof = [{"hash": "sha256:abc", "position": "invalid"}]
        result = verify_merkle_inclusion("sha256:leaf", proof, "sha256:root")
        self.assertFalse(result)

    def test_verify_wrong_root(self):
        proof = [{"hash": "sha256:sibling", "position": "right"}]
        result = verify_merkle_inclusion("sha256:leaf", proof, "sha256:wrongroot")
        self.assertFalse(result)


class TestArtifactMerkleRoot(unittest.TestCase):
    def test_empty_artifacts(self):
        result = compute_artifact_merkle_root([])
        self.assertEqual(result, "")

    def test_artifacts_without_hash_field(self):
        artifacts = [{"id": "a1"}, {"id": "a2"}]
        result = compute_artifact_merkle_root(artifacts)
        self.assertEqual(result, "")

    def test_artifacts_with_hash_field(self):
        artifacts = [
            {"fit_hash": "sha256:aaa"},
            {"fit_hash": "sha256:bbb"},
        ]
        result = compute_artifact_merkle_root(artifacts, hash_field="fit_hash")
        self.assertTrue(result.startswith("sha256:"))

    def test_artifacts_sorted_deterministic(self):
        artifacts1 = [
            {"hash": "sha256:bbb"},
            {"hash": "sha256:aaa"},
        ]
        artifacts2 = [
            {"hash": "sha256:aaa"},
            {"hash": "sha256:bbb"},
        ]
        result1 = compute_artifact_merkle_root(artifacts1)
        result2 = compute_artifact_merkle_root(artifacts2)
        # Should be equal because artifacts are sorted
        self.assertEqual(result1, result2)

    def test_artifacts_mixed_valid_invalid(self):
        artifacts = [
            {"hash": "sha256:aaa"},
            {"no_hash": "missing"},
            {"hash": "sha256:bbb"},
        ]
        result = compute_artifact_merkle_root(artifacts)
        self.assertTrue(result.startswith("sha256:"))


if __name__ == "__main__":
    unittest.main()

