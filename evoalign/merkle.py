"""Merkle tree utilities for tamper-evident provenance."""

import hashlib
from typing import Sequence


def sha256_bytes(data: bytes) -> str:
    """Compute SHA-256 hash of bytes, return prefixed hex string."""
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def sha256_str(data: str) -> str:
    """Compute SHA-256 hash of UTF-8 string, return prefixed hex string."""
    return sha256_bytes(data.encode("utf-8"))


def merkle_root(leaves: Sequence[str]) -> str:
    """
    Compute Merkle root from a sequence of leaf hashes.

    Leaves should be prefixed hashes (e.g., "sha256:abc...").
    Returns prefixed hash of root, or empty string if no leaves.
    """
    if not leaves:
        return ""

    # Normalize: strip prefix for internal computation
    def normalize(h: str) -> str:
        return h.replace("sha256:", "")

    current_level = [normalize(leaf) for leaf in leaves]

    while len(current_level) > 1:
        next_level = []
        for i in range(0, len(current_level), 2):
            left = current_level[i]
            # If odd number of nodes, duplicate the last one
            right = current_level[i + 1] if i + 1 < len(current_level) else left
            combined = left + right
            parent = hashlib.sha256(combined.encode("utf-8")).hexdigest()
            next_level.append(parent)
        current_level = next_level

    return f"sha256:{current_level[0]}"


def verify_merkle_inclusion(leaf: str, proof: list[dict], root: str) -> bool:
    """
    Verify a leaf is included in a Merkle tree given a proof.

    Proof format: [{"hash": "sha256:...", "position": "left"|"right"}, ...]
    Returns True if leaf + proof reconstructs the root.
    """
    if not leaf or not root:
        return False

    def normalize(h: str) -> str:
        return h.replace("sha256:", "")

    current = normalize(leaf)

    for step in proof:
        sibling = normalize(step.get("hash", ""))
        position = step.get("position", "")

        if position == "left":
            combined = sibling + current
        elif position == "right":
            combined = current + sibling
        else:
            return False

        current = hashlib.sha256(combined.encode("utf-8")).hexdigest()

    return f"sha256:{current}" == root


def compute_artifact_merkle_root(artifacts: Sequence[dict], hash_field: str = "hash") -> str:
    """
    Compute Merkle root from a sequence of artifact dicts.

    Each artifact should have a hash field (default: "hash").
    Artifacts are sorted by hash for deterministic ordering.
    """
    hashes = []
    for artifact in artifacts:
        h = artifact.get(hash_field)
        if h:
            hashes.append(h)

    if not hashes:
        return ""

    # Sort for deterministic ordering
    hashes.sort()
    return merkle_root(hashes)

