# Tamper Evidence

This repo supports cryptographic tamper evidence via Merkle roots and optional signature verification.

## Merkle Trees (§12.3)

Merkle trees provide tamper-evident hashing for artifact collections.

### Utilities

The `evoalign/merkle.py` module provides:

| Function | Purpose |
|----------|---------|
| `merkle_root(leaves)` | Compute Merkle root from leaf hashes |
| `verify_merkle_inclusion(leaf, proof, root)` | Verify leaf inclusion with proof |
| `compute_artifact_merkle_root(artifacts, hash_field)` | Compute root from artifact dicts |

### AAR Provenance

AARs may include `provenance.merkle_root` computed from `risk_fit_artifacts`:

```json
{
  "provenance": {
    "merkle_root": "sha256:...",
    "previous_aar_hash": "sha256:..."
  },
  "risk_modeling": {
    "risk_fit_artifacts": [
      {"fit_id": "f1", "fit_hash": "sha256:aaa"},
      {"fit_id": "f2", "fit_hash": "sha256:bbb"}
    ]
  }
}
```

The `TAMPER_EVIDENCE` invariant verifies the merkle_root matches computed value.

### Ledger Root Hash

AARs may include `lineage_references.ledger_root_hash` for lineage integrity:

```json
{
  "lineage_references": {
    "lineage_ids": ["lin_v1"],
    "ledger_root_hash": "sha256:..."
  }
}
```

The invariant verifies this matches the Merkle root of all lineage entry hashes.

## Public Key Registry (§12.3)

Keys for signature verification are stored in `control_plane/keys/`.

### Schema

`PublicKeyRegistry.schema.json` defines:

```json
{
  "registry_version": "0.1.0",
  "keys": [
    {
      "key_id": "safety-lead-2025",
      "role": "Safety Lead",
      "algorithm": "ed25519",
      "public_key": "MCowBQYDK2VwAyEA...",
      "valid_from": "2025-01-01T00:00:00Z",
      "valid_until": "2026-01-01T00:00:00Z",
      "revoked": false
    }
  ]
}
```

### Supported Algorithms

- `ed25519` — EdDSA with Curve25519
- `rsa-sha256` — RSA with SHA-256
- `ecdsa-p256` — ECDSA with P-256 curve

### Key References

Signatures may reference keys using `key:KEY_ID` format:

```json
{
  "governance": {
    "approvals": [
      {"signature": "key:safety-lead-2025", "timestamp": "..."}
    ]
  }
}
```

The `TAMPER_EVIDENCE` invariant validates referenced keys exist and are not revoked.

## CI Enforcement

| Check | Behavior |
|-------|----------|
| `provenance.merkle_root` | If present, must match computed root |
| `ledger_root_hash` | If present, must match lineage entries |
| `key:KEY_ID` signatures | If key registry exists, key must be valid |

### Fail-Closed Semantics

- Merkle root mismatch → **FAIL**
- Ledger root claimed but no entries → **FAIL**
- Key reference to unknown/revoked key → **FAIL**
- Fields not present → **PASS** (optional-if-present)

## Signature Verification (Future)

Actual cryptographic signature verification is not yet implemented. The current invariant validates:

1. Key references point to valid, non-revoked keys
2. Keys have supported algorithms
3. Key validity periods are declared

Full signature verification requires runtime cryptographic libraries.

