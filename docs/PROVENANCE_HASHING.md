# Provenance Hashing Standard

This repo uses canonical hashing so provenance is stable and verifiable.

## Canonical JSON

- Serialize with: `json.dumps(obj, sort_keys=True, separators=(",", ":"))`.
- Encode as UTF-8 bytes.
- Hash with SHA-256.
- Represent as: `sha256:<hex>`.

## YAML

- Load YAML into a native object.
- Canonicalize using the JSON rules above.
- Hash with SHA-256 and prefix with `sha256:`.

## Files

- For binary or opaque files, hash raw bytes with SHA-256.
- Represent as: `sha256:<hex>`.

## Manifests

- All manifest hashes in provenance should use the canonical JSON hash.
- Fit, plan, and AAR hashes should be computed from their canonical JSON payloads.

## Fit Provenance Hardening

Status: Implemented.

### Threat Model

- Accidental drift: suite sets, datasets, or fitting code changed without regenerating fits.
- Incentive-corrupt edits: hand-tuning k/epsilon to make budgets look cheaper.
- Process bypass: claiming a fit came from a sweep with no manifest or hash.
- Reproducibility rot: AAR claims a commit/config that does not match the fit artifacts.

### Enforcement Summary

- Schema validation for risk fits, oversight plans, sweeps, eval runs, suite sets, and datasets.
- Required fit provenance fields (generator commit, eval run/sweep IDs + hashes, suite set + registry hashes, dataset hashes, config hash, seeds).
- Integrity checks for manifest hashes, dataset presence, and git commit existence.
- Oversight plans and AARs bind to fit and plan hashes for end-to-end evidence linkage.
- AAR evidence chain checks contract hashes, secret registry hashes, and previous AAR references when present.
- Governance gating for fit/sweep/run/suite set changes (RFC + approvals).
- Tests for missing manifests, hash mismatches, bad commits, dataset gaps, and plan/AAR inconsistencies.
