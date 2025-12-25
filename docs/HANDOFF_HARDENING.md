# Handoff Hardening

This sprint makes the repo adoption-ready by adding schema validation as a first-class invariant and CLI tooling for local evidence workflows.

## Schema Validation

`SCHEMA_VALIDATION` validates:

- JSON schema syntax for all `*.schema.json` files.
- All artifact files (JSON/YAML) against their declared schemas.

The authoritative target map is in `ci/invariants/schema_validation.py` and covers:

- contracts, lattice, fits, plans, sweeps
- eval manifests, suite registry/sets, dataset manifests
- AARs, lineage entries, chronicle events
- keys + runtime configs

## CLI Tooling

The CLI lives at `evoalign/cli.py` and is exposed as the `evoalign` command after installation.

Commands:

- `hash <file>` — canonical hash for JSON/YAML, raw hash for other files
- `verify-chain` — runs the evidence chain invariants locally
- `new-aar` — scaffolds an AAR with optional `previous_aar_hash`

Example:

```bash
pip install -e .
evoalign hash aars/aar_v0_1.json
evoalign verify-chain --repo-root .
evoalign new-aar --previous "$(evoalign hash aars/aar_v0_1.json)"
```

### Sandboxed Environment Fallback

If `pip install` fails due to SSL/certificate restrictions (common in some IDEs or CI sandboxes), use:

```bash
PYTHONPATH=/path/to/evoalign python -m evoalign.cli --help
```

## Integration Test

`tests/integration/test_evidence_chain.py` creates a fresh AAR entry and confirms the evidence chain invariants pass end-to-end.
