# Secret Suite Hash Registry

This repo enforces secrecy boundaries by comparing cryptographic fingerprints of secret suite items against protected artifacts (training corpora, Chronicle training data, prompt libraries). The goal is non-overlap by content, not by string IDs.

## Registry Files

- Suite registry: `control_plane/evals/suites/registry.json`
- Secret hash registry: `control_plane/evals/suites/hash_registries/secret_suite_hashes_v1.json`

If any suite in the suite registry is marked `secrecy_level="secret"`, the secret hash registry must exist and include that suite ID. CI fails closed if the registry is missing or incomplete.

## Hashing Scheme

Each secret registry declares a hashing scheme:

- `scheme_id`: `sha256-v1` or `hmac-sha256-v1`
- `digest_prefix`: `sha256:` or `hmacsha256:`
- `normalization`: `json_canonical_v1`
- Optional `key_id` for HMAC (e.g., `github_actions_secret:EVOALIGN_SECRECY_HMAC_KEY`)

For HMAC schemes, CI requires the key to be present in the environment. Missing keys are treated as failures.

### Fingerprint Root

Each suite entry includes a `suite_fingerprint_root` computed as:

- Sort `test_case_fingerprints` lexicographically
- Join with `\n`
- Hash the bytes with SHA-256 and prefix `sha256:`

This provides a compact integrity check over the suite fingerprint list.

## Canonicalization Rules

- JSON/YAML items:
  - `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`
  - UTF-8 bytes
- JSONL:
  - Parse each line as JSON; if parsing fails, treat the line as a raw string
- Text (`.txt`/`.md`):
  - Normalize line endings to `\n`
  - Split into paragraphs by blank lines
  - Fingerprint each paragraph and the full text blob

These rules are implemented in `evoalign/secrecy_fingerprints.py`.

## CI Enforcement

- `SECRET_REGISTRY_INTEGRITY` checks registry completeness and fingerprint roots.
- `SECRECY` scans protected paths and fails on hash intersection.
- `secrecy_inventory.py` emits `secrecy_audit.json` as a CI artifact.

Protected paths (v1):

- `training/data/`
- `training/corpora/`
- `culture/chronicle/training_data/`
- `prompts/`
- `prompt_libraries/`

