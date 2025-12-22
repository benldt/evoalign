# EvoAlign v2: Schemas & CI Invariants

> **From philosophy to engineering**: This package provides the formal schemas and CI enforcement that make EvoAlign a system that can refuse to accept changes that violate its safety invariants.

## Overview

This implementation provides:

1. **JSON Schemas** for all core EvoAlign data structures
2. **CI Invariant Checks** that block PRs violating safety boundaries
3. **Example artifacts** demonstrating proper usage

## Non-Negotiables: Testing Discipline And Maintainability

- **100%** Line/Branch/Function/Statement coverage required

- **350 LOC Limit**: Hard cap per source file (tests/types exempt). Enforce via CI. Split modules aggressively.

## Schemas

All schemas follow [JSON Schema Draft 2020-12](https://json-schema.org/draft/2020-12/schema).

### Core Schemas

| Schema | Purpose | EvoAlign Section |
|--------|---------|------------------|
| `SafetyContract.schema.json` | Hazards, severities, tolerances, disallowed events | §3 |
| `RiskCurveFit.schema.json` | Risk model parameters with uncertainty | §5.1-5.4 |
| `OversightPlan.schema.json` | Computed oversight allocations | §5.2, §5.7 |
| `AAR.schema.json` | Alignment Assurance Report | §13 |
| `LineageLedgerEntry.schema.json` | Append-only lineage tracking | §8.4 |
| `ChronicleEntry.schema.json` | Cultural memory with tiering | §10 |
| `EvalResult.schema.json` | Evaluation results with secrecy tracking | §6 |

### Schema Relationships

```
SafetyContract
    │
    ├──▶ defines tolerances ──▶ RiskCurveFit (validates against)
    │                              │
    │                              └──▶ OversightPlan (computed from)
    │
    └──▶ defines hazards ──▶ EvalResult (measures against)
                               │
                               └──▶ LineageLedgerEntry (records in)
                                        │
                                        └──▶ ChronicleEntry (may create)

                    All feed into ──▶ AAR (comprehensive report)
```

## CI Invariants

Per EvoAlign v2 §14.3, these invariants MUST pass for any change to merge.

### Invariant Summary

| Invariant | Rule | Failure Consequence |
|-----------|------|---------------------|
| **SECRECY** | Secret suites never enter training corpora, Chronicle training, or prompt libraries | PR blocked |
| **PROMOTION** | No lineage promotion without passing required suite sets at tolerances | PR blocked |
| **SALVAGE** | No deployable artifact may include salvage unless transfer tests passed and logged | PR blocked |
| **ROLLBACK** | Deployments must have a certified rollback target | PR blocked |
| **CONTRACT** | Safety Contract changes require approved RFC and signatures | PR blocked |

### Running Invariant Checks

```bash
# Create and activate repo-local virtualenv (recommended)
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install pyyaml jsonschema coverage

# Set repo root
export REPO_ROOT=/path/to/evoalign

# Run all invariants
python ci/invariants/check_invariants.py

# Run tests for the invariant checker itself
python -m unittest discover -s tests

# Enforce 100% coverage and 350 LOC cap
python -m coverage run --branch --source=ci/invariants,evoalign -m unittest discover -s tests
python -m coverage report --fail-under=100
python ci/invariants/loc_check.py
```

### CI Pipeline

The GitHub Actions pipeline (`ci/pipelines/invariants.yaml`) runs:

1. **Schema validation** - Ensures all schemas are syntactically valid
2. **Data validation** - Validates data files against their schemas
3. **Core invariants** - Runs all five invariant checks
4. **Secrecy boundary** - Additional defense against secret suite leaks
5. **Salvage safety** - Verifies salvage artifact certifications
6. **Contract governance** - Ensures RFC and approval requirements

All jobs must pass for the **Invariant Gate** to allow merge.

## Directory Structure

```
evoalign/
├── schemas/                          # JSON Schemas
│   ├── SafetyContract.schema.json
│   ├── RiskCurveFit.schema.json
│   ├── OversightPlan.schema.json
│   ├── AAR.schema.json
│   ├── LineageLedgerEntry.schema.json
│   ├── ChronicleEntry.schema.json
│   └── EvalResult.schema.json
│
├── contracts/
│   └── safety_contracts/
│       └── safety_contract_v0_4.yaml # Example contract
│
├── ci/
│   ├── invariants/
│   │   └── check_invariants.py       # Invariant enforcement
│   └── pipelines/
│       └── invariants.yaml           # GitHub Actions config
│
└── tests/
    └── invariants/
        └── test_invariants.py        # Invariant checker tests
```

## Usage Examples

### Validating a Safety Contract

```python
import json
from jsonschema import validate

with open("schemas/SafetyContract.schema.json") as f:
    schema = json.load(f)

with open("contracts/safety_contracts/safety_contract_v0_4.yaml") as f:
    import yaml
    contract = yaml.safe_load(f)

validate(instance=contract, schema=schema)
print("Contract is valid!")
```

### Creating a Lineage Ledger Entry

```python
entry = {
    "lineage_id": "L-2025-01-0001",
    "entry_type": "promotion",
    "timestamp": "2025-01-15T10:00:00Z",
    "status": "active",
    "training_config_hash": "sha256:abc123...",
    "contract_version": "0.4.0",
    "gates_passed": [
        {
            "suite_set_id": "core_v3",
            "result_hash": "sha256:def456...",
            "timestamp": "2025-01-14T15:00:00Z",
            "tolerances_met": True
        }
    ],
    "approvals": [
        {
            "role": "Technical Safety Lead",
            "approved": True,
            "signature": "sig_xyz...",
            "timestamp": "2025-01-15T09:00:00Z"
        }
    ]
}
```

### Checking Invariants Programmatically

```python
from pathlib import Path
from ci.invariants.check_invariants import run_all_invariants

results = run_all_invariants(Path("/path/to/repo"))

if results["all_passed"]:
    print("All invariants passed!")
else:
    for r in results["results"]:
        if r["result"] == "FAIL":
            print(f"FAILED: {r['name']} - {r['message']}")
```

## Key Design Decisions

### Why JSON Schema?

- **Standardized**: Widely supported validation tooling
- **Machine-readable**: Enables automated enforcement
- **Self-documenting**: Schema IS the documentation
- **Language-agnostic**: Works with any language/toolchain

### Why CI Invariants?

- **Shift left**: Catch violations before merge, not in production
- **Automated**: No human gatekeeping bottleneck
- **Auditable**: Every check is logged
- **Immutable**: Can't be bypassed by "just this once"

### Conservative Defaults

The invariant checks follow a "fail-closed" philosophy:
- Missing evidence = FAIL (not skip)
- Ambiguous state = FAIL (not pass)
- Unknown artifacts = FAIL (not ignore)

## Extending the System

### Adding a New Invariant

1. Create a new class inheriting from `InvariantChecker`
2. Implement the `check()` method returning `InvariantCheck`
3. Add to `ALL_INVARIANTS` list
4. Add tests in `tests/invariants/`

```python
class MyNewInvariant(InvariantChecker):
    def check(self) -> InvariantCheck:
        # Your check logic here
        if violation_found:
            return InvariantCheck(
                name="MY_NEW",
                result=InvariantResult.FAIL,
                message="Violation detected",
                details={"violations": [...]}
            )
        return InvariantCheck(
            name="MY_NEW",
            result=InvariantResult.PASS,
            message="Check passed"
        )
```

### Adding a New Schema

1. Create `YourSchema.schema.json` in `schemas/`
2. Use `$id` for canonical URI
3. Add to SCHEMA_MAP in CI pipeline for validation
4. Document in this README

## Relationship to EvoAlign v2 Spec

This implementation covers:

- ✅ §3: Safety Contract (hazards, severities, tolerances)
- ✅ §5: Risk modeling and oversight planning
- ✅ Fit provenance hardening (manifests, hashing, fit/plan/AAR bindings)
- ✅ §6: Evaluation with secrecy invariants
- ✅ §8.4: Lineage ledger
- ✅ §9: Salvage with taint tracking
- ✅ §10: Chronicle tiering
- ✅ §11.4: Rollback requirements
- ✅ §12.2: Contract change governance
- ✅ §13: AAR structure
- ✅ §14.3: CI-enforceable invariants

Not yet implemented (future work):

- ⬜ §5.5-5.6: Stability controls and damping (runtime)
- ⬜ §7: Experience Graph schema
- ⬜ §11.1-11.3: Operational monitoring (runtime)
- ⬜ §12.3: Cryptographic tamper evidence (needs PKI)

## License

See LICENSE file in repository root.

---

**Remember**: The repo itself is now a guardrail. It can refuse changes that violate safety boundaries. That's the line from philosophy to engineering.
