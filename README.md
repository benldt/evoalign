# EvoAlign v2: Alignment Governance System

> **From philosophy to engineering**: This package provides the formal schemas and CI enforcement that make EvoAlign a system that can refuse to accept changes that violate its safety invariants.

## State of Play

| Metric | Status |
|--------|--------|
| **Tests** | 313 passing |
| **Coverage** | 100% line/branch/function/statement |
| **LOC Cap** | All source files ≤350 LOC |
| **Invariants** | 19 total (16 PASS, 3 SKIP*) |
| **Schemas** | 16 JSON schemas |
| **License** | MIT |

*PROMOTION, SALVAGE, ROLLBACK skip when no artifacts present (fail-closed when artifacts exist).

### What's Implemented

| EvoAlign Section | Feature | Status |
|------------------|---------|--------|
| §3 | Safety Contract (hazards, severities, tolerances) | ✅ |
| §4 | Context lattice semantics and governance | ✅ |
| §5.1-5.4 | Risk modeling, sweeps, fits, oversight planning | ✅ |
| §5.5-5.6 | Stability controls and damping | ✅ |
| §6 | Evaluation provenance + secrecy enforcement | ✅ |
| §8.4 | Lineage ledger (append-only entries) | ✅ |
| §9 | Salvage with taint tracking | ✅ |
| §10 | Chronicle (anomaly-focused events) | ✅ |
| §11.1-11.3 | Operational monitoring | ✅ |
| §11.4 | Rollback requirements | ✅ |
| §12.2 | Contract/lattice governance | ✅ |
| §12.3 | Cryptographic tamper evidence (Merkle + PKI) | ✅ |
| §13 | AAR structure with hash bindings | ✅ |
| §14.3 | CI-enforceable invariants | ✅ |
| §7 | Experience Graph | ⬜ Future |

---

## Quick Start

```bash
# Clone and setup
git clone https://github.com/benldt/evoalign.git
cd evoalign
python3 -m venv .venv
source .venv/bin/activate
pip install -e .

# Verify installation
evoalign --help

# Run invariant checks
export REPO_ROOT=.
export PYTHONPATH=.
python ci/invariants/check_invariants.py

# Run tests with coverage
python -m coverage run --branch --source=ci/invariants,evoalign -m unittest discover -s tests
python -m coverage report --fail-under=100
```

### CLI Tooling

```bash
# Compute canonical hash for any data file
evoalign hash aars/aar_v0_1.json

# Verify evidence chain locally
evoalign verify-chain --repo-root .

# Scaffold a new AAR with chain link
evoalign new-aar --previous "$(evoalign hash aars/aar_v0_1.json)"
```

**Sandboxed environment fallback**: If `pip install` fails due to SSL restrictions, use:
```bash
PYTHONPATH=/path/to/evoalign python -m evoalign.cli --help
```

---

## Non-Negotiables

| Constraint | Enforcement |
|------------|-------------|
| **100% Coverage** | `coverage report --fail-under=100` |
| **350 LOC Cap** | `loc_check.py` (tests/types exempt) |
| **Fail-Closed** | Missing evidence = FAIL, not SKIP |

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           ALIGNMENT ASSURANCE REPORT (AAR)              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │
│  │ Safety       │  │ Risk         │  │ Stability    │  │ Operational  │ │
│  │ Contract     │  │ Modeling     │  │ Controls     │  │ Controls     │ │
│  │ (contract_   │  │ (fit_hashes, │  │ (damping,    │  │ (monitoring, │ │
│  │  hash)       │  │  plan_hash)  │  │  thrash)     │  │  alerting)   │ │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘ │
└─────────┼─────────────────┼─────────────────┼─────────────────┼─────────┘
          │                 │                 │                 │
          ▼                 ▼                 ▼                 ▼
┌──────────────────┐ ┌──────────────────┐ ┌──────────────────┐ ┌──────────────────┐
│ contracts/       │ │ control_plane/   │ │ control_plane/   │ │ control_plane/   │
│ safety_contracts/│ │ governor/        │ │ runtime/         │ │ runtime/         │
│                  │ │ risk_fits/       │ │ damping_*.json   │ │ monitoring_*.json│
│                  │ │ oversight_plans/ │ │                  │ │                  │
└──────────────────┘ │ sweeps/          │ └──────────────────┘ └──────────────────┘
                     └────────┬─────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         EVALUATION PROVENANCE                           │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │
│  │ EvalRun      │  │ SuiteRegistry│  │ SuiteSet     │  │ Dataset      │ │
│  │ Manifests    │  │              │  │              │  │ Manifests    │ │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘ │
│                                                                         │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ SecretSuiteHashRegistry — HMAC/SHA-256 fingerprints for secrecy  │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         GOVERNANCE ARTIFACTS                            │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐       │
│  │ Lineage Ledger   │  │ Chronicle        │  │ Public Key       │       │
│  │ (append-only     │  │ (anomaly events, │  │ Registry         │       │
│  │  stage gates)    │  │  incidents)      │  │ (signatures)     │       │
│  └──────────────────┘  └──────────────────┘  └──────────────────┘       │
└─────────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         CI INVARIANT GATE                               │
│  19 invariants must pass for merge — fail-closed on missing evidence    │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Schemas (16 total)

All schemas follow [JSON Schema Draft 2020-12](https://json-schema.org/draft/2020-12/schema).

| Schema | Purpose | Section |
|--------|---------|---------|
| `SafetyContract.schema.json` | Hazards, severities, tolerances, disallowed events | §3 |
| `ContextLattice.schema.json` | Context lattice registry and semantics | §4 |
| `RiskCurveFit.schema.json` | Risk model parameters with uncertainty | §5.1-5.4 |
| `RiskSweepManifest.schema.json` | Risk sweep manifests backing fits | §5.1 |
| `OversightPlan.schema.json` | Computed oversight allocations | §5.2, §5.7 |
| `DampingConfig.schema.json` | Stability controls configuration | §5.5-5.6 |
| `EvalRunManifest.schema.json` | Evaluation run manifests | §6 |
| `SuiteRegistry.schema.json` | Suite registry for provenance | §6 |
| `SuiteSet.schema.json` | Suite set manifests | §6 |
| `DatasetManifest.schema.json` | Dataset manifest provenance | §6 |
| `SecretSuiteHashRegistry.schema.json` | Secret suite fingerprint registry | §6 |
| `LineageLedgerEntry.schema.json` | Lineage ledger entry (append-only) | §8.4 |
| `ChronicleEntry.schema.json` | Chronicle anomaly event | §10 |
| `MonitoringConfig.schema.json` | Operational monitoring configuration | §11.1-11.3 |
| `PublicKeyRegistry.schema.json` | Public key registry for signatures | §12.3 |
| `AAR.schema.json` | Alignment Assurance Report | §13 |

### Schema Relationships

```
ContextLattice ──▶ context_class semantics for contracts, sweeps, fits, plans

SuiteRegistry ──▶ SuiteSet ─┐
DatasetManifest ───────────┴─▶ EvalRunManifest ─▶ RiskSweepManifest ─▶ RiskCurveFit ─▶ OversightPlan ─▶ AAR

SecretSuiteHashRegistry ─▶ Secrecy invariant + AAR reproducibility hashes

LineageLedgerEntry ─▶ stage gates, promotions, retirements (append-only chain)
ChronicleEntry ─▶ anomaly events, incidents, drift detection ─▶ AAR known_gaps

PublicKeyRegistry ─▶ key verification for signatures (optional tamper evidence)

DampingConfig ─▶ stability controls bound to AAR stability_controls claims
MonitoringConfig ─▶ alerting thresholds bound to AAR operational_controls claims
```

---

## CI Invariants (19 total)

Per EvoAlign v2 §14.3, these invariants MUST pass for any change to merge.

| # | Invariant | Rule | On Failure |
|---|-----------|------|------------|
| 1 | **SCHEMA_VALIDATION** | Artifacts validate against declared schemas | PR blocked |
| 2 | **SECRET_REGISTRY_INTEGRITY** | Secret hash registry completeness + hash/root integrity | PR blocked |
| 3 | **SECRECY** | Secret fingerprints do not appear in protected artifacts | PR blocked |
| 4 | **PROMOTION** | Lineage promotions require gates_passed evidence | PR blocked |
| 5 | **SALVAGE** | Salvage usage requires certified transfer tests + taint tags | PR blocked |
| 6 | **ROLLBACK** | Deployments include certified rollback target | PR blocked |
| 7 | **CONTRACT** | Safety Contract changes require RFC + approvals | PR blocked |
| 8 | **CONTEXT_LATTICE_GOVERNANCE** | Lattice changes require RFC + approvals | PR blocked |
| 9 | **CONTEXT_REGISTRY** | All context_class IDs must appear in lattice registry | PR blocked |
| 10 | **BUDGET_SOLVENCY** | Oversight plans satisfy tolerances under conservative fits | PR blocked |
| 11 | **EVIDENCE_GOVERNANCE** | Fits/sweeps/runs/sets include RFC + signed approvals | PR blocked |
| 12 | **FIT_PROVENANCE_COMPLETE** | Fit provenance required fields are present | PR blocked |
| 13 | **FIT_PROVENANCE_INTEGRITY** | Fit provenance hashes/manifests/commits verified | PR blocked |
| 14 | **FIT_PLAN_AAR_CONSISTENCY** | Plans/AARs bind to fit hashes + reproducibility | PR blocked |
| 15 | **AAR_EVIDENCE_CHAIN** | AAR contract/secret hashes + previous AAR chain verified | PR blocked |
| 16 | **LINEAGE_INTEGRITY** | Lineage entries have valid provenance and chain | PR blocked |
| 17 | **CHRONICLE_GOVERNANCE** | Chronicle entries reference valid AARs | PR blocked |
| 18 | **TAMPER_EVIDENCE** | Merkle roots and key references verified when present | PR blocked |
| 19 | **RUNTIME_CONFIG** | Runtime configs match AAR stability/monitoring claims | PR blocked |

### Fail-Closed Philosophy

- **Missing evidence** = FAIL (not skip)
- **Ambiguous state** = FAIL (not pass)
- **Unknown artifacts** = FAIL (not ignore)

---

## Directory Structure

```
evoalign/
├── aars/
│   └── aar_v0_1.json                 # Example Alignment Assurance Report
├── chronicle/
│   └── events/                       # Chronicle anomaly entries
│       ├── event_anomaly_001.json
│       └── event_threshold_002.json
├── ci/
│   ├── invariants/                   # 19 invariant checkers + utilities
│   │   ├── check_invariants.py       # Main entry point
│   │   ├── schema_validation.py      # SCHEMA_VALIDATION invariant
│   │   ├── aar_evidence_chain.py     # AAR_EVIDENCE_CHAIN invariant
│   │   ├── lineage_integrity.py      # LINEAGE_INTEGRITY invariant
│   │   ├── chronicle_governance.py   # CHRONICLE_GOVERNANCE invariant
│   │   ├── tamper_evidence.py        # TAMPER_EVIDENCE invariant
│   │   ├── runtime_config.py         # RUNTIME_CONFIG invariant
│   │   └── ...                       # Other invariants
│   └── pipelines/
│       └── invariants.yaml           # GitHub Actions workflow
├── contracts/
│   ├── context_lattice/
│   │   └── context_lattice_v0_1.yaml # Context lattice registry
│   └── safety_contracts/
│       └── safety_contract_v0_4.yaml # Safety contract
├── control_plane/
│   ├── evals/
│   │   ├── datasets/manifests/       # Dataset manifests
│   │   ├── runs/                     # Eval run manifests
│   │   └── suites/                   # Suite registry + sets + hash registries
│   │       ├── registry.json
│   │       ├── sets/
│   │       └── hash_registries/
│   ├── governor/
│   │   ├── oversight_plans/          # Oversight plans
│   │   ├── risk_fits/                # Risk curve fits
│   │   └── sweeps/                   # Risk sweep manifests
│   ├── keys/
│   │   └── key_registry_v0_1.json    # Public key registry
│   └── runtime/
│       ├── damping_v0_1.json         # Damping configuration
│       └── monitoring_v0_1.json      # Monitoring configuration
├── docs/
│   ├── CONTEXT_LATTICE.md            # Context lattice semantics
│   ├── PROVENANCE_HASHING.md         # Canonical hashing standard
│   ├── SECRECY_HASH_REGISTRY.md      # Secrecy enforcement
│   ├── LINEAGE_CHRONICLE.md          # Lineage + chronicle system
│   ├── TAMPER_EVIDENCE.md            # Merkle roots + PKI
│   ├── RUNTIME_GUARDRAILS.md         # Damping + monitoring
│   └── HANDOFF_HARDENING.md          # Schema validation + CLI
├── evoalign/
│   ├── __init__.py
│   ├── cli.py                        # CLI tooling (hash, verify-chain, new-aar)
│   ├── context_lattice.py            # Lattice engine
│   ├── merkle.py                     # Merkle tree utilities
│   ├── provenance.py                 # Canonical hashing
│   └── secrecy_fingerprints.py       # Fingerprinting for secrecy
├── lineage/
│   ├── entry_lin_v1_creation.json    # Example lineage entry
│   └── entry_lin_v1_promotion_canary.json
├── schemas/                          # 16 JSON schemas
├── tests/
│   ├── integration/                  # End-to-end evidence chain test
│   └── invariants/                   # Invariant unit tests
├── LICENSE                           # MIT
├── pyproject.toml                    # Package metadata + entrypoint
└── setup.py                          # Editable install shim
```

---

## CI Pipeline

The GitHub Actions pipeline (`ci/pipelines/invariants.yaml`) runs:

1. **Schema validation** — Validates all artifacts against schemas via `schema_validation.py`
2. **Core invariants** — Runs the full 19-invariant suite
3. **Context inventory** — Emits context usage artifact
4. **Coverage + LOC gates** — Enforces 100% coverage and 350 LOC cap
5. **Secrecy boundary** — Generates secrecy audit artifact
6. **Salvage safety** — Verifies salvage artifact certifications
7. **Contract governance** — Ensures RFC and approval requirements

All jobs must pass for the **Invariant Gate** to allow merge.

---

## Usage Examples

### Validating a Safety Contract

```python
import json
import yaml
from jsonschema import validate

with open("schemas/SafetyContract.schema.json") as f:
    schema = json.load(f)

with open("contracts/safety_contracts/safety_contract_v0_4.yaml") as f:
    contract = yaml.safe_load(f)

validate(instance=contract, schema=schema)
print("Contract is valid!")
```

### Validating an AAR

```python
import json
from jsonschema import validate

with open("schemas/AAR.schema.json") as f:
    schema = json.load(f)

with open("aars/aar_v0_1.json") as f:
    aar = json.load(f)

validate(instance=aar, schema=schema)
print("AAR is valid!")
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

---

## Extending the System

### Adding a New Invariant

1. Create a new class inheriting from `InvariantChecker` in `ci/invariants/`
2. Implement the `check()` method returning `InvariantCheck`
3. Add to `ALL_INVARIANTS` list in `check_invariants.py`
4. Add tests in `tests/invariants/`
5. Ensure 100% coverage

```python
from base import InvariantCheck, InvariantChecker, InvariantResult

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
3. Add to target map in `schema_validation.py`
4. Document in this README

---

## Documentation

| Document | Purpose |
|----------|---------|
| `docs/CONTEXT_LATTICE.md` | Context lattice semantics, ordering, coverage rules |
| `docs/PROVENANCE_HASHING.md` | Canonical hashing standard, fit provenance hardening |
| `docs/SECRECY_HASH_REGISTRY.md` | Secret hash registry, fingerprinting, CI enforcement |
| `docs/LINEAGE_CHRONICLE.md` | Lineage ledger entries, chronicle events, chain integrity |
| `docs/TAMPER_EVIDENCE.md` | Merkle roots, public key registry, signature verification |
| `docs/RUNTIME_GUARDRAILS.md` | Damping config, monitoring config, AAR binding |
| `docs/HANDOFF_HARDENING.md` | Schema validation invariant, CLI tooling |

---

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

### Why Fail-Closed?

- **Safety-critical**: Missing evidence is not acceptable
- **No silent failures**: Ambiguity must be resolved explicitly
- **Defense in depth**: Multiple invariants catch different failure modes

---

## License

MIT — See [LICENSE](LICENSE) file.

---

**Remember**: The repo itself is now a guardrail. It can refuse changes that violate safety boundaries. That's the line from philosophy to engineering.
