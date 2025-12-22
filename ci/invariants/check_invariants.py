#!/usr/bin/env python3
"""
EvoAlign CI Invariants
======================
Enforceable invariants per EvoAlign v2 §14.3.

Invariants:
- SCHEMA_VALIDATION: Artifacts validate against their declared schemas
- SECRECY: Secret suites never enter training corpora, Chronicle training, or prompt libraries
- SECRET_REGISTRY_INTEGRITY: Secret hash registry matches suite registry and fingerprints
- PROMOTION: No lineage promotion without passing required suite sets at tolerances
- SALVAGE: No deployable artifact may include salvage unless transfer tests passed
- ROLLBACK: Deployments must have a certified rollback target
- CONTRACT: Safety Contract changes require approved RFC and signatures
- CONTEXT_REGISTRY: All context_class values must be defined in the context lattice
- CONTEXT_LATTICE_GOVERNANCE: Lattice changes require RFC reference and signatures
- BUDGET_SOLVENCY: Oversight plans must satisfy tolerances under conservative fits
- EVIDENCE_GOVERNANCE: Evidence artifacts require RFC references and approvals
- FIT_PROVENANCE_COMPLETE: Fits have required provenance fields
- FIT_PROVENANCE_INTEGRITY: Fit provenance hashes and manifests are verifiable
- FIT_PLAN_AAR_CONSISTENCY: Plans and AARs reference fits by hash
- AAR_EVIDENCE_CHAIN: AAR hashes verified against source files and chain
- LINEAGE_INTEGRITY: Lineage entries have valid provenance and chain
- CHRONICLE_GOVERNANCE: Chronicle entries reference valid AARs
- TAMPER_EVIDENCE: Merkle roots and signatures verified when present
- RUNTIME_CONFIG: Runtime configs match AAR stability/monitoring claims
"""

import os
import sys
from pathlib import Path

from base import InvariantResult
from budget_solvency import BudgetSolvencyInvariant
from context_lattice_governance import ContextLatticeGovernanceInvariant
from context_registry import ContextRegistryInvariant
from contract import ContractInvariant
from evidence_governance import EvidenceGovernanceInvariant
from fit_plan_aar_consistency import FitPlanAarConsistencyInvariant
from fit_provenance_complete import FitProvenanceCompleteInvariant
from fit_provenance_integrity import FitProvenanceIntegrityInvariant
from promotion import PromotionInvariant
from rollback import RollbackInvariant
from salvage import SalvageInvariant
from secret_registry_integrity import SecretRegistryIntegrityInvariant
from secrecy import SecrecyInvariant
from aar_evidence_chain import AarEvidenceChainInvariant
from chronicle_governance import ChronicleGovernanceInvariant
from lineage_integrity import LineageIntegrityInvariant
from tamper_evidence import TamperEvidenceInvariant
from runtime_config import RuntimeConfigInvariant
from schema_validation import SchemaValidationInvariant


ALL_INVARIANTS = [
    SchemaValidationInvariant,
    SecretRegistryIntegrityInvariant,
    SecrecyInvariant,
    PromotionInvariant,
    SalvageInvariant,
    RollbackInvariant,
    ContractInvariant,
    ContextLatticeGovernanceInvariant,
    ContextRegistryInvariant,
    BudgetSolvencyInvariant,
    EvidenceGovernanceInvariant,
    FitProvenanceCompleteInvariant,
    FitProvenanceIntegrityInvariant,
    FitPlanAarConsistencyInvariant,
    AarEvidenceChainInvariant,
    LineageIntegrityInvariant,
    ChronicleGovernanceInvariant,
    TamperEvidenceInvariant,
    RuntimeConfigInvariant,
]


def run_all_invariants(repo_root: Path) -> dict:
    results = []
    all_passed = True

    for invariant_class in ALL_INVARIANTS:
        checker = invariant_class(repo_root)
        result = checker.check()
        results.append(result.to_dict())

        if result.result == InvariantResult.FAIL:
            all_passed = False

    return {
        "all_passed": all_passed,
        "results": results,
    }


def main() -> int:
    repo_root = Path(os.environ.get("REPO_ROOT", ".")).resolve()

    print("EvoAlign Invariant Checker")
    print(f"Repo root: {repo_root}")
    print("=" * 60)

    results = run_all_invariants(repo_root)

    for result in results["results"]:
        status_icon = {
            "PASS": "✓",
            "FAIL": "✗",
            "WARN": "⚠",
            "SKIP": "○",
        }[result["result"]]

        print(f"\n{status_icon} {result['name']}: {result['result']}")
        print(f"  {result['message']}")

        if result.get("details"):
            for key, value in result["details"].items():
                if isinstance(value, list) and value:
                    print(f"  {key}:")
                    for item in value[:5]:
                        print(f"    - {item}")
                    if len(value) > 5:
                        print(f"    ... and {len(value) - 5} more")

    print("\n" + "=" * 60)

    if results["all_passed"]:
        print("All invariants PASSED")
        return 0

    print("Some invariants FAILED")
    return 1


if __name__ == "__main__":
    sys.exit(main())
