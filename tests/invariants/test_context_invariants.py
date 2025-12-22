#!/usr/bin/env python3
import json
import shutil
import tempfile
import unittest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "ci" / "invariants"))
from base import InvariantResult  # noqa: E402
from budget_solvency import BudgetSolvencyInvariant  # noqa: E402
from context_lattice_governance import ContextLatticeGovernanceInvariant  # noqa: E402
from context_registry import ContextRegistryInvariant  # noqa: E402


class ContextInvariantBase(unittest.TestCase):
    def setUp(self):
        self.repo_root = Path(__file__).resolve().parents[2]
        self.test_dir = Path(tempfile.mkdtemp())
        self._write_schema()
        self._write_lattice()

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def _write_schema(self):
        schema_src = self.repo_root / "schemas/ContextLattice.schema.json"
        schema_dst = self.test_dir / "schemas/ContextLattice.schema.json"
        schema_dst.parent.mkdir(parents=True, exist_ok=True)
        schema_dst.write_text(schema_src.read_text())

    def _write_lattice(self):
        lattice_path = self.test_dir / "contracts/context_lattice/context_lattice_v0_1.yaml"
        lattice_path.parent.mkdir(parents=True, exist_ok=True)
        lattice_path.write_text("\n".join([
            "version: \"0.1.0\"",
            "dimensions:",
            "  tool_access:",
            "    type: set",
            "    atoms: [\"web\", \"email\"]",
            "    top: \"*\"",
            "    bottom: []",
            "contexts:",
            "  any:",
            "    tool_access: \"*\"",
            "  tool_access:any:",
            "    tool_access: \"*\"",
            "  tool_access:web+email:",
            "    tool_access: [\"web\", \"email\"]",
            "metadata:",
            "  created_at: \"2025-01-15T00:00:00Z\"",
            "  rfc_reference: \"RFC-CTX-0001\"",
            "  approvals:",
            "    - role: \"Technical Safety Lead\"",
            "      signature: \"sig_ctx\"",
            "      timestamp: \"2025-01-15T00:00:00Z\"",
        ]))

    def _write_safety_contract(self, tolerances):
        contract_path = self.test_dir / "contracts/safety_contracts/contract.yaml"
        contract_path.parent.mkdir(parents=True, exist_ok=True)
        contract_path.write_text("\n".join([
            "version: \"0.4.0\"",
            "tolerances:",
            *[
                "\n".join([
                    "  - hazard_id: \"{hazard_id}\"".format(**tol),
                    "    context_class: \"{context_class}\"".format(**tol),
                    "    severity_id: \"{severity_id}\"".format(**tol),
                    "    tau: {tau}".format(**tol),
                    "    confidence: 0.9",
                ])
                for tol in tolerances
            ],
        ]))

    def _write_contract_text(self, text: str):
        contract_path = self.test_dir / "contracts/safety_contracts/contract.yaml"
        contract_path.parent.mkdir(parents=True, exist_ok=True)
        contract_path.write_text(text)

    def _write_risk_fits(self, fits):
        fits_path = self.test_dir / "control_plane/governor/risk_fits/fits.json"
        fits_path.parent.mkdir(parents=True, exist_ok=True)
        fits_path.write_text(json.dumps(fits))

    def _write_risk_fits_text(self, text: str):
        fits_path = self.test_dir / "control_plane/governor/risk_fits/fits.json"
        fits_path.parent.mkdir(parents=True, exist_ok=True)
        fits_path.write_text(text)

    def _write_oversight_plans(self, plans):
        plans_path = self.test_dir / "control_plane/governor/oversight_plans/plan.json"
        plans_path.parent.mkdir(parents=True, exist_ok=True)
        plans_path.write_text(json.dumps({"plans_by_context": plans}))

    def _write_oversight_plan_text(self, text: str):
        plans_path = self.test_dir / "control_plane/governor/oversight_plans/plan.json"
        plans_path.parent.mkdir(parents=True, exist_ok=True)
        plans_path.write_text(text)


class TestContextRegistryInvariant(ContextInvariantBase):
    def test_registry_passes(self):
        self._write_safety_contract([{
            "hazard_id": "H1",
            "severity_id": "S3",
            "context_class": "any",
            "tau": 0.1,
        }])

        result = ContextRegistryInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.PASS)

    def test_registry_fails_on_unknown_context(self):
        self._write_safety_contract([{
            "hazard_id": "H1",
            "severity_id": "S3",
            "context_class": "unknown_ctx",
            "tau": 0.1,
        }])

        result = ContextRegistryInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_registry_skips_without_references(self):
        result = ContextRegistryInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.SKIP)

    def test_registry_fails_without_lattice(self):
        shutil.rmtree(self.test_dir / "contracts/context_lattice")
        result = ContextRegistryInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_registry_repo_artifacts(self):
        repo_root = Path(__file__).resolve().parents[2]
        result = ContextRegistryInvariant(repo_root).check()
        self.assertEqual(result.result, InvariantResult.PASS)


class TestContextLatticeGovernanceInvariant(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_governance_skips_without_lattice(self):
        result = ContextLatticeGovernanceInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.SKIP)

    def test_governance_parse_error_fails(self):
        lattice_dir = self.test_dir / "contracts/context_lattice"
        lattice_dir.mkdir(parents=True)
        (lattice_dir / "context_lattice.yaml").write_text("[]")

        result = ContextLatticeGovernanceInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_governance_parse_exception_fails(self):
        lattice_dir = self.test_dir / "contracts/context_lattice"
        lattice_dir.mkdir(parents=True)
        (lattice_dir / "context_lattice.yaml").write_text("[unclosed")

        result = ContextLatticeGovernanceInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_governance_missing_rfc_fails(self):
        lattice_dir = self.test_dir / "contracts/context_lattice"
        lattice_dir.mkdir(parents=True)
        (lattice_dir / "context_lattice.yaml").write_text("\n".join([
            "version: \"0.1.0\"",
            "dimensions:",
            "  tool_access:",
            "    type: set",
            "    atoms: [\"web\"]",
            "    top: \"*\"",
            "    bottom: []",
            "contexts:",
            "  any:",
            "    tool_access: \"*\"",
            "metadata:",
            "  approvals:",
            "    - role: \"Lead\"",
            "      signature: \"sig\"",
            "      timestamp: \"2025-01-15T00:00:00Z\"",
        ]))

        result = ContextLatticeGovernanceInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_governance_missing_signature_fails(self):
        lattice_dir = self.test_dir / "contracts/context_lattice"
        lattice_dir.mkdir(parents=True)
        (lattice_dir / "context_lattice.yaml").write_text("\n".join([
            "version: \"0.1.0\"",
            "dimensions:",
            "  tool_access:",
            "    type: set",
            "    atoms: [\"web\"]",
            "    top: \"*\"",
            "    bottom: []",
            "contexts:",
            "  any:",
            "    tool_access: \"*\"",
            "metadata:",
            "  rfc_reference: \"RFC-CTX-0001\"",
            "  approvals:",
            "    - role: \"Lead\"",
            "      timestamp: \"2025-01-15T00:00:00Z\"",
        ]))

        result = ContextLatticeGovernanceInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_governance_passes(self):
        lattice_dir = self.test_dir / "contracts/context_lattice"
        lattice_dir.mkdir(parents=True)
        (lattice_dir / "context_lattice.yaml").write_text("\n".join([
            "version: \"0.1.0\"",
            "dimensions:",
            "  tool_access:",
            "    type: set",
            "    atoms: [\"web\"]",
            "    top: \"*\"",
            "    bottom: []",
            "contexts:",
            "  any:",
            "    tool_access: \"*\"",
            "metadata:",
            "  rfc_reference: \"RFC-CTX-0001\"",
            "  approvals:",
            "    - role: \"Lead\"",
            "      signature: \"sig\"",
            "      timestamp: \"2025-01-15T00:00:00Z\"",
        ]))

        result = ContextLatticeGovernanceInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.PASS)


class TestBudgetSolvencyInvariant(ContextInvariantBase):
    def test_budget_solvency_strictest_tau_and_worst_fit(self):
        self._write_safety_contract([
            {
                "hazard_id": "H1",
                "severity_id": "S3",
                "context_class": "any",
                "tau": 0.1,
            },
            {
                "hazard_id": "H1",
                "severity_id": "S3",
                "context_class": "tool_access:any",
                "tau": 0.05,
            },
        ])
        self._write_risk_fits([
            {
                "fit_id": "fit_any",
                "hazard_id": "H1",
                "severity_id": "S3",
                "context_class": "any",
                "conservative_epsilon_high": 0.04,
            },
            {
                "fit_id": "fit_tool",
                "hazard_id": "H1",
                "severity_id": "S3",
                "context_class": "tool_access:any",
                "conservative_epsilon_high": 0.06,
            },
        ])
        self._write_oversight_plans([
            {
                "context_class": "tool_access:web+email",
                "plan_id": "plan-1",
                "channel_allocations": {},
            }
        ])

        result = BudgetSolvencyInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_budget_solvency_passes(self):
        self._write_safety_contract([
            {
                "hazard_id": "H1",
                "severity_id": "S3",
                "context_class": "any",
                "tau": 0.1,
            }
        ])
        self._write_risk_fits([
            {
                "fit_id": "fit_any",
                "hazard_id": "H1",
                "severity_id": "S3",
                "context_class": "any",
                "conservative_epsilon_high": 0.05,
            }
        ])
        self._write_oversight_plans([
            {
                "context_class": "tool_access:web+email",
                "plan_id": "plan-2",
                "channel_allocations": {},
            }
        ])

        result = BudgetSolvencyInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.PASS)

    def test_budget_solvency_fails_without_lattice(self):
        shutil.rmtree(self.test_dir / "contracts/context_lattice")
        result = BudgetSolvencyInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_budget_solvency_skips_without_plans(self):
        self._write_safety_contract([{
            "hazard_id": "H1",
            "severity_id": "S3",
            "context_class": "any",
            "tau": 0.1,
        }])
        self._write_risk_fits([{
            "fit_id": "fit_any",
            "hazard_id": "H1",
            "severity_id": "S3",
            "context_class": "any",
            "conservative_epsilon_high": 0.01,
        }])

        result = BudgetSolvencyInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.SKIP)

    def test_budget_solvency_fails_without_tolerances(self):
        self._write_oversight_plans([{
            "context_class": "tool_access:web+email",
            "plan_id": "plan-no-tol",
            "channel_allocations": {},
        }])
        self._write_risk_fits([{
            "fit_id": "fit_any",
            "hazard_id": "H1",
            "severity_id": "S3",
            "context_class": "any",
            "conservative_epsilon_high": 0.01,
        }])

        result = BudgetSolvencyInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_budget_solvency_fails_without_fits(self):
        self._write_safety_contract([{
            "hazard_id": "H1",
            "severity_id": "S3",
            "context_class": "any",
            "tau": 0.1,
        }])
        self._write_oversight_plans([{
            "context_class": "tool_access:web+email",
            "plan_id": "plan-no-fit",
            "channel_allocations": {},
        }])

        result = BudgetSolvencyInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_budget_solvency_fails_missing_tolerance_context(self):
        self._write_contract_text("\n".join([
            "version: \"0.4.0\"",
            "tolerances:",
            "  - hazard_id: \"H1\"",
            "    severity_id: \"S3\"",
            "    tau: 0.1",
            "    confidence: 0.9",
        ]))
        self._write_risk_fits([{
            "fit_id": "fit_any",
            "hazard_id": "H1",
            "severity_id": "S3",
            "context_class": "any",
            "conservative_epsilon_high": 0.01,
        }])
        self._write_oversight_plans([{
            "context_class": "tool_access:web+email",
            "plan_id": "plan-missing-tol-context",
            "channel_allocations": {},
        }])

        result = BudgetSolvencyInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_budget_solvency_fails_invalid_tau(self):
        self._write_contract_text("\n".join([
            "version: \"0.4.0\"",
            "tolerances:",
            "  - hazard_id: \"H1\"",
            "    context_class: \"any\"",
            "    severity_id: \"S3\"",
            "    tau: \"bad\"",
            "    confidence: 0.9",
        ]))
        self._write_risk_fits([{
            "fit_id": "fit_any",
            "hazard_id": "H1",
            "severity_id": "S3",
            "context_class": "any",
            "conservative_epsilon_high": 0.01,
        }])
        self._write_oversight_plans([{
            "context_class": "tool_access:web+email",
            "plan_id": "plan-bad-tau",
            "channel_allocations": {},
        }])

        result = BudgetSolvencyInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_budget_solvency_fails_no_applicable_tolerance(self):
        self._write_safety_contract([{
            "hazard_id": "H1",
            "severity_id": "S3",
            "context_class": "tool_access:web+email",
            "tau": 0.1,
        }])
        self._write_risk_fits([{
            "fit_id": "fit_any",
            "hazard_id": "H1",
            "severity_id": "S3",
            "context_class": "tool_access:web+email",
            "conservative_epsilon_high": 0.01,
        }])
        self._write_oversight_plans([{
            "context_class": "any",
            "plan_id": "plan-no-applicable-tol",
            "channel_allocations": {},
        }])

        result = BudgetSolvencyInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_budget_solvency_fails_missing_fit_context(self):
        self._write_safety_contract([{
            "hazard_id": "H1",
            "severity_id": "S3",
            "context_class": "any",
            "tau": 0.1,
        }])
        self._write_risk_fits_text(json.dumps([{
            "fit_id": "fit_any",
            "hazard_id": "H1",
            "severity_id": "S3",
            "conservative_epsilon_high": 0.01,
        }]))
        self._write_oversight_plans([{
            "context_class": "tool_access:web+email",
            "plan_id": "plan-missing-fit-context",
            "channel_allocations": {},
        }])

        result = BudgetSolvencyInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_budget_solvency_fails_no_applicable_fit(self):
        self._write_safety_contract([{
            "hazard_id": "H1",
            "severity_id": "S3",
            "context_class": "any",
            "tau": 0.1,
        }])
        self._write_risk_fits([{
            "fit_id": "fit_any",
            "hazard_id": "H1",
            "severity_id": "S3",
            "context_class": "tool_access:web+email",
            "conservative_epsilon_high": 0.01,
        }])
        self._write_oversight_plans([{
            "context_class": "any",
            "plan_id": "plan-no-applicable-fit",
            "channel_allocations": {},
        }])

        result = BudgetSolvencyInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_budget_solvency_handles_fit_error(self):
        self._write_safety_contract([{
            "hazard_id": "H1",
            "severity_id": "S3",
            "context_class": "any",
            "tau": 0.1,
        }])
        self._write_risk_fits([{
            "fit_id": "fit_any",
            "hazard_id": "H1",
            "severity_id": "S3",
            "context_class": "any",
            "conservative_epsilon_high": 0.01,
        }])
        self._write_oversight_plans([{
            "context_class": "any",
            "plan_id": "plan-bad-allocations",
            "channel_allocations": [1],
        }])

        result = BudgetSolvencyInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_budget_solvency_unknown_plan_context(self):
        self._write_safety_contract([{
            "hazard_id": "H1",
            "severity_id": "S3",
            "context_class": "any",
            "tau": 0.1,
        }])
        self._write_risk_fits([{
            "fit_id": "fit_any",
            "hazard_id": "H1",
            "severity_id": "S3",
            "context_class": "any",
            "conservative_epsilon_high": 0.01,
        }])
        self._write_oversight_plans([{
            "context_class": "missing",
            "plan_id": "plan-unknown-context",
            "channel_allocations": {},
        }])

        result = BudgetSolvencyInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_budget_solvency_repo_artifacts(self):
        repo_root = Path(__file__).resolve().parents[2]
        result = BudgetSolvencyInvariant(repo_root).check()
        self.assertEqual(result.result, InvariantResult.PASS)

    def test_budget_solvency_fit_context_unknown(self):
        self._write_safety_contract([{
            "hazard_id": "H1",
            "severity_id": "S3",
            "context_class": "any",
            "tau": 0.1,
        }])
        self._write_risk_fits([{
            "fit_id": "fit_any",
            "hazard_id": "H1",
            "severity_id": "S3",
            "context_class": "unknown",
            "conservative_epsilon_high": 0.01,
        }])
        self._write_oversight_plans([{
            "context_class": "any",
            "plan_id": "plan-unknown-fit",
            "channel_allocations": {},
        }])

        result = BudgetSolvencyInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.FAIL)


if __name__ == "__main__":
    unittest.main()
