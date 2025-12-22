#!/usr/bin/env python3
import json
import shutil
import tempfile
import unittest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "ci" / "invariants"))
from evoalign.context_lattice import ContextLatticeError  # noqa: E402
import lattice_utils  # noqa: E402


class TestLatticeUtils(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_load_context_lattice_missing_dir(self):
        with self.assertRaises(ContextLatticeError):
            lattice_utils.load_context_lattice(self.test_dir)

    def test_load_context_lattice_no_files(self):
        lattice_dir = self.test_dir / "contracts/context_lattice"
        lattice_dir.mkdir(parents=True)
        with self.assertRaises(ContextLatticeError):
            lattice_utils.load_context_lattice(self.test_dir)

    def test_load_context_lattice_success(self):
        repo_root = Path(__file__).resolve().parents[2]
        lattice, path = lattice_utils.load_context_lattice(repo_root)
        self.assertTrue(lattice.version)
        self.assertTrue(path.exists())

    def test_load_lattice_index_empty(self):
        index = lattice_utils.load_lattice_index(self.test_dir)
        self.assertEqual(index, {})

    def test_load_lattice_index_missing_version(self):
        lattice_dir = self.test_dir / "contracts/context_lattice"
        lattice_dir.mkdir(parents=True)
        (lattice_dir / "context_lattice.yaml").write_text("dimensions: {}")

        with self.assertRaises(ContextLatticeError):
            lattice_utils.load_lattice_index(self.test_dir)

    def test_load_lattice_index_duplicate_version(self):
        lattice_dir = self.test_dir / "contracts/context_lattice"
        lattice_dir.mkdir(parents=True)
        content = "version: '0.1.0'\ndimensions: {}\ncontexts: {}"
        (lattice_dir / "a.yaml").write_text(content)
        (lattice_dir / "b.yaml").write_text(content)

        with self.assertRaises(ContextLatticeError):
            lattice_utils.load_lattice_index(self.test_dir)

    def test_load_lattice_index_success(self):
        lattice_dir = self.test_dir / "contracts/context_lattice"
        lattice_dir.mkdir(parents=True)
        (lattice_dir / "a.yaml").write_text("version: '0.1.0'\ndimensions: {}\ncontexts: {}")
        (lattice_dir / "b.yaml").write_text("[]")

        index = lattice_utils.load_lattice_index(self.test_dir)
        self.assertIn("0.1.0", index)

    def test_load_safety_contracts_skips_invalid(self):
        contracts_dir = self.test_dir / "contracts/safety_contracts"
        contracts_dir.mkdir(parents=True)
        (contracts_dir / "contract.yaml").write_text("version: '0.4.0'\ntolerances: []")
        (contracts_dir / "bad.json").write_text("{not-json")
        (contracts_dir / "list.json").write_text("[]")

        contracts = lattice_utils.load_safety_contracts(self.test_dir)
        self.assertEqual(len(contracts), 1)

    def test_extract_tolerances_skips_non_dict(self):
        contracts = [{"file": Path("contract.yaml"), "data": {"tolerances": ["bad"]}}]
        tolerances = lattice_utils.extract_tolerances(contracts)
        self.assertEqual(tolerances, [])

    def test_load_risk_fits_list_and_dict(self):
        fits_dir = self.test_dir / "control_plane/governor/risk_fits"
        fits_dir.mkdir(parents=True)
        (fits_dir / "list.json").write_text(json.dumps([{"fit_id": "a"}, "skip"]))
        (fits_dir / "dict.json").write_text(json.dumps({"fit_id": "b"}))
        (fits_dir / "skip.yaml").write_text("fit_id: c")
        (fits_dir / "bad.json").write_text("{not-json")

        fits = lattice_utils.load_risk_fits(self.test_dir)
        self.assertEqual(len(fits), 2)

    def test_extract_plan_entries_variants(self):
        self.assertEqual(lattice_utils.extract_plan_entries([{"context_class": "any"}]), [{"context_class": "any"}])
        self.assertEqual(
            lattice_utils.extract_plan_entries({"plans_by_context": [{"context_class": "any"}]}),
            [{"context_class": "any"}],
        )
        self.assertEqual(
            lattice_utils.extract_plan_entries({"plans": [{"context_class": "any"}]}),
            [{"context_class": "any"}],
        )
        self.assertEqual(
            lattice_utils.extract_plan_entries({"context_class": "any"}),
            [{"context_class": "any"}],
        )
        self.assertEqual(lattice_utils.extract_plan_entries({"other": 1}), [])
        self.assertEqual(lattice_utils.extract_plan_entries("string"), [])

    def test_load_oversight_plans_skips_invalid(self):
        plans_dir = self.test_dir / "control_plane/governor/oversight_plans"
        plans_dir.mkdir(parents=True)
        (plans_dir / "plan.json").write_text(json.dumps({
            "plans_by_context": [
                "skip",
                {"plan_id": "x"}
            ]
        }))
        (plans_dir / "bad.json").write_text("{not-json")

        plans = lattice_utils.load_oversight_plans(self.test_dir)
        self.assertEqual(plans, [])

    def test_get_numeric_success_and_failure(self):
        self.assertEqual(lattice_utils.get_numeric("1.5", "tau", "src"), 1.5)
        with self.assertRaises(ValueError):
            lattice_utils.get_numeric("bad", "tau", "src")

    def test_compute_fit_risk_branches(self):
        fit = {
            "file": "fit.json",
            "conservative_epsilon_high": 0.1,
            "conservative_k_low": 0.2,
            "k_low_by_channel": {"a": 0.1},
        }
        risk = lattice_utils.compute_fit_risk(fit, {"a": 2})
        self.assertGreater(risk, 0.1)

        risk_no_alloc = lattice_utils.compute_fit_risk(fit, None)
        self.assertEqual(risk_no_alloc, 0.1)

        with self.assertRaises(ValueError):
            lattice_utils.compute_fit_risk(fit, [])

        with self.assertRaises(ValueError):
            lattice_utils.compute_fit_risk(fit, {"a": 0})

        fit_no_k = {"file": "fit.json", "conservative_epsilon_high": 0.1}
        risk_no_k = lattice_utils.compute_fit_risk(fit_no_k, {"a": 2})
        self.assertEqual(risk_no_k, 0.1)

        fit_bad = {"file": "fit.json", "conservative_epsilon_high": "bad"}
        with self.assertRaises(ValueError):
            lattice_utils.compute_fit_risk(fit_bad, None)


if __name__ == "__main__":
    unittest.main()
