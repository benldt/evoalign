#!/usr/bin/env python3
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "ci" / "invariants"))

from base import InvariantResult  # noqa: E402
from evidence_governance import EvidenceGovernanceInvariant  # noqa: E402
from fit_plan_aar_consistency import FitPlanAarConsistencyInvariant  # noqa: E402
from fit_provenance_complete import FitProvenanceCompleteInvariant  # noqa: E402
from fit_provenance_integrity import FitProvenanceIntegrityInvariant  # noqa: E402
import provenance_utils  # noqa: E402

from evoalign.provenance import sha256_canonical  # noqa: E402


def write_json(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2))


def build_good_repo(root: Path) -> dict:
    contract = {"version": "0.1.0"}
    lattice = {"version": "0.1.0"}
    write_json(root / "contracts/safety_contracts/contract.json", contract)
    write_json(root / "contracts/context_lattice/lattice.json", lattice)
    contract_hash = sha256_canonical(contract)
    lattice_hash = sha256_canonical(lattice)

    registry = {
        "registry_version": "0.1.0",
        "generated_at": "2025-01-01T00:00:00Z",
        "suites": [
            {
                "suite_id": "suite1",
                "suite_type": "baseline",
                "suite_version": "1.0.0",
                "secrecy_level": "public",
                "n_test_cases": 1,
                "last_updated": "2025-01-01T00:00:00Z",
                "suite_hash": "sha256:111"
            }
        ]
    }
    registry_hash = sha256_canonical(registry)
    write_json(root / "control_plane/evals/suites/registry.json", registry)

    suite_set = {
        "suite_set_id": "set_good",
        "suite_ids": ["suite1"],
        "registry_hash": registry_hash,
        "created_at": "2025-01-01T00:00:00Z",
        "rfc_reference": "RFC-TEST-0001",
        "approvals": [
            {"role": "Lead", "signature": "sig", "timestamp": "2025-01-01T00:00:00Z"}
        ]
    }
    suite_set_hash = sha256_canonical(suite_set)
    write_json(root / "control_plane/evals/suites/sets/set_good.json", suite_set)

    dataset = {
        "dataset_id": "ds1",
        "source": "internal",
        "snapshot_timestamp": "2025-01-01T00:00:00Z",
        "dataset_hash": "sha256:abc",
        "access_policy": "internal"
    }
    write_json(root / "control_plane/evals/datasets/manifests/ds1.json", dataset)

    eval_run = {
        "eval_run_id": "run_good",
        "suite_set_id": "set_good",
        "suite_set_hash": suite_set_hash,
        "dataset_ids": ["ds1"],
        "dataset_hashes": {"ds1": "sha256:abc"},
        "rfc_reference": "RFC-TEST-0002",
        "approvals": [
            {"role": "Eval", "signature": "sig", "timestamp": "2025-01-01T00:00:00Z"}
        ],
        "code_commit": "good",
        "config_hash": "sha256:cfg",
        "random_seeds": [1],
        "date_range": {"start": "2025-01-01T00:00:00Z", "end": "2025-01-01T01:00:00Z"},
        "result_summary_hash": "sha256:res"
    }
    eval_run_hash = sha256_canonical(eval_run)
    write_json(root / "control_plane/evals/runs/run_good.json", eval_run)

    sweep = {
        "sweep_id": "sweep_good",
        "hazard_id": "H1",
        "severity_id": "S1",
        "context_class": "any",
        "oversight_levels_tested": [1],
        "eval_run_ids": ["run_good"],
        "eval_run_hashes": {"run_good": eval_run_hash},
        "rfc_reference": "RFC-TEST-0003",
        "approvals": [
            {"role": "Risk", "signature": "sig", "timestamp": "2025-01-01T00:00:00Z"}
        ],
        "fitting_inputs_hash": "sha256:inputs",
        "generated_at": "2025-01-01T00:00:00Z",
        "generator_commit": "good"
    }
    sweep_hash = sha256_canonical(sweep)
    write_json(root / "control_plane/governor/sweeps/sweep_good.json", sweep)

    fit = {
        "fit_id": "fit_good",
        "hazard_id": "H1",
        "severity_id": "S1",
        "context_class": "any",
        "conservative_epsilon_high": 0.1,
        "conservative_k_low": 0.01,
        "provenance": {
            "provenance_version": "0.1.0",
            "rfc_reference": "RFC-TEST-0004",
            "approvals": [
                {"role": "Risk", "signature": "sig", "timestamp": "2025-01-01T00:00:00Z"}
            ],
            "fit_generator_commit": "good",
            "eval_run_id": "run_good",
            "eval_run_hash": eval_run_hash,
            "sweep_id": "sweep_good",
            "sweep_hash": sweep_hash,
            "suite_set_id": "set_good",
            "suite_set_hash": suite_set_hash,
            "suite_registry_hash": registry_hash,
            "config_hash": "sha256:cfg",
            "dataset_hashes": {"ds1": "sha256:abc"},
            "random_seeds": [1]
        }
    }
    fit_hash = sha256_canonical(fit)
    write_json(root / "control_plane/governor/risk_fits/fits.json", [fit])

    plan = {
        "plan_version": "0.1.0",
        "generated_at": "2025-01-01T00:00:00Z",
        "plans_by_context": [
            {"context_class": "any", "plan_id": "plan_good", "channel_allocations": {"a": 1}}
        ],
        "computed_from_fit_hashes": [
            {"fit_id": "fit_good", "fit_hash": fit_hash}
        ],
        "provenance": {
            "governor_commit": "good",
            "contract_hash": contract_hash,
            "suite_registry_hash": registry_hash,
            "context_lattice_hash": lattice_hash,
            "generated_at": "2025-01-01T00:00:00Z"
        }
    }
    write_json(root / "control_plane/governor/oversight_plans/plan.json", plan)

    return {
        "contract_hash": contract_hash,
        "lattice_hash": lattice_hash,
        "registry_hash": registry_hash,
        "suite_set_hash": suite_set_hash,
        "eval_run_hash": eval_run_hash,
        "sweep_hash": sweep_hash,
        "fit_hash": fit_hash,
    }


class TestProvenanceUtils(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_loaders(self):
        registry = {"registry_version": "0.1.0", "generated_at": "2025-01-01T00:00:00Z", "suites": []}
        registry_hash = sha256_canonical(registry)
        write_json(self.test_dir / "control_plane/evals/suites/registry.json", registry)
        (self.test_dir / "control_plane/evals/suites/registry.txt").write_text("skip")

        suite_set = {
            "suite_set_id": "set1",
            "suite_ids": ["suite1"],
            "registry_hash": registry_hash,
            "created_at": "2025-01-01T00:00:00Z",
            "rfc_reference": "RFC-TEST",
            "approvals": [
                {"role": "Lead", "signature": "sig", "timestamp": "2025-01-01T00:00:00Z"}
            ]
        }
        write_json(self.test_dir / "control_plane/evals/suites/sets/set1.json", suite_set)
        write_json(self.test_dir / "control_plane/evals/suites/sets/skip.json", {"suite_ids": []})
        write_json(self.test_dir / "control_plane/evals/suites/sets/list.json", [])
        (self.test_dir / "control_plane/evals/suites/sets/skip.txt").write_text("skip")
        (self.test_dir / "control_plane/evals/suites/sets/skip.yaml").write_text("suite_set_id: set2")

        dataset = {
            "dataset_id": "ds1",
            "source": "internal",
            "snapshot_timestamp": "2025-01-01T00:00:00Z",
            "dataset_hash": "sha256:abc",
            "access_policy": "internal"
        }
        write_json(self.test_dir / "control_plane/evals/datasets/manifests/ds1.json", dataset)
        write_json(self.test_dir / "control_plane/evals/datasets/manifests/skip.json", {"dataset_hash": "x"})
        write_json(self.test_dir / "control_plane/evals/datasets/manifests/list.json", [])
        (self.test_dir / "control_plane/evals/datasets/manifests/skip.txt").write_text("skip")
        (self.test_dir / "control_plane/evals/datasets/manifests/skip.yaml").write_text("dataset_id: ds2")

        eval_run = {
            "eval_run_id": "run1",
            "suite_set_id": "set1",
            "suite_set_hash": sha256_canonical(suite_set),
            "dataset_ids": ["ds1"],
            "dataset_hashes": {"ds1": "sha256:abc"},
            "rfc_reference": "RFC-TEST",
            "approvals": [
                {"role": "Eval", "signature": "sig", "timestamp": "2025-01-01T00:00:00Z"}
            ],
            "code_commit": "good",
            "config_hash": "sha256:cfg",
            "random_seeds": [1],
            "date_range": {"start": "2025-01-01T00:00:00Z", "end": "2025-01-01T00:00:00Z"},
            "result_summary_hash": "sha256:res"
        }
        write_json(self.test_dir / "control_plane/evals/runs/run1.json", eval_run)
        write_json(self.test_dir / "control_plane/evals/runs/skip.json", {"suite_set_id": "set1"})
        write_json(self.test_dir / "control_plane/evals/runs/list.json", [])
        (self.test_dir / "control_plane/evals/runs/skip.txt").write_text("skip")
        (self.test_dir / "control_plane/evals/runs/skip.yaml").write_text("eval_run_id: run2")

        sweep = {
            "sweep_id": "sweep1",
            "hazard_id": "H1",
            "severity_id": "S1",
            "context_class": "any",
            "oversight_levels_tested": [1],
            "eval_run_ids": ["run1"],
            "eval_run_hashes": {"run1": sha256_canonical(eval_run)},
            "rfc_reference": "RFC-TEST",
            "approvals": [
                {"role": "Risk", "signature": "sig", "timestamp": "2025-01-01T00:00:00Z"}
            ],
            "fitting_inputs_hash": "sha256:inputs",
            "generated_at": "2025-01-01T00:00:00Z",
            "generator_commit": "good"
        }
        write_json(self.test_dir / "control_plane/governor/sweeps/sweep1.json", sweep)
        write_json(self.test_dir / "control_plane/governor/sweeps/skip.json", {"hazard_id": "H1"})
        write_json(self.test_dir / "control_plane/governor/sweeps/list.json", [])
        (self.test_dir / "control_plane/governor/sweeps/skip.txt").write_text("skip")
        (self.test_dir / "control_plane/governor/sweeps/skip.yaml").write_text("sweep_id: sweep2")

        fits = [{"fit_id": "fit1"}, "skip"]
        write_json(self.test_dir / "control_plane/governor/risk_fits/fits.json", fits)
        write_json(self.test_dir / "control_plane/governor/risk_fits/fit.json", {"fit_id": "fit2"})
        (self.test_dir / "control_plane/governor/risk_fits/skip.txt").write_text("skip")
        (self.test_dir / "control_plane/governor/risk_fits/skip.yaml").write_text("fit_id: fit3")

        write_json(self.test_dir / "control_plane/governor/oversight_plans/plan.json", {"plan_version": "0.1"})
        write_json(self.test_dir / "control_plane/governor/oversight_plans/skip.json", ["bad"])
        (self.test_dir / "control_plane/governor/oversight_plans/skip.txt").write_text("skip")
        (self.test_dir / "control_plane/governor/oversight_plans/skip.yaml").write_text("plan_version: 0.1")

        write_json(self.test_dir / "aars/aar.json", {"aar_id": "a1"})
        write_json(self.test_dir / "aars/skip.json", ["bad"])
        (self.test_dir / "aars/skip.txt").write_text("skip")
        (self.test_dir / "aars/skip.yaml").write_text("aar_id: a2")

        registry_loaded = provenance_utils.load_registry(self.test_dir)
        self.assertEqual(registry_loaded["hash"], registry_hash)

        self.assertIn("set1", provenance_utils.load_suite_sets(self.test_dir))
        self.assertIn("ds1", provenance_utils.load_dataset_manifests(self.test_dir))
        self.assertIn("run1", provenance_utils.load_eval_runs(self.test_dir))
        self.assertIn("sweep1", provenance_utils.load_sweeps(self.test_dir))
        self.assertEqual(len(provenance_utils.load_risk_fits(self.test_dir)), 2)
        self.assertEqual(len(provenance_utils.load_oversight_plan_files(self.test_dir)), 1)
        self.assertEqual(len(provenance_utils.load_aars(self.test_dir)), 1)
        self.assertTrue(provenance_utils.compute_object_hash({"a": 1}).startswith("sha256:"))

    def test_registry_invalid(self):
        write_json(self.test_dir / "control_plane/evals/suites/registry.json", [])
        self.assertIsNone(provenance_utils.load_registry(self.test_dir))


class TestFitProvenanceCompleteInvariant(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_skip_no_fits(self):
        result = FitProvenanceCompleteInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.SKIP)

    def test_failures(self):
        fits = [
            {"fit_id": "fit1"},
            {
                "fit_id": "fit2",
                "provenance": {
                    "provenance_version": "",
                    "fit_generator_commit": "good",
                    "eval_run_id": "run",
                    "eval_run_hash": "sha256:abc",
                    "sweep_id": "sweep",
                    "sweep_hash": "sha256:abc",
                    "suite_set_id": "set",
                    "suite_set_hash": "sha256:abc",
                    "suite_registry_hash": "sha256:abc",
                    "config_hash": "sha256:abc",
                    "dataset_hashes": {},
                    "random_seeds": []
                }
            }
        ]
        write_json(self.test_dir / "control_plane/governor/risk_fits/fits.json", fits)
        result = FitProvenanceCompleteInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_pass(self):
        fit = {
            "fit_id": "fit1",
            "provenance": {
                "provenance_version": "0.1",
                "rfc_reference": "RFC",
                "approvals": [{"role": "Lead", "signature": "sig", "timestamp": "2025-01-01T00:00:00Z"}],
                "fit_generator_commit": "good",
                "eval_run_id": "run",
                "eval_run_hash": "sha256:abc",
                "sweep_id": "sweep",
                "sweep_hash": "sha256:abc",
                "suite_set_id": "set",
                "suite_set_hash": "sha256:abc",
                "suite_registry_hash": "sha256:abc",
                "config_hash": "sha256:abc",
                "dataset_hashes": {"ds": "sha256:abc"},
                "random_seeds": [1]
            }
        }
        write_json(self.test_dir / "control_plane/governor/risk_fits/fits.json", [fit])
        result = FitProvenanceCompleteInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.PASS)


class TestFitProvenanceIntegrityInvariant(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_skip_no_fits(self):
        result = FitProvenanceIntegrityInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.SKIP)

    def test_missing_registry(self):
        fit = {
            "fit_id": "fit1",
            "hazard_id": "H1",
            "severity_id": "S1",
            "context_class": "any",
            "provenance": {
                "provenance_version": "0.1",
                "rfc_reference": "RFC",
                "approvals": [{"role": "Lead", "signature": "sig", "timestamp": "2025-01-01T00:00:00Z"}],
                "fit_generator_commit": "good",
                "eval_run_id": "run1",
                "eval_run_hash": "sha256:abc",
                "sweep_id": "missing",
                "sweep_hash": "sha256:abc",
                "suite_set_id": "set1",
                "suite_set_hash": "sha256:abc",
                "suite_registry_hash": "sha256:abc",
                "config_hash": "sha256:abc",
                "dataset_hashes": {},
                "random_seeds": [1]
            }
        }
        write_json(self.test_dir / "control_plane/governor/risk_fits/fits.json", [fit])
        suite_set = {
            "suite_set_id": "set1",
            "suite_ids": ["suite1"],
            "registry_hash": "sha256:missing",
            "created_at": "2025-01-01T00:00:00Z",
            "rfc_reference": "RFC",
            "approvals": [{"role": "Lead", "signature": "sig", "timestamp": "2025-01-01T00:00:00Z"}]
        }
        write_json(self.test_dir / "control_plane/evals/suites/sets/set1.json", suite_set)
        eval_run = {
            "eval_run_id": "run1",
            "suite_set_id": "set1",
            "suite_set_hash": "sha256:abc",
            "dataset_ids": [],
            "dataset_hashes": {},
            "rfc_reference": "RFC",
            "approvals": [{"role": "Eval", "signature": "sig", "timestamp": "2025-01-01T00:00:00Z"}],
            "code_commit": "good",
            "config_hash": "sha256:abc",
            "random_seeds": [1],
            "date_range": {"start": "2025-01-01T00:00:00Z", "end": "2025-01-01T00:00:00Z"},
            "result_summary_hash": "sha256:res"
        }
        write_json(self.test_dir / "control_plane/evals/runs/run1.json", eval_run)
        with mock.patch("fit_provenance_integrity.git_commit_exists", return_value=True):
            result = FitProvenanceIntegrityInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_pass(self):
        build_good_repo(self.test_dir)
        with mock.patch("fit_provenance_integrity.git_commit_exists", return_value=True):
            result = FitProvenanceIntegrityInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.PASS)

    def test_pass_and_failures(self):
        hashes = build_good_repo(self.test_dir)

        suite_set_bad = {
            "suite_set_id": "set_bad",
            "suite_ids": ["unknown"],
            "registry_hash": "sha256:bad",
            "created_at": "2025-01-01T00:00:00Z",
            "rfc_reference": "RFC-BAD",
            "approvals": [
                {"role": "Lead", "signature": "sig", "timestamp": "2025-01-01T00:00:00Z"}
            ]
        }
        write_json(self.test_dir / "control_plane/evals/suites/sets/set_bad.json", suite_set_bad)
        suite_set_bad_hash = sha256_canonical(suite_set_bad)

        sweep_bad = {
            "sweep_id": "sweep_bad",
            "hazard_id": "H9",
            "severity_id": "S9",
            "context_class": "none",
            "oversight_levels_tested": [1],
            "eval_run_ids": [],
            "eval_run_hashes": {"run_good": "sha256:bad"},
            "rfc_reference": "RFC-BAD",
            "approvals": [
                {"role": "Risk", "signature": "sig", "timestamp": "2025-01-01T00:00:00Z"}
            ],
            "fitting_inputs_hash": "sha256:bad",
            "generated_at": "2025-01-01T00:00:00Z",
            "generator_commit": "good"
        }
        write_json(self.test_dir / "control_plane/governor/sweeps/sweep_bad.json", sweep_bad)
        sweep_bad_hash = sha256_canonical(sweep_bad)

        base_fit = json.loads(
            (self.test_dir / "control_plane/governor/risk_fits/fits.json").read_text()
        )[0]

        fit_bad_commit = json.loads(json.dumps(base_fit))
        fit_bad_commit["fit_id"] = "fit_bad_commit"
        fit_bad_commit["provenance"]["fit_generator_commit"] = "bad"

        fit_bad_eval = json.loads(json.dumps(base_fit))
        fit_bad_eval["fit_id"] = "fit_bad_eval"
        fit_bad_eval["provenance"]["eval_run_id"] = "missing"

        fit_bad_sweep = json.loads(json.dumps(base_fit))
        fit_bad_sweep["fit_id"] = "fit_bad_sweep"
        fit_bad_sweep["provenance"]["sweep_id"] = "missing_sweep"

        fit_bad_mismatch = json.loads(json.dumps(base_fit))
        fit_bad_mismatch["fit_id"] = "fit_bad_mismatch"
        fit_bad_mismatch["hazard_id"] = "H2"
        fit_bad_mismatch["severity_id"] = "S2"
        fit_bad_mismatch["context_class"] = "no_tools"
        fit_bad_mismatch["provenance"]["sweep_id"] = "sweep_bad"
        fit_bad_mismatch["provenance"]["sweep_hash"] = "sha256:wrong"
        fit_bad_mismatch["provenance"]["suite_set_id"] = "set_bad"
        fit_bad_mismatch["provenance"]["suite_set_hash"] = "sha256:wrong"
        fit_bad_mismatch["provenance"]["suite_registry_hash"] = "sha256:wrong"
        fit_bad_mismatch["provenance"]["config_hash"] = "sha256:wrong"
        fit_bad_mismatch["provenance"]["random_seeds"] = [99]
        fit_bad_mismatch["provenance"]["dataset_hashes"] = {
            "ds1": "sha256:wrong",
            "ds_missing": "sha256:missing"
        }
        fit_bad_mismatch["provenance"]["eval_run_hash"] = "sha256:wrong"

        fit_bad_suite_missing = json.loads(json.dumps(base_fit))
        fit_bad_suite_missing["fit_id"] = "fit_bad_suite_missing"
        fit_bad_suite_missing["provenance"]["suite_set_id"] = "missing_set"
        fit_bad_suite_missing["provenance"]["suite_set_hash"] = suite_set_bad_hash

        fit_no_prov = {"fit_id": "fit_no_prov"}

        fits = [
            base_fit,
            fit_no_prov,
            fit_bad_commit,
            fit_bad_eval,
            fit_bad_sweep,
            fit_bad_mismatch,
            fit_bad_suite_missing,
        ]
        write_json(self.test_dir / "control_plane/governor/risk_fits/fits.json", fits)

        def commit_check(commit, repo_root=None):
            return commit != "bad"

        with mock.patch("fit_provenance_integrity.git_commit_exists", side_effect=commit_check):
            result = FitProvenanceIntegrityInvariant(self.test_dir).check()

        self.assertEqual(result.result, InvariantResult.FAIL)

        with mock.patch("fit_provenance_integrity.git_commit_exists", return_value=True):
            result = FitProvenanceIntegrityInvariant(self.test_dir).check()

        self.assertEqual(result.result, InvariantResult.FAIL)


class TestEvidenceGovernanceInvariant(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_skip(self):
        result = EvidenceGovernanceInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.SKIP)

    def test_fail(self):
        fit = {
            "fit_id": "fit1",
            "provenance": {
                "provenance_version": "0.1",
                "fit_generator_commit": "good",
                "eval_run_id": "run",
                "eval_run_hash": "sha256:abc",
                "sweep_id": "sweep",
                "sweep_hash": "sha256:abc",
                "suite_set_id": "set",
                "suite_set_hash": "sha256:abc",
                "suite_registry_hash": "sha256:abc",
                "config_hash": "sha256:abc",
                "dataset_hashes": {"ds": "sha256:abc"},
                "random_seeds": [1]
            }
        }
        write_json(self.test_dir / "control_plane/governor/risk_fits/fits.json", [fit])

        sweep = {
            "sweep_id": "sweep1",
            "hazard_id": "H1",
            "severity_id": "S1",
            "context_class": "any",
            "oversight_levels_tested": [1],
            "eval_run_ids": ["run"],
            "eval_run_hashes": {"run": "sha256:abc"},
            "fitting_inputs_hash": "sha256:inputs",
            "generated_at": "2025-01-01T00:00:00Z",
            "generator_commit": "good"
        }
        write_json(self.test_dir / "control_plane/governor/sweeps/sweep.json", sweep)

        eval_run = {
            "eval_run_id": "run",
            "suite_set_id": "set",
            "suite_set_hash": "sha256:abc",
            "dataset_ids": ["ds"],
            "dataset_hashes": {"ds": "sha256:abc"},
            "rfc_reference": "",
            "approvals": [{"role": "Eval", "timestamp": "2025-01-01T00:00:00Z"}],
            "code_commit": "good",
            "config_hash": "sha256:cfg",
            "random_seeds": [1],
            "date_range": {"start": "2025-01-01T00:00:00Z", "end": "2025-01-01T00:00:00Z"},
            "result_summary_hash": "sha256:res"
        }
        write_json(self.test_dir / "control_plane/evals/runs/run.json", eval_run)

        suite_set = {
            "suite_set_id": "set",
            "suite_ids": ["suite1"],
            "registry_hash": "sha256:abc",
            "created_at": "2025-01-01T00:00:00Z",
            "rfc_reference": "",
            "approvals": []
        }
        write_json(self.test_dir / "control_plane/evals/suites/sets/set.json", suite_set)

        result = EvidenceGovernanceInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_pass(self):
        build_good_repo(self.test_dir)
        result = EvidenceGovernanceInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.PASS)


class TestFitPlanAarConsistencyInvariant(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_skip_no_plans(self):
        result = FitPlanAarConsistencyInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.SKIP)

    def test_fail_no_fits(self):
        write_json(self.test_dir / "control_plane/governor/oversight_plans/plan.json", {"plan_version": "0.1"})
        result = FitPlanAarConsistencyInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_pass_without_aars(self):
        build_good_repo(self.test_dir)
        with mock.patch("fit_plan_aar_consistency.git_commit_exists", return_value=True):
            result = FitPlanAarConsistencyInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.PASS)

    def test_with_aars_failures(self):
        hashes = build_good_repo(self.test_dir)

        (self.test_dir / "contracts/safety_contracts/skip.txt").write_text("skip")
        (self.test_dir / "contracts/context_lattice/skip.txt").write_text("skip")

        fits = json.loads((self.test_dir / "control_plane/governor/risk_fits/fits.json").read_text())
        fits.append({"hazard_id": "H9"})
        dup_fit = json.loads(json.dumps(fits[0]))
        dup_fit["hazard_id"] = "H2"
        fits.append(dup_fit)
        write_json(self.test_dir / "control_plane/governor/risk_fits/fits.json", fits)
        dup_fit_hash = sha256_canonical(dup_fit)

        plan_missing = {
            "plan_version": "0.1.0",
            "generated_at": "2025-01-01T00:00:00Z",
            "plans_by_context": [
                {"context_class": "any", "plan_id": "plan_missing", "channel_allocations": {"a": 1}}
            ]
        }
        write_json(self.test_dir / "control_plane/governor/oversight_plans/plan_missing.json", plan_missing)

        plan_bad = {
            "plan_version": "0.1.0",
            "generated_at": "2025-01-01T00:00:00Z",
            "plans_by_context": [
                {"context_class": "any", "plan_id": "plan_ok", "channel_allocations": {"a": 1}},
                {"context_class": "any", "channel_allocations": {"a": 1}},
                "bad"
            ],
            "computed_from_fit_hashes": [
                "bad",
                {"fit_id": "unknown_fit", "fit_hash": "sha256:bad"},
                {"fit_id": "fit_good", "fit_hash": "sha256:bad"},
                {"fit_id": "fit_good", "fit_hash": dup_fit_hash}
            ],
            "provenance": {
                "governor_commit": "bad_commit",
                "contract_hash": "sha256:bad",
                "suite_registry_hash": "sha256:bad",
                "context_lattice_hash": "sha256:bad",
                "generated_at": "2025-01-01T00:00:00Z"
            }
        }
        write_json(self.test_dir / "control_plane/governor/oversight_plans/plan_bad.json", plan_bad)
        plan_bad_hash = sha256_canonical(plan_bad)

        aar_bad_list = {
            "aar_id": "a1",
            "version": "0.1",
            "scope_and_threat_model": {"in_scope": {}, "out_of_scope": {}, "adversary_model": {}},
            "safety_contract": {
                "contract_version": "0.1",
                "contract_hash": "sha256:bad",
                "context_lattice_version": "0.1",
                "context_lattice_hash": "sha256:bad"
            },
            "evaluation_coverage": {"coverage_matrix": [], "suite_inventory": []},
            "risk_modeling": {"risk_curve_fits": [], "sweep_summary": {}, "risk_fit_artifacts": "bad"},
            "oversight_policy": {
                "plans_by_context": [
                    {"context_class": "any", "plan_id": "unknown_plan", "plan_hash": "sha256:bad"}
                ]
            },
            "stability_controls": {"update_policy": {}},
            "lineage_references": {"lineage_ids": []},
            "operational_controls": {},
            "reproducibility": {
                "code_commit": "good",
                "config_hash": "sha256:cfg",
                "suite_registry_hash": "sha256:bad",
                "suite_set_hashes": {},
                "context_lattice_hash": "sha256:bad",
                "secret_hash_registry_hash": "sha256:bad"
            },
            "known_gaps": {"gaps": []},
            "governance": {}
        }
        write_json(self.test_dir / "aars/aar_bad_list.json", aar_bad_list)

        aar_bad_entries = {
            "aar_id": "a2",
            "version": "0.1",
            "scope_and_threat_model": {"in_scope": {}, "out_of_scope": {}, "adversary_model": {}},
            "safety_contract": {
                "contract_version": "0.1",
                "contract_hash": "sha256:bad",
                "context_lattice_version": "0.1",
                "context_lattice_hash": "sha256:bad"
            },
            "evaluation_coverage": {"coverage_matrix": [], "suite_inventory": []},
            "risk_modeling": {
                "risk_curve_fits": [],
                "sweep_summary": {},
                "risk_fit_artifacts": [
                    "bad",
                    {
                        "fit_id": "unknown_fit",
                        "fit_hash": "sha256:bad",
                        "sweep_id": "missing",
                        "sweep_hash": "sha256:bad",
                        "eval_run_id": "missing",
                        "eval_run_hash": "sha256:bad"
                    },
                    {
                        "fit_id": "fit_good",
                        "fit_hash": "sha256:bad",
                        "sweep_id": "sweep_good",
                        "sweep_hash": "sha256:bad",
                        "eval_run_id": "run_good",
                        "eval_run_hash": "sha256:bad"
                    },
                    {
                        "fit_id": "fit_good",
                        "fit_hash": dup_fit_hash,
                        "sweep_id": "sweep_good",
                        "sweep_hash": hashes["sweep_hash"],
                        "eval_run_id": "run_good",
                        "eval_run_hash": hashes["eval_run_hash"]
                    }
                ]
            },
            "oversight_policy": {
                "plans_by_context": [
                    {"context_class": "any", "plan_id": "plan_ok", "plan_hash": "sha256:bad"},
                    {"context_class": "any", "plan_id": "plan_ok", "plan_hash": plan_bad_hash},
                    {"context_class": "any", "plan_id": "unknown_plan", "plan_hash": "sha256:bad"},
                    "bad"
                ]
            },
            "stability_controls": {"update_policy": {}},
            "lineage_references": {"lineage_ids": []},
            "operational_controls": {},
            "reproducibility": {
                "code_commit": "good",
                "config_hash": "sha256:cfg",
                "suite_registry_hash": hashes["registry_hash"],
                "suite_set_hashes": {
                    "set_good": hashes["suite_set_hash"],
                    "set_missing": "sha256:bad"
                },
                "context_lattice_hash": hashes["lattice_hash"],
                "secret_hash_registry_hash": "sha256:bad"
            },
            "known_gaps": {"gaps": []},
            "governance": {}
        }
        write_json(self.test_dir / "aars/aar_bad_entries.json", aar_bad_entries)

        def commit_check(commit, repo_root=None):
            return commit != "bad_commit"

        with mock.patch("fit_plan_aar_consistency.git_commit_exists", side_effect=commit_check):
            result = FitPlanAarConsistencyInvariant(self.test_dir).check()

        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_aar_reproducibility_mismatch(self):
        hashes = build_good_repo(self.test_dir)
        plan = json.loads(
            (self.test_dir / "control_plane/governor/oversight_plans/plan.json").read_text()
        )
        plan_hash = sha256_canonical(plan)

        aar = {
            "aar_id": "aar_mismatch",
            "risk_modeling": {
                "risk_fit_artifacts": [
                    {
                        "fit_id": "fit_good",
                        "fit_hash": hashes["fit_hash"],
                        "sweep_id": "sweep_good",
                        "sweep_hash": hashes["sweep_hash"],
                        "eval_run_id": "run_good",
                        "eval_run_hash": hashes["eval_run_hash"],
                    }
                ]
            },
            "oversight_policy": {
                "plans_by_context": [
                    {"context_class": "any", "plan_id": "plan_good", "plan_hash": plan_hash}
                ]
            },
            "reproducibility": {
                "code_commit": "bad_commit",
                "config_hash": "sha256:bad",
                "suite_registry_hash": hashes["registry_hash"],
                "suite_set_hashes": {"set_good": hashes["suite_set_hash"]},
                "context_lattice_hash": hashes["lattice_hash"],
                "secret_hash_registry_hash": "sha256:bad",
            },
        }
        write_json(self.test_dir / "aars/aar_mismatch.json", aar)

        with mock.patch("fit_plan_aar_consistency.git_commit_exists", return_value=True):
            result = FitPlanAarConsistencyInvariant(self.test_dir).check()

        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_aar_reproducibility_multiple_commits(self):
        hashes = build_good_repo(self.test_dir)

        fits = json.loads((self.test_dir / "control_plane/governor/risk_fits/fits.json").read_text())
        base_fit = json.loads(json.dumps(fits[0]))

        fit_alt = json.loads(json.dumps(base_fit))
        fit_alt["fit_id"] = "fit_alt"
        fit_alt["provenance"]["fit_generator_commit"] = "alt_commit"
        fit_alt["provenance"]["config_hash"] = "sha256:alt"

        fit_missing = json.loads(json.dumps(base_fit))
        fit_missing["fit_id"] = "fit_missing"
        fit_missing["provenance"].pop("fit_generator_commit", None)
        fit_missing["provenance"].pop("config_hash", None)

        fits = [base_fit, fit_alt, fit_missing]
        write_json(self.test_dir / "control_plane/governor/risk_fits/fits.json", fits)

        plan = json.loads(
            (self.test_dir / "control_plane/governor/oversight_plans/plan.json").read_text()
        )
        plan_hash = sha256_canonical(plan)

        def fit_ref(fit_id, fit_data):
            return {
                "fit_id": fit_id,
                "fit_hash": sha256_canonical(fit_data),
                "sweep_id": "sweep_good",
                "sweep_hash": hashes["sweep_hash"],
                "eval_run_id": "run_good",
                "eval_run_hash": hashes["eval_run_hash"],
            }

        aar = {
            "aar_id": "aar_multi_commit",
            "risk_modeling": {
                "risk_fit_artifacts": [
                    fit_ref("fit_good", base_fit),
                    fit_ref("fit_alt", fit_alt),
                    fit_ref("fit_missing", fit_missing),
                ]
            },
            "oversight_policy": {
                "plans_by_context": [
                    {"context_class": "any", "plan_id": "plan_good", "plan_hash": plan_hash}
                ]
            },
            "reproducibility": {
                "code_commit": base_fit["provenance"]["fit_generator_commit"],
                "config_hash": base_fit["provenance"]["config_hash"],
                "suite_registry_hash": hashes["registry_hash"],
                "suite_set_hashes": {"set_good": hashes["suite_set_hash"]},
                "context_lattice_hash": hashes["lattice_hash"],
                "secret_hash_registry_hash": "sha256:bad",
            },
        }
        write_json(self.test_dir / "aars/aar_multi_commit.json", aar)

        with mock.patch("fit_plan_aar_consistency.git_commit_exists", return_value=True):
            result = FitPlanAarConsistencyInvariant(self.test_dir).check()

        self.assertEqual(result.result, InvariantResult.FAIL)


if __name__ == "__main__":
    unittest.main()
