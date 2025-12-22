#!/usr/bin/env python3
import contextlib
import io
import json
import os
import runpy
import shutil
import tempfile
import unittest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "ci" / "invariants"))
from base import InvariantCheck, InvariantChecker, InvariantResult  # noqa: E402
import check_invariants  # noqa: E402
import context_inventory  # noqa: E402
import context_scan  # noqa: E402
import file_utils  # noqa: E402
import loc_check  # noqa: E402
from evoalign.provenance import git_commit_exists  # noqa: E402


class TestFileUtils(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_load_data_file_json_and_yaml(self):
        json_path = self.test_dir / "data.json"
        yaml_path = self.test_dir / "data.yaml"
        json_path.write_text(json.dumps({"value": 1}))
        yaml_path.write_text("value: 2")

        self.assertEqual(file_utils.load_data_file(json_path)["value"], 1)
        self.assertEqual(file_utils.load_data_file(yaml_path)["value"], 2)

    def test_iter_data_files(self):
        missing = self.test_dir / "missing"
        self.assertEqual(file_utils.iter_data_files(missing), [])

        (self.test_dir / "a.json").write_text("{}")
        (self.test_dir / "b.yaml").write_text("value: 1")
        (self.test_dir / "c.txt").write_text("skip")

        files = file_utils.iter_data_files(self.test_dir)
        self.assertEqual([f.name for f in files], ["a.json", "b.yaml"])


class TestContextScan(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_find_context_classes_nested(self):
        data = {
            "context_class": "any",
            "items": [
                {"context_class": "tool_access:any"},
                {"nested": {"context_class": "no_tools"}},
            ],
        }
        results = context_scan._find_context_classes(data)
        self.assertEqual({r["context_class"] for r in results}, {"any", "tool_access:any", "no_tools"})

    def test_scan_context_classes(self):
        contracts_dir = self.test_dir / "contracts/safety_contracts"
        contracts_dir.mkdir(parents=True)
        (contracts_dir / "contract.json").write_text(json.dumps({
            "tolerances": [{"context_class": "any"}]
        }))
        (contracts_dir / "contract.yaml").write_text("context_class: tool_access:any")
        (contracts_dir / "nested").mkdir()
        (contracts_dir / "note.txt").write_text("ignore")
        (contracts_dir / "bad.json").write_text("{not-json")

        results = context_scan.scan_context_classes(self.test_dir, ["contracts/safety_contracts"])
        found = sorted({r["context_class"] for r in results})
        self.assertEqual(found, ["any", "tool_access:any"])


class TestContextInventory(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp())
        self.prev_repo_root = os.environ.get("REPO_ROOT")
        self.prev_output = os.environ.get("CONTEXT_INVENTORY_OUTPUT")

    def tearDown(self):
        if self.prev_repo_root is None:
            os.environ.pop("REPO_ROOT", None)
        else:
            os.environ["REPO_ROOT"] = self.prev_repo_root
        if self.prev_output is None:
            os.environ.pop("CONTEXT_INVENTORY_OUTPUT", None)
        else:
            os.environ["CONTEXT_INVENTORY_OUTPUT"] = self.prev_output
        shutil.rmtree(self.test_dir)

    def test_inventory_empty(self):
        output = self.test_dir / "inventory.json"
        with contextlib.redirect_stdout(io.StringIO()):
            os.environ["REPO_ROOT"] = str(self.test_dir)
            os.environ["CONTEXT_INVENTORY_OUTPUT"] = str(output)
            result = context_inventory.main()

        payload = json.loads(output.read_text())
        self.assertEqual(payload["context_ids"], [])
        self.assertEqual(result, 0)

    def test_inventory_with_contexts(self):
        contracts_dir = self.test_dir / "contracts/safety_contracts"
        contracts_dir.mkdir(parents=True)
        (contracts_dir / "contract.json").write_text(json.dumps({
            "tolerances": [{"context_class": "any"}]
        }))

        output = self.test_dir / "inventory.json"
        with contextlib.redirect_stdout(io.StringIO()):
            os.environ["REPO_ROOT"] = str(self.test_dir)
            os.environ["CONTEXT_INVENTORY_OUTPUT"] = str(output)
            result = context_inventory.main()

        payload = json.loads(output.read_text())
        self.assertEqual(payload["context_ids"], ["any"])
        self.assertEqual(result, 0)

    def test_inventory_default_output_path(self):
        contracts_dir = self.test_dir / "contracts/safety_contracts"
        contracts_dir.mkdir(parents=True)
        (contracts_dir / "contract.json").write_text(json.dumps({
            "tolerances": [{"context_class": "any"}]
        }))

        with contextlib.redirect_stdout(io.StringIO()):
            os.environ["REPO_ROOT"] = str(self.test_dir)
            os.environ.pop("CONTEXT_INVENTORY_OUTPUT", None)
            result = context_inventory.main()

        output = self.test_dir / "context_inventory.json"
        payload = json.loads(output.read_text())
        self.assertEqual(payload["context_ids"], ["any"])
        self.assertEqual(result, 0)

    def test_inventory_as_script(self):
        contracts_dir = self.test_dir / "contracts/safety_contracts"
        contracts_dir.mkdir(parents=True)
        (contracts_dir / "contract.json").write_text(json.dumps({
            "tolerances": [{"context_class": "any"}]
        }))
        os.environ["REPO_ROOT"] = str(self.test_dir)
        os.environ["CONTEXT_INVENTORY_OUTPUT"] = str(self.test_dir / "inv.json")

        module_path = Path(__file__).resolve().parents[2] / "ci/invariants/context_inventory.py"
        with contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as exc:
                runpy.run_path(str(module_path), run_name="__main__")
        self.assertEqual(exc.exception.code, 0)


class TestLocCheck(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp())
        self.prev_repo_root = os.environ.get("REPO_ROOT")
        self.prev_max_loc = os.environ.get("MAX_LOC")

    def tearDown(self):
        if self.prev_repo_root is None:
            os.environ.pop("REPO_ROOT", None)
        else:
            os.environ["REPO_ROOT"] = self.prev_repo_root
        if self.prev_max_loc is None:
            os.environ.pop("MAX_LOC", None)
        else:
            os.environ["MAX_LOC"] = self.prev_max_loc
        shutil.rmtree(self.test_dir)

    def test_count_and_collect(self):
        file_path = self.test_dir / "example.py"
        file_path.write_text("line1\nline2\n")
        self.assertEqual(loc_check.count_loc(file_path), 2)

        files = loc_check.collect_python_files(self.test_dir)
        self.assertEqual(files, [file_path])

    def test_loc_check_with_and_without_violation(self):
        file_path = self.test_dir / "example.py"
        file_path.write_text("line1\nline2\nline3\n")

        violations = loc_check.check_loc(self.test_dir, max_loc=10)
        self.assertEqual(violations, [])

        violations = loc_check.check_loc(self.test_dir, max_loc=2)
        self.assertEqual(len(violations), 1)

        violations = loc_check.check_loc(self.test_dir, max_loc=2, excluded_dirs={"skip"})
        self.assertEqual(len(violations), 1)

    def test_loc_check_excludes_tests(self):
        tests_dir = self.test_dir / "tests"
        tests_dir.mkdir(parents=True)
        (tests_dir / "skip.py").write_text("line1\n" * 400)

        violations = loc_check.check_loc(self.test_dir, max_loc=1)
        self.assertEqual(violations, [])

    def test_loc_check_main(self):
        file_path = self.test_dir / "example.py"
        file_path.write_text("line1\nline2\nline3\n")

        with contextlib.redirect_stdout(io.StringIO()):
            os.environ["REPO_ROOT"] = str(self.test_dir)
            os.environ["MAX_LOC"] = "2"
            self.assertEqual(loc_check.main(), 1)

        with contextlib.redirect_stdout(io.StringIO()):
            os.environ["REPO_ROOT"] = str(self.test_dir)
            os.environ["MAX_LOC"] = "10"
            self.assertEqual(loc_check.main(), 0)

    def test_loc_check_as_script(self):
        file_path = self.test_dir / "example.py"
        file_path.write_text("line1\nline2\n")
        os.environ["REPO_ROOT"] = str(self.test_dir)
        os.environ["MAX_LOC"] = "10"

        module_path = Path(__file__).resolve().parents[2] / "ci/invariants/loc_check.py"
        with contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as exc:
                runpy.run_path(str(module_path), run_name="__main__")
        self.assertEqual(exc.exception.code, 0)


class DummyInvariantPass(InvariantChecker):
    def check(self) -> InvariantCheck:
        return InvariantCheck("DUMMY", InvariantResult.PASS, "ok")


class DummyInvariantFail(InvariantChecker):
    def check(self) -> InvariantCheck:
        return InvariantCheck("DUMMY_FAIL", InvariantResult.FAIL, "fail")


class DummyInvariantDetails(InvariantChecker):
    def check(self) -> InvariantCheck:
        return InvariantCheck(
            "DUMMY_DETAILS",
            InvariantResult.PASS,
            "details",
            details={
                "items": [1, 2, 3, 4, 5, 6],
                "short": [1, 2],
                "empty": [],
            },
        )


class TestCheckInvariantsRunner(unittest.TestCase):
    def setUp(self):
        self.original_invariants = check_invariants.ALL_INVARIANTS
        self.prev_repo_root = os.environ.get("REPO_ROOT")

    def tearDown(self):
        check_invariants.ALL_INVARIANTS = self.original_invariants
        if self.prev_repo_root is None:
            os.environ.pop("REPO_ROOT", None)
        else:
            os.environ["REPO_ROOT"] = self.prev_repo_root

    def test_run_all_invariants_pass_and_fail(self):
        check_invariants.ALL_INVARIANTS = [DummyInvariantPass]
        results = check_invariants.run_all_invariants(Path("."))
        self.assertTrue(results["all_passed"])

        check_invariants.ALL_INVARIANTS = [DummyInvariantFail]
        results = check_invariants.run_all_invariants(Path("."))
        self.assertFalse(results["all_passed"])

    def test_main_with_details(self):
        check_invariants.ALL_INVARIANTS = [DummyInvariantDetails]
        with contextlib.redirect_stdout(io.StringIO()):
            result = check_invariants.main()
        self.assertEqual(result, 0)

    def test_main_failure_branch(self):
        check_invariants.ALL_INVARIANTS = self.original_invariants
        temp_dir = Path(tempfile.mkdtemp())
        try:
            os.environ["REPO_ROOT"] = str(temp_dir)
            with contextlib.redirect_stdout(io.StringIO()):
                result = check_invariants.main()
            self.assertEqual(result, 1)
        finally:
            shutil.rmtree(temp_dir)

    def test_main_as_script(self):
        repo_root = Path(__file__).resolve().parents[2]
        os.environ["REPO_ROOT"] = str(repo_root)
        with contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as exc:
                runpy.run_path(str(repo_root / "ci/invariants/check_invariants.py"), run_name="__main__")
        expected = 0 if git_commit_exists("HEAD", repo_root) else 1
        self.assertEqual(exc.exception.code, expected)


class TestInvariantBase(unittest.TestCase):
    def test_base_check_not_implemented(self):
        with self.assertRaises(NotImplementedError):
            InvariantChecker(Path(".")).check()


if __name__ == "__main__":
    unittest.main()
