#!/usr/bin/env python3
import json
import runpy
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "ci" / "invariants"))

from base import InvariantResult  # noqa: E402
from schema_validation import (  # noqa: E402
    SchemaTarget,
    SchemaValidationInvariant,
    iter_target_files,
    load_data_file,
    main,
)


def write_json(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2))


def write_yaml(path: Path, payload: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(payload)


class TestSchemaValidationInvariant(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp())
        (self.test_dir / "schemas").mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_skip_with_no_data_files(self):
        result = SchemaValidationInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.SKIP)

    def test_pass_with_valid_contract_yaml(self):
        write_json(
            self.test_dir / "schemas/SafetyContract.schema.json",
            {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "type": "object",
                "required": ["version"],
                "properties": {"version": {"type": "string"}},
            },
        )
        write_yaml(
            self.test_dir / "contracts/safety_contracts/contract.yaml",
            "version: 0.1.0\n",
        )

        result = SchemaValidationInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.PASS)

    def test_fail_invalid_contract(self):
        write_json(
            self.test_dir / "schemas/SafetyContract.schema.json",
            {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "type": "object",
                "required": ["version"],
                "properties": {"version": {"type": "string"}},
            },
        )
        write_yaml(self.test_dir / "contracts/safety_contracts/contract.yaml", "bad: 1\n")

        result = SchemaValidationInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_fail_missing_schema(self):
        write_yaml(self.test_dir / "contracts/safety_contracts/contract.yaml", "version: 0.1.0\n")

        result = SchemaValidationInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_fail_invalid_schema(self):
        write_json(
            self.test_dir / "schemas/Bad.schema.json",
            {"type": "unknown"},
        )
        result = SchemaValidationInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_fail_invalid_json_data(self):
        write_json(
            self.test_dir / "schemas/AAR.schema.json",
            {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "type": "object",
            },
        )
        bad_path = self.test_dir / "aars" / "bad.json"
        bad_path.parent.mkdir(parents=True, exist_ok=True)
        bad_path.write_text("{bad json")

        result = SchemaValidationInvariant(self.test_dir).check()
        self.assertEqual(result.result, InvariantResult.FAIL)

    def test_load_data_file_rejects_yaml(self):
        path = self.test_dir / "data.yaml"
        write_yaml(path, "key: value\n")
        with self.assertRaises(ValueError):
            load_data_file(path, allow_yaml=False)

    def test_load_data_file_unsupported_suffix(self):
        path = self.test_dir / "note.txt"
        path.write_text("hello")
        with self.assertRaises(ValueError):
            load_data_file(path, allow_yaml=True)

    def test_iter_target_files_skips_yaml(self):
        write_yaml(self.test_dir / "aars/skip.yaml", "aar_id: a1\n")
        target = SchemaTarget(path="aars", schema="AAR.schema.json")
        files = iter_target_files(self.test_dir, target)
        self.assertEqual(files, [])

    def test_iter_target_files_missing_path(self):
        target = SchemaTarget(path="missing", schema="AAR.schema.json")
        files = iter_target_files(self.test_dir, target)
        self.assertEqual(files, [])

    def test_main_exit_code(self):
        write_json(
            self.test_dir / "schemas/SafetyContract.schema.json",
            {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "type": "object",
                "required": ["version"],
                "properties": {"version": {"type": "string"}},
            },
        )
        write_yaml(
            self.test_dir / "contracts/safety_contracts/contract.yaml",
            "version: 0.1.0\n",
        )

        exit_code = main(["--repo-root", str(self.test_dir)])
        self.assertEqual(exit_code, 0)

    def test_main_failure_details(self):
        write_json(
            self.test_dir / "schemas/SafetyContract.schema.json",
            {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "type": "object",
                "required": ["version"],
                "properties": {"version": {"type": "string"}},
            },
        )
        contracts_dir = self.test_dir / "contracts" / "safety_contracts"
        contracts_dir.mkdir(parents=True, exist_ok=True)
        for idx in range(11):
            write_yaml(contracts_dir / f"bad_{idx}.yaml", "bad: true\n")

        exit_code = main(["--repo-root", str(self.test_dir)])
        self.assertEqual(exit_code, 1)

    def test_main_failure_details_small(self):
        write_json(
            self.test_dir / "schemas/SafetyContract.schema.json",
            {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "type": "object",
                "required": ["version"],
                "properties": {"version": {"type": "string"}},
            },
        )
        write_yaml(
            self.test_dir / "contracts/safety_contracts/bad.yaml",
            "bad: true\n",
        )
        exit_code = main(["--repo-root", str(self.test_dir)])
        self.assertEqual(exit_code, 1)

    def test_run_as_script(self):
        write_json(
            self.test_dir / "schemas/SafetyContract.schema.json",
            {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "type": "object",
                "required": ["version"],
                "properties": {"version": {"type": "string"}},
            },
        )
        write_yaml(
            self.test_dir / "contracts/safety_contracts/contract.yaml",
            "version: 0.1.0\n",
        )
        schema_path = Path(__file__).parent.parent.parent / "ci" / "invariants" / "schema_validation.py"
        argv = sys.argv[:]
        sys.argv = ["schema_validation.py", "--repo-root", str(self.test_dir)]
        try:
            with self.assertRaises(SystemExit) as ctx:
                runpy.run_path(str(schema_path), run_name="__main__")
            self.assertEqual(ctx.exception.code, 0)
        finally:
            sys.argv = argv


if __name__ == "__main__":
    unittest.main()
