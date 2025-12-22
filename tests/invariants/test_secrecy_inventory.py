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

from evoalign.provenance import sha256_data_file  # noqa: E402
import secrecy_inventory  # noqa: E402


def write_json(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2))


class TestSecrecyInventory(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp())
        self.prev_repo_root = os.environ.get("REPO_ROOT")
        self.prev_output = os.environ.get("SECRECY_AUDIT_OUTPUT")
        self.prev_fail = os.environ.get("FAIL_ON_LEAK")

    def tearDown(self):
        if self.prev_repo_root is None:
            os.environ.pop("REPO_ROOT", None)
        else:
            os.environ["REPO_ROOT"] = self.prev_repo_root
        if self.prev_output is None:
            os.environ.pop("SECRECY_AUDIT_OUTPUT", None)
        else:
            os.environ["SECRECY_AUDIT_OUTPUT"] = self.prev_output
        if self.prev_fail is None:
            os.environ.pop("FAIL_ON_LEAK", None)
        else:
            os.environ["FAIL_ON_LEAK"] = self.prev_fail
        shutil.rmtree(self.test_dir)

    def _write_suite_registry(self, suites):
        path = self.test_dir / "control_plane/evals/suites/registry.json"
        write_json(path, {
            "registry_version": "0.2.0",
            "generated_at": "2025-01-01T00:00:00Z",
            "suites": suites,
        })
        return sha256_data_file(path)

    def _write_secret_registry(self, suite_registry_hash, suites):
        path = self.test_dir / "control_plane/evals/suites/hash_registries/secret_suite_hashes_v1.json"
        write_json(path, {
            "registry_version": "1.0",
            "hashing_scheme": {
                "scheme_id": "sha256-v1",
                "normalization": "json_canonical_v1",
                "digest_prefix": "sha256:",
            },
            "generated_at": "2025-01-01T00:00:00Z",
            "suite_registry_hash": suite_registry_hash,
            "suites": suites,
        })

    def test_main_pass(self):
        registry_hash = self._write_suite_registry([
            {"suite_id": "secret", "secrecy_level": "secret"}
        ])
        self._write_secret_registry(registry_hash, [{
            "suite_id": "secret",
            "suite_version": "1.0.0",
            "suite_fingerprint_root": "sha256:dead",
            "n_test_cases": 0,
            "test_case_fingerprints": [],
        }])

        output = self.test_dir / "audit.json"
        os.environ["REPO_ROOT"] = str(self.test_dir)
        os.environ["SECRECY_AUDIT_OUTPUT"] = str(output)

        with contextlib.redirect_stdout(io.StringIO()):
            result = secrecy_inventory.main()

        payload = json.loads(output.read_text())
        self.assertEqual(payload["status"], "pass")
        self.assertEqual(result, 0)

    def test_main_fail(self):
        self._write_suite_registry([
            {"suite_id": "secret", "secrecy_level": "secret"}
        ])
        output = self.test_dir / "audit.json"
        os.environ["REPO_ROOT"] = str(self.test_dir)
        os.environ["SECRECY_AUDIT_OUTPUT"] = str(output)

        with contextlib.redirect_stdout(io.StringIO()):
            result = secrecy_inventory.main()

        payload = json.loads(output.read_text())
        self.assertEqual(payload["status"], "fail")
        self.assertEqual(result, 1)

    def test_main_fail_on_leak_disabled(self):
        self._write_suite_registry([
            {"suite_id": "secret", "secrecy_level": "secret"}
        ])
        output = self.test_dir / "audit.json"
        os.environ["REPO_ROOT"] = str(self.test_dir)
        os.environ["SECRECY_AUDIT_OUTPUT"] = str(output)
        os.environ["FAIL_ON_LEAK"] = "0"

        with contextlib.redirect_stdout(io.StringIO()):
            result = secrecy_inventory.main()

        self.assertEqual(result, 0)

    def test_inventory_as_script(self):
        self._write_suite_registry([
            {"suite_id": "public", "secrecy_level": "public"}
        ])
        os.environ["REPO_ROOT"] = str(self.test_dir)
        os.environ["SECRECY_AUDIT_OUTPUT"] = str(self.test_dir / "audit.json")

        module_path = Path(__file__).resolve().parents[2] / "ci/invariants/secrecy_inventory.py"
        with contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as exc:
                runpy.run_path(str(module_path), run_name="__main__")
        self.assertEqual(exc.exception.code, 0)


if __name__ == "__main__":
    unittest.main()
