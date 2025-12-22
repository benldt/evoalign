#!/usr/bin/env python3
import io
import json
import runpy
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from evoalign import cli
from evoalign.provenance import sha256_data_file, sha256_file


class TestCli(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_hash_json_file(self):
        payload = {"name": "demo"}
        path = self.test_dir / "demo.json"
        path.write_text(json.dumps(payload))

        stdout = io.StringIO()
        with redirect_stdout(stdout):
            exit_code = cli.main(["hash", str(path)])
        self.assertEqual(exit_code, 0)
        self.assertEqual(stdout.getvalue().strip(), sha256_data_file(path))

    def test_hash_non_data_file(self):
        path = self.test_dir / "note.txt"
        path.write_text("hello")

        stdout = io.StringIO()
        with redirect_stdout(stdout):
            exit_code = cli.main(["hash", str(path)])
        self.assertEqual(exit_code, 0)
        self.assertEqual(stdout.getvalue().strip(), sha256_file(path))

    def test_hash_missing_file(self):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            exit_code = cli.main(["hash", str(self.test_dir / "missing.json")])
        self.assertEqual(exit_code, 1)
        self.assertIn("file not found", stderr.getvalue())

    def test_new_aar_with_template(self):
        template = self.test_dir / "template.json"
        template.write_text(json.dumps({"aar_id": "template"}))
        output_path = self.test_dir / "aars" / "aar_new.json"

        stdout = io.StringIO()
        with redirect_stdout(stdout):
            exit_code = cli.main([
                "new-aar",
                "--repo-root",
                str(self.test_dir),
                "--template",
                str(template),
                "--output",
                str(output_path),
                "--previous",
                "sha256:abc",
                "--aar-id",
                "aar_new",
                "--release-id",
                "release_new",
            ])
        self.assertEqual(exit_code, 0)
        data = json.loads(output_path.read_text())
        self.assertEqual(data["aar_id"], "aar_new")
        self.assertEqual(data["release_id"], "release_new")
        self.assertEqual(data["provenance"]["previous_aar_hash"], "sha256:abc")
        self.assertIn("generated_at", data)

    def test_new_aar_preserves_template_id(self):
        template = self.test_dir / "template.json"
        template.write_text(json.dumps({"aar_id": "template_id"}))
        data = cli.scaffold_aar(
            repo_root=self.test_dir,
            output_path=self.test_dir / "aars" / "aar_out.json",
            previous_hash=None,
            template_path=template,
            aar_id=None,
            release_id=None,
        )
        self.assertEqual(data["aar_id"], "template_id")

    def test_new_aar_with_existing_provenance(self):
        template = self.test_dir / "template.json"
        template.write_text(json.dumps({"aar_id": "template", "provenance": {}}))
        data = cli.scaffold_aar(
            repo_root=self.test_dir,
            output_path=self.test_dir / "aars" / "aar_out.json",
            previous_hash="sha256:prev",
            template_path=template,
            aar_id=None,
            release_id=None,
        )
        self.assertEqual(data["provenance"]["previous_aar_hash"], "sha256:prev")

    def test_template_not_object(self):
        template = self.test_dir / "template.json"
        template.write_text(json.dumps(["not", "object"]))
        with self.assertRaises(ValueError):
            cli.load_template(template, self.test_dir)

    def test_new_aar_without_template(self):
        output_path = self.test_dir / "aars" / "aar_empty.json"
        exit_code = cli.main([
            "new-aar",
            "--repo-root",
            str(self.test_dir),
            "--output",
            str(output_path),
        ])
        self.assertEqual(exit_code, 0)
        data = json.loads(output_path.read_text())
        self.assertEqual(data["aar_id"], "aar_empty")

    def test_new_aar_default_output(self):
        exit_code = cli.main([
            "new-aar",
            "--repo-root",
            str(self.test_dir),
        ])
        self.assertEqual(exit_code, 0)
        generated = list((self.test_dir / "aars").glob("aar_*.json"))
        self.assertEqual(len(generated), 1)

    def test_verify_chain_missing_repo(self):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            exit_code = cli.main(["verify-chain", "--repo-root", str(self.test_dir / "missing")])
        self.assertEqual(exit_code, 1)
        self.assertIn("repo root not found", stderr.getvalue())

    def test_verify_chain_success(self):
        repo_root = Path(__file__).resolve().parents[1]
        exit_code = cli.command_verify_chain(repo_root)
        self.assertEqual(exit_code, 0)

    def test_load_invariant_classes_missing_root(self):
        with self.assertRaises(RuntimeError):
            cli.load_invariant_classes(Path(self.test_dir / "missing"))

    def test_load_invariant_classes_reuse_path(self):
        invariants_root = Path(__file__).resolve().parents[1] / "ci" / "invariants"
        while str(invariants_root) in sys.path:
            sys.path.remove(str(invariants_root))
        classes, result_type = cli.load_invariant_classes(invariants_root)
        self.assertTrue(classes)
        self.assertTrue(hasattr(result_type, "FAIL"))
        classes_again, _ = cli.load_invariant_classes(invariants_root)
        self.assertEqual(len(classes), len(classes_again))

    def test_run_evidence_chain_failure(self):
        repo_root = self.test_dir
        fit_path = repo_root / "control_plane/governor/risk_fits/fit.json"
        fit_path.parent.mkdir(parents=True, exist_ok=True)
        fit_path.write_text(json.dumps({"fit_id": "fit_bad"}))
        invariants_root = Path(__file__).resolve().parents[1] / "ci" / "invariants"
        results, passed = cli.run_evidence_chain(repo_root, invariants_root=invariants_root)
        self.assertFalse(passed)
        self.assertTrue(results)

    def test_verify_chain_failure(self):
        repo_root = self.test_dir
        fit_path = repo_root / "control_plane/governor/risk_fits/fit.json"
        fit_path.parent.mkdir(parents=True, exist_ok=True)
        fit_path.write_text(json.dumps({"fit_id": "fit_bad"}))
        invariants_root = Path(__file__).resolve().parents[1] / "ci" / "invariants"

        stdout = io.StringIO()
        with redirect_stdout(stdout):
            exit_code = cli.command_verify_chain(repo_root, invariants_root=invariants_root)
        self.assertEqual(exit_code, 1)
        self.assertIn("Evidence chain verification FAILED", stdout.getvalue())

    def test_verify_chain_missing_invariants(self):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            exit_code = cli.command_verify_chain(self.test_dir)
        self.assertEqual(exit_code, 1)
        self.assertIn("Invariant modules not found", stderr.getvalue())

    def test_run_cli_as_script(self):
        path = self.test_dir / "demo.json"
        path.write_text(json.dumps({"name": "demo"}))
        cli_path = Path(__file__).resolve().parents[1] / "evoalign" / "cli.py"
        argv = sys.argv[:]
        sys.argv = ["cli.py", "hash", str(path)]
        try:
            with self.assertRaises(SystemExit) as ctx:
                runpy.run_path(str(cli_path), run_name="__main__")
            self.assertEqual(ctx.exception.code, 0)
        finally:
            sys.argv = argv


if __name__ == "__main__":
    unittest.main()
