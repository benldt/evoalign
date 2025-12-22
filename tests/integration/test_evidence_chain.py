#!/usr/bin/env python3
import json
import unittest
from pathlib import Path

from evoalign import cli
from evoalign.provenance import sha256_data_file


class TestEvidenceChainIntegration(unittest.TestCase):
    def test_evidence_chain_with_new_aar(self):
        repo_root = Path(__file__).resolve().parents[2]
        template_path = repo_root / "aars" / "aar_v0_1.json"
        output_path = repo_root / "aars" / "aar_integration_test.json"
        previous_hash = sha256_data_file(template_path)

        try:
            cli.command_new_aar(
                repo_root=repo_root,
                output_path=output_path,
                previous_hash=previous_hash,
                template_path=template_path,
                aar_id="aar_integration_test",
                release_id="release_integration_test",
            )

            data = json.loads(output_path.read_text())
            self.assertEqual(data["provenance"]["previous_aar_hash"], previous_hash)

            results, passed = cli.run_evidence_chain(repo_root)
            self.assertTrue(passed)
            self.assertTrue(results)
        finally:
            output_path.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
