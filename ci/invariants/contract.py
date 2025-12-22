import json

import yaml

from base import InvariantCheck, InvariantChecker, InvariantResult
from lattice_utils import load_lattice_index
from evoalign.context_lattice import ContextLatticeError


class ContractInvariant(InvariantChecker):
    """
    Enforces: Changes to Safety Contract require:
    - Approved RFC reference
    - Panel signatures
    """

    def get_contract_changes(self, changed_files: list | None = None) -> list:
        changes = []

        contract_path = self.repo_root / "contracts/safety_contracts/"
        if not contract_path.exists():
            return changes

        if changed_files:
            for file_name in changed_files:
                if "safety_contract" in file_name.lower():
                    changes.append({
                        "file": file_name,
                        "type": "modified",
                    })
        else:
            for contract_file in contract_path.rglob("*.yaml"):
                changes.append({
                    "file": str(contract_file.relative_to(self.repo_root)),
                    "type": "check_metadata",
                })
            for contract_file in contract_path.rglob("*.json"):
                changes.append({
                    "file": str(contract_file.relative_to(self.repo_root)),
                    "type": "check_metadata",
                })

        return changes

    def validate_contract_change(self, change: dict, lattice_index: dict) -> tuple[bool, str]:
        file_path = self.repo_root / change["file"]

        if not file_path.exists():
            return False, "Contract file not found"

        try:
            if file_path.suffix == ".yaml":
                with open(file_path) as f:
                    contract = yaml.safe_load(f)
            else:
                with open(file_path) as f:
                    contract = json.load(f)
        except Exception as exc:
            return False, f"Failed to parse contract: {exc}"

        metadata = contract.get("metadata", {})

        if not metadata.get("rfc_reference"):
            return False, "No rfc_reference in contract metadata"

        approvals = metadata.get("approvals", [])
        if not approvals:
            return False, "No approvals in contract metadata"

        signed_approvals = [a for a in approvals if a.get("signature")]
        if not signed_approvals:
            return False, "No signed approvals in contract"

        if not metadata.get("context_lattice_version"):
            return False, "No context_lattice_version in contract metadata"
        if not metadata.get("context_lattice_hash"):
            return False, "No context_lattice_hash in contract metadata"

        if not lattice_index:
            return False, "No context lattice registry available"

        lattice_version = metadata.get("context_lattice_version")
        lattice_hash = metadata.get("context_lattice_hash")
        if lattice_version not in lattice_index:
            return False, f"Unknown context lattice version '{lattice_version}'"

        expected_hash = lattice_index[lattice_version]["hash"]
        normalized_hash = lattice_hash.replace("sha256:", "")
        if normalized_hash != expected_hash:
            return False, f"Context lattice hash mismatch for version {lattice_version}"

        return True, "Valid"

    def check(self) -> InvariantCheck:
        changes = self.get_contract_changes()

        if not changes:
            return InvariantCheck(
                name="CONTRACT",
                result=InvariantResult.SKIP,
                message="No Safety Contract changes detected",
            )

        try:
            lattice_index = load_lattice_index(self.repo_root)
        except ContextLatticeError as exc:
            return InvariantCheck(
                name="CONTRACT",
                result=InvariantResult.FAIL,
                message=str(exc),
            )

        failures = []
        for change in changes:
            valid, reason = self.validate_contract_change(change, lattice_index)
            if not valid:
                failures.append({
                    "file": change["file"],
                    "reason": reason,
                })

        if failures:
            return InvariantCheck(
                name="CONTRACT",
                result=InvariantResult.FAIL,
                message=f"{len(failures)} contract(s) missing required governance",
                details={"failures": failures},
            )

        return InvariantCheck(
            name="CONTRACT",
            result=InvariantResult.PASS,
            message=f"Verified {len(changes)} contract(s) have required RFC and signatures",
        )
