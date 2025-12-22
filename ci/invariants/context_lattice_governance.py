from base import InvariantCheck, InvariantChecker, InvariantResult
from file_utils import iter_data_files, load_data_file


class ContextLatticeGovernanceInvariant(InvariantChecker):
    """Enforces: Context lattice changes require RFC reference and signatures."""

    def check(self) -> InvariantCheck:
        lattice_dir = self.repo_root / "contracts/context_lattice"
        lattice_files = iter_data_files(lattice_dir)
        if not lattice_files:
            return InvariantCheck(
                name="CONTEXT_LATTICE_GOVERNANCE",
                result=InvariantResult.SKIP,
                message="No context lattice files found",
            )

        failures = []
        for file_path in lattice_files:
            try:
                data = load_data_file(file_path)
            except Exception as exc:
                failures.append({
                    "file": str(file_path.relative_to(self.repo_root)),
                    "reason": f"Failed to parse lattice file: {exc}",
                })
                continue
            if not isinstance(data, dict):
                failures.append({
                    "file": str(file_path.relative_to(self.repo_root)),
                    "reason": "Lattice file must be a mapping",
                })
                continue
            metadata = (data or {}).get("metadata", {})
            if not metadata.get("rfc_reference"):
                failures.append({
                    "file": str(file_path.relative_to(self.repo_root)),
                    "reason": "No rfc_reference in lattice metadata",
                })
            approvals = metadata.get("approvals", [])
            signed = [a for a in approvals if a.get("signature")]
            if not signed:
                failures.append({
                    "file": str(file_path.relative_to(self.repo_root)),
                    "reason": "No signed approvals in lattice metadata",
                })

        if failures:
            return InvariantCheck(
                name="CONTEXT_LATTICE_GOVERNANCE",
                result=InvariantResult.FAIL,
                message=f"{len(failures)} lattice governance issue(s)",
                details={"failures": failures},
            )

        return InvariantCheck(
            name="CONTEXT_LATTICE_GOVERNANCE",
            result=InvariantResult.PASS,
            message=f"Verified {len(lattice_files)} lattice file(s) have required RFC and signatures",
        )
