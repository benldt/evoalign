"""Lineage Integrity Invariant: validates ledger entry provenance and chain."""

from base import InvariantCheck, InvariantChecker, InvariantResult
from evoalign.provenance import sha256_canonical, verify_hash
from file_utils import iter_data_files, load_data_file


class LineageIntegrityInvariant(InvariantChecker):
    """Enforces: lineage entries have valid provenance and chain integrity."""

    def _load_lineage_entries(self) -> list[dict]:
        lineage_dir = self.repo_root / "lineage"
        entries = []
        for file_path in iter_data_files(lineage_dir):
            data = load_data_file(file_path)
            if isinstance(data, dict):
                entries.append({"file": file_path, "data": data})
        return entries

    def check(self) -> InvariantCheck:
        entries = self._load_lineage_entries()
        if not entries:
            return InvariantCheck(
                name="LINEAGE_INTEGRITY",
                result=InvariantResult.SKIP,
                message="No lineage entries found",
            )

        failures = []
        entry_hashes = {e["data"].get("entry_id"): sha256_canonical(e["data"]) for e in entries}

        for entry in entries:
            data = entry["data"]
            file_path = str(entry["file"].relative_to(self.repo_root))
            entry_id = data.get("entry_id")

            # Check required provenance
            provenance = data.get("provenance")
            if not isinstance(provenance, dict):
                failures.append({"file": file_path, "reason": "Missing provenance"})
                continue

            if not provenance.get("rfc_reference"):
                failures.append({"file": file_path, "reason": "Missing rfc_reference in provenance"})

            approvals = provenance.get("approvals")
            if not isinstance(approvals, list) or not approvals:
                failures.append({"file": file_path, "reason": "Missing approvals in provenance"})

            # Check promotion entries have gate_evidence
            entry_type = data.get("entry_type")
            if entry_type == "promotion":
                gate_evidence = data.get("gate_evidence")
                if not isinstance(gate_evidence, dict):
                    failures.append({"file": file_path, "reason": "Promotion entry missing gate_evidence"})

            # Check previous_entry_hash chain integrity
            prev_hash = data.get("previous_entry_hash")
            if prev_hash:
                found = any(verify_hash(prev_hash, h) for h in entry_hashes.values())
                if not found:
                    failures.append({
                        "file": file_path,
                        "reason": "previous_entry_hash not found in lineage entries",
                    })

        if failures:
            return InvariantCheck(
                name="LINEAGE_INTEGRITY",
                result=InvariantResult.FAIL,
                message=f"{len(failures)} lineage integrity issue(s) detected",
                details={"failures": failures},
            )

        return InvariantCheck(
            name="LINEAGE_INTEGRITY",
            result=InvariantResult.PASS,
            message=f"Verified integrity for {len(entries)} lineage entry(ies)",
        )

