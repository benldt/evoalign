"""Chronicle Governance Invariant: validates anomaly event provenance."""

from base import InvariantCheck, InvariantChecker, InvariantResult
from file_utils import iter_data_files, load_data_file
from provenance_utils import load_aars


class ChronicleGovernanceInvariant(InvariantChecker):
    """Enforces: chronicle entries reference valid AARs and have required fields."""

    def _load_chronicle_entries(self) -> list[dict]:
        chronicle_dir = self.repo_root / "chronicle/events"
        entries = []
        for file_path in iter_data_files(chronicle_dir):
            data = load_data_file(file_path)
            if isinstance(data, dict):
                entries.append({"file": file_path, "data": data})
        return entries

    def check(self) -> InvariantCheck:
        entries = self._load_chronicle_entries()
        if not entries:
            return InvariantCheck(
                name="CHRONICLE_GOVERNANCE",
                result=InvariantResult.SKIP,
                message="No chronicle entries found",
            )

        failures = []
        aars = load_aars(self.repo_root)
        aar_ids = {aar["data"].get("aar_id") for aar in aars if aar["data"].get("aar_id")}

        for entry in entries:
            data = entry["data"]
            file_path = str(entry["file"].relative_to(self.repo_root))

            # Check required fields
            if not data.get("release_id"):
                failures.append({"file": file_path, "reason": "Missing release_id"})

            if not data.get("severity"):
                failures.append({"file": file_path, "reason": "Missing severity"})

            # Critical events should have response_actions
            severity = data.get("severity")
            if severity == "critical":
                response_actions = data.get("response_actions")
                if not isinstance(response_actions, list) or not response_actions:
                    failures.append({
                        "file": file_path,
                        "reason": "Critical event missing response_actions",
                    })

            # Validate aar_reference if present
            aar_ref = data.get("aar_reference")
            if aar_ref and aar_ref not in aar_ids:
                failures.append({
                    "file": file_path,
                    "reason": f"aar_reference '{aar_ref}' not found in AARs",
                })

        if failures:
            return InvariantCheck(
                name="CHRONICLE_GOVERNANCE",
                result=InvariantResult.FAIL,
                message=f"{len(failures)} chronicle governance issue(s) detected",
                details={"failures": failures},
            )

        return InvariantCheck(
            name="CHRONICLE_GOVERNANCE",
            result=InvariantResult.PASS,
            message=f"Verified governance for {len(entries)} chronicle entry(ies)",
        )

