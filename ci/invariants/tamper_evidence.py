"""Tamper Evidence Invariant: validates merkle roots and optional signatures."""

from pathlib import Path

from base import InvariantCheck, InvariantChecker, InvariantResult
from evoalign.merkle import compute_artifact_merkle_root, merkle_root
from evoalign.provenance import sha256_canonical, sha256_data_file, verify_hash
from file_utils import iter_data_files, load_data_file
from provenance_utils import load_aars


def load_key_registry(repo_root: Path) -> dict | None:
    """Load the public key registry if it exists."""
    keys_dir = repo_root / "control_plane/keys"
    for file_path in iter_data_files(keys_dir):
        data = load_data_file(file_path)
        if isinstance(data, dict) and "keys" in data:
            return {"file": file_path, "data": data}
    return None


def load_lineage_entry_hashes(repo_root: Path) -> list[str]:
    """Load all lineage entry hashes for merkle root computation."""
    lineage_dir = repo_root / "lineage"
    hashes = []
    for file_path in iter_data_files(lineage_dir):
        data = load_data_file(file_path)
        if isinstance(data, dict):
            hashes.append(sha256_canonical(data))
    return sorted(hashes)


class TamperEvidenceInvariant(InvariantChecker):
    """Enforces: merkle roots and signatures are verifiable when present."""

    def check(self) -> InvariantCheck:
        aars = load_aars(self.repo_root)
        key_registry = load_key_registry(self.repo_root)

        if not aars and not key_registry:
            return InvariantCheck(
                name="TAMPER_EVIDENCE",
                result=InvariantResult.SKIP,
                message="No AARs or key registry found",
            )

        failures = []
        key_ids = set()
        if key_registry:
            for key in key_registry["data"].get("keys", []):
                if isinstance(key, dict) and not key.get("revoked"):
                    key_id = key.get("key_id")
                    if key_id:
                        key_ids.add(key_id)

        lineage_hashes = load_lineage_entry_hashes(self.repo_root)
        computed_ledger_root = merkle_root(lineage_hashes) if lineage_hashes else ""

        for aar in aars:
            data = aar["data"]
            file_path = str(aar["file"].relative_to(self.repo_root))

            # Check provenance.merkle_root if present
            provenance = data.get("provenance") or {}
            claimed_merkle = provenance.get("merkle_root")
            if claimed_merkle:
                risk_artifacts = data.get("risk_modeling", {}).get("risk_fit_artifacts", [])
                if risk_artifacts:
                    computed = compute_artifact_merkle_root(risk_artifacts, hash_field="fit_hash")
                    if computed and not verify_hash(claimed_merkle, computed):
                        failures.append({
                            "file": file_path,
                            "reason": "provenance.merkle_root mismatch",
                        })

            # Check lineage_references.ledger_root_hash if present
            lineage_refs = data.get("lineage_references") or {}
            claimed_ledger_root = lineage_refs.get("ledger_root_hash")
            if claimed_ledger_root:
                if not computed_ledger_root:
                    failures.append({
                        "file": file_path,
                        "reason": "ledger_root_hash claimed but no lineage entries found",
                    })
                elif not verify_hash(claimed_ledger_root, computed_ledger_root):
                    failures.append({
                        "file": file_path,
                        "reason": "ledger_root_hash mismatch",
                    })

            # Check governance approvals reference valid keys (if key registry exists)
            if key_ids:
                governance = data.get("governance") or {}
                for approval in governance.get("approvals", []) or []:
                    if not isinstance(approval, dict):
                        continue
                    sig = approval.get("signature")
                    # If signature looks like a key reference, validate it exists
                    if sig and sig.startswith("key:"):
                        key_ref = sig.replace("key:", "")
                        if key_ref not in key_ids:
                            failures.append({
                                "file": file_path,
                                "reason": f"Approval references unknown key: {key_ref}",
                            })

        if failures:
            return InvariantCheck(
                name="TAMPER_EVIDENCE",
                result=InvariantResult.FAIL,
                message=f"{len(failures)} tamper evidence issue(s) detected",
                details={"failures": failures},
            )

        checked_items = []
        if aars:
            checked_items.append(f"{len(aars)} AAR(s)")
        if key_registry:
            checked_items.append(f"{len(key_ids)} active key(s)")

        return InvariantCheck(
            name="TAMPER_EVIDENCE",
            result=InvariantResult.PASS,
            message=f"Verified tamper evidence for {', '.join(checked_items)}",
        )

