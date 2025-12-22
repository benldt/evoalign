from base import InvariantCheck, InvariantChecker, InvariantResult
from evoalign.provenance import sha256_canonical, sha256_data_file, verify_hash
from file_utils import iter_data_files
from provenance_utils import load_aars
from secrecy_utils import SECRET_HASH_REGISTRY_PATH


class AarEvidenceChainInvariant(InvariantChecker):
    """Enforces: AAR evidence chain binds to contracts and secret registries."""

    def _load_contract_hashes(self) -> list[str]:
        contracts_dir = self.repo_root / "contracts/safety_contracts"
        hashes = []
        for file_path in iter_data_files(contracts_dir):
            hashes.append(sha256_data_file(file_path))
        return hashes

    def _load_secret_registry_hash(self) -> str | None:
        registry_path = self.repo_root / SECRET_HASH_REGISTRY_PATH
        if not registry_path.exists():
            return None
        return sha256_data_file(registry_path)

    def check(self) -> InvariantCheck:
        aars = load_aars(self.repo_root)
        if not aars:
            return InvariantCheck(
                name="AAR_EVIDENCE_CHAIN",
                result=InvariantResult.SKIP,
                message="No AARs found",
            )

        contract_hashes = self._load_contract_hashes()
        secret_registry_hash = self._load_secret_registry_hash()
        aar_hashes = [sha256_canonical(aar["data"]) for aar in aars]

        failures = []
        for aar in aars:
            data = aar["data"]
            file_path = str(aar["file"].relative_to(self.repo_root))

            claimed_contract_hash = (data.get("safety_contract") or {}).get("contract_hash")
            if claimed_contract_hash:
                if not contract_hashes:
                    failures.append({
                        "file": file_path,
                        "reason": "No contract files found for claimed contract_hash",
                    })
                elif not any(verify_hash(claimed_contract_hash, h) for h in contract_hashes):
                    failures.append({
                        "file": file_path,
                        "reason": "AAR contract_hash does not match any contract file",
                    })

            claimed_secret_hash = (data.get("reproducibility") or {}).get("secret_hash_registry_hash")
            if claimed_secret_hash:
                if not secret_registry_hash:
                    failures.append({
                        "file": file_path,
                        "reason": "Secret hash registry missing for claimed secret_hash_registry_hash",
                    })
                elif not verify_hash(claimed_secret_hash, secret_registry_hash):
                    failures.append({
                        "file": file_path,
                        "reason": "AAR secret_hash_registry_hash mismatch",
                    })

            previous_hash = (data.get("provenance") or {}).get("previous_aar_hash")
            if previous_hash:
                if not any(verify_hash(previous_hash, h) for h in aar_hashes):
                    failures.append({
                        "file": file_path,
                        "reason": "previous_aar_hash not found in existing AARs",
                    })

        if failures:
            return InvariantCheck(
                name="AAR_EVIDENCE_CHAIN",
                result=InvariantResult.FAIL,
                message=f"{len(failures)} AAR evidence issue(s) detected",
                details={"failures": failures},
            )

        return InvariantCheck(
            name="AAR_EVIDENCE_CHAIN",
            result=InvariantResult.PASS,
            message=f"Verified evidence chain for {len(aars)} AAR(s)",
        )
