import json

from base import InvariantCheck, InvariantChecker, InvariantResult


class PromotionInvariant(InvariantChecker):
    """
    Enforces: Lineage promotions and stage unlocks require:
    - Passing suite sets at required tolerances
    - Evidence pack in ledger
    """

    def get_pending_promotions(self) -> list:
        promotions = []

        ledger_path = self.repo_root / "control_plane/ledger/"
        if not ledger_path.exists():
            return promotions

        for entry_file in ledger_path.rglob("*.json"):
            try:
                with open(entry_file) as f:
                    entry = json.load(f)
                    if entry.get("entry_type") in ["promotion", "stage_unlock"]:
                        promotions.append({
                            "file": str(entry_file.relative_to(self.repo_root)),
                            "entry": entry,
                        })
            except (json.JSONDecodeError, IOError):
                continue

        return promotions

    def validate_promotion(self, promotion: dict) -> tuple[bool, str]:
        entry = promotion["entry"]

        gates = entry.get("gates_passed", [])
        if not gates:
            return False, "No gates_passed in promotion entry"

        for gate in gates:
            if not gate.get("suite_set_id"):
                return False, "Gate missing suite_set_id"
            if not gate.get("result_hash"):
                return False, "Gate missing result_hash"
            if gate.get("tolerances_met") is not True:
                return False, f"Gate {gate.get('suite_set_id')} did not meet tolerances"

        stage = entry.get("stage", "")
        if "full" in stage.lower() or "autonomy" in stage.lower():
            approvals = entry.get("approvals", [])
            if not any(a.get("approved") and a.get("signature") for a in approvals):
                return False, "High-risk stage unlock requires signed approval"

        return True, "Valid"

    def check(self) -> InvariantCheck:
        promotions = self.get_pending_promotions()

        if not promotions:
            return InvariantCheck(
                name="PROMOTION",
                result=InvariantResult.SKIP,
                message="No promotions in this change",
            )

        failures = []
        for promo in promotions:
            valid, reason = self.validate_promotion(promo)
            if not valid:
                failures.append({
                    "file": promo["file"],
                    "lineage_id": promo["entry"].get("lineage_id"),
                    "reason": reason,
                })

        if failures:
            return InvariantCheck(
                name="PROMOTION",
                result=InvariantResult.FAIL,
                message=f"{len(failures)} promotion(s) missing required evidence",
                details={"failures": failures},
            )

        return InvariantCheck(
            name="PROMOTION",
            result=InvariantResult.PASS,
            message=f"Verified {len(promotions)} promotion(s) have required evidence",
        )
