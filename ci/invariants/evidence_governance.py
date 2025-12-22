from base import InvariantCheck, InvariantChecker, InvariantResult
from provenance_utils import load_eval_runs, load_risk_fits, load_suite_sets, load_sweeps


def has_signed_approval(approvals) -> bool:
    if not isinstance(approvals, list):
        return False
    for approval in approvals:
        if isinstance(approval, dict) and approval.get("signature"):
            return True
    return False


class EvidenceGovernanceInvariant(InvariantChecker):
    """Enforces: evidence artifacts include RFC references and signed approvals."""

    def check(self) -> InvariantCheck:
        fits = load_risk_fits(self.repo_root)
        sweeps = load_sweeps(self.repo_root)
        eval_runs = load_eval_runs(self.repo_root)
        suite_sets = load_suite_sets(self.repo_root)

        if not fits and not sweeps and not eval_runs and not suite_sets:
            return InvariantCheck(
                name="EVIDENCE_GOVERNANCE",
                result=InvariantResult.SKIP,
                message="No evidence artifacts found",
            )

        failures = []

        for fit in fits:
            prov = fit["data"].get("provenance") or {}
            if not prov.get("rfc_reference"):
                failures.append({
                    "file": str(fit["file"].relative_to(self.repo_root)),
                    "reason": "Missing rfc_reference in fit provenance",
                })
            if not has_signed_approval(prov.get("approvals")):
                failures.append({
                    "file": str(fit["file"].relative_to(self.repo_root)),
                    "reason": "Missing signed approval in fit provenance",
                })

        for sweep in sweeps.values():
            data = sweep["data"]
            if not data.get("rfc_reference"):
                failures.append({
                    "file": str(sweep["file"].relative_to(self.repo_root)),
                    "reason": "Missing rfc_reference in sweep manifest",
                })
            if not has_signed_approval(data.get("approvals")):
                failures.append({
                    "file": str(sweep["file"].relative_to(self.repo_root)),
                    "reason": "Missing signed approval in sweep manifest",
                })

        for run in eval_runs.values():
            data = run["data"]
            if not data.get("rfc_reference"):
                failures.append({
                    "file": str(run["file"].relative_to(self.repo_root)),
                    "reason": "Missing rfc_reference in eval run manifest",
                })
            if not has_signed_approval(data.get("approvals")):
                failures.append({
                    "file": str(run["file"].relative_to(self.repo_root)),
                    "reason": "Missing signed approval in eval run manifest",
                })

        for suite_set in suite_sets.values():
            data = suite_set["data"]
            if not data.get("rfc_reference"):
                failures.append({
                    "file": str(suite_set["file"].relative_to(self.repo_root)),
                    "reason": "Missing rfc_reference in suite set manifest",
                })
            if not has_signed_approval(data.get("approvals")):
                failures.append({
                    "file": str(suite_set["file"].relative_to(self.repo_root)),
                    "reason": "Missing signed approval in suite set manifest",
                })

        if failures:
            return InvariantCheck(
                name="EVIDENCE_GOVERNANCE",
                result=InvariantResult.FAIL,
                message=f"{len(failures)} governance issue(s) detected",
                details={"failures": failures},
            )

        return InvariantCheck(
            name="EVIDENCE_GOVERNANCE",
            result=InvariantResult.PASS,
            message="Verified governance metadata for evidence artifacts",
        )
