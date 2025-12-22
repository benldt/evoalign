from base import InvariantCheck, InvariantChecker, InvariantResult
from secrecy_utils import build_secrecy_audit


class SecrecyInvariant(InvariantChecker):
    """Enforces: secret suite fingerprints do not appear in protected artifacts."""

    def check(self) -> InvariantCheck:
        audit = build_secrecy_audit(self.repo_root)
        status = audit.get("status")

        if status == "skip":
            return InvariantCheck(
                name="SECRECY",
                result=InvariantResult.SKIP,
                message=audit.get("message", "No secret suites defined"),
                details=audit,
            )

        if status != "pass":
            return InvariantCheck(
                name="SECRECY",
                result=InvariantResult.FAIL,
                message=audit.get("message", "Secrecy enforcement failed"),
                details=audit,
            )

        return InvariantCheck(
            name="SECRECY",
            result=InvariantResult.PASS,
            message="Secret suite fingerprints not found in protected artifacts",
            details=audit,
        )
