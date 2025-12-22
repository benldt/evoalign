from base import InvariantCheck, InvariantChecker, InvariantResult
from context_scan import scan_context_classes
from evoalign.context_lattice import ContextLatticeError
from lattice_utils import load_context_lattice


class ContextRegistryInvariant(InvariantChecker):
    """Enforces: context_class values must exist in the context lattice registry."""

    SEARCH_PATHS = [
        "contracts/safety_contracts",
        "control_plane/governor/risk_fits",
        "control_plane/governor/oversight_plans",
        "control_plane/governor/sweeps",
        "deployments",
        "aars",
    ]

    def check(self) -> InvariantCheck:
        try:
            lattice, lattice_path = load_context_lattice(self.repo_root)
        except ContextLatticeError as exc:
            return InvariantCheck(
                name="CONTEXT_REGISTRY",
                result=InvariantResult.FAIL,
                message=str(exc),
            )

        references = scan_context_classes(self.repo_root, self.SEARCH_PATHS)
        if not references:
            return InvariantCheck(
                name="CONTEXT_REGISTRY",
                result=InvariantResult.SKIP,
                message=f"No context_class references found (lattice: {lattice_path.name})",
            )

        missing = [
            ref
            for ref in references
            if ref["context_class"] not in lattice.contexts
        ]

        if missing:
            return InvariantCheck(
                name="CONTEXT_REGISTRY",
                result=InvariantResult.FAIL,
                message=f"{len(missing)} context reference(s) missing from lattice registry",
                details={"missing": missing},
            )

        return InvariantCheck(
            name="CONTEXT_REGISTRY",
            result=InvariantResult.PASS,
            message=f"Verified {len(references)} context reference(s) against lattice registry",
        )
