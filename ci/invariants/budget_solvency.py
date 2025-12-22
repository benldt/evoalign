from base import InvariantCheck, InvariantChecker, InvariantResult
from evoalign.context_lattice import ContextLatticeError
from lattice_utils import (
    compute_fit_risk,
    extract_tolerances,
    get_numeric,
    load_context_lattice,
    load_oversight_plans,
    load_risk_fits,
    load_safety_contracts,
)


class BudgetSolvencyInvariant(InvariantChecker):
    """Enforces: Oversight plans satisfy strictest tolerances using worst-case fits."""

    def check(self) -> InvariantCheck:
        try:
            lattice, lattice_path = load_context_lattice(self.repo_root)
        except ContextLatticeError as exc:
            return InvariantCheck(
                name="BUDGET_SOLVENCY",
                result=InvariantResult.FAIL,
                message=str(exc),
            )

        plans = load_oversight_plans(self.repo_root)
        if not plans:
            return InvariantCheck(
                name="BUDGET_SOLVENCY",
                result=InvariantResult.SKIP,
                message=f"No oversight plans found (lattice: {lattice_path.name})",
            )

        contracts = load_safety_contracts(self.repo_root)
        tolerances = extract_tolerances(contracts)
        if not tolerances:
            return InvariantCheck(
                name="BUDGET_SOLVENCY",
                result=InvariantResult.FAIL,
                message="No safety contract tolerances found",
            )

        fits = load_risk_fits(self.repo_root)
        if not fits:
            return InvariantCheck(
                name="BUDGET_SOLVENCY",
                result=InvariantResult.FAIL,
                message="No risk fits found",
            )

        hazards = sorted({
            (tol.get("hazard_id"), tol.get("severity_id"))
            for tol in tolerances
            if tol.get("hazard_id") and tol.get("severity_id")
        })

        failures = []
        for plan in plans:
            plan_context = plan["context_class"]
            plan_label = plan.get("plan_id") or plan_context
            for hazard_id, severity_id in hazards:
                applicable_tolerances = []
                for tol in tolerances:
                    if tol.get("hazard_id") != hazard_id or tol.get("severity_id") != severity_id:
                        continue
                    tol_context = tol.get("context_class")
                    if not tol_context:
                        failures.append({
                            "plan": plan_label,
                            "reason": "Tolerance missing context_class",
                            "hazard_id": hazard_id,
                            "severity_id": severity_id,
                            "file": str(tol.get("file", "")),
                        })
                        continue
                    try:
                        if lattice.covers(tol_context, plan_context):
                            applicable_tolerances.append(tol)
                    except ContextLatticeError as exc:
                        failures.append({
                            "plan": plan_label,
                            "reason": str(exc),
                            "hazard_id": hazard_id,
                            "severity_id": severity_id,
                            "file": str(tol.get("file", "")),
                        })

                if not applicable_tolerances:
                    failures.append({
                        "plan": plan_label,
                        "reason": "No tolerance covers plan context",
                        "hazard_id": hazard_id,
                        "severity_id": severity_id,
                        "file": str(plan["file"].relative_to(self.repo_root)),
                    })
                    continue

                tau_values = []
                for tol in applicable_tolerances:
                    try:
                        tau_values.append(get_numeric(tol.get("tau"), "tau", str(tol.get("file", ""))))
                    except ValueError as exc:
                        failures.append({
                            "plan": plan_label,
                            "reason": str(exc),
                            "hazard_id": hazard_id,
                            "severity_id": severity_id,
                            "file": str(tol.get("file", "")),
                        })
                if not tau_values:
                    failures.append({
                        "plan": plan_label,
                        "reason": "No valid tau values found",
                        "hazard_id": hazard_id,
                        "severity_id": severity_id,
                        "file": str(plan["file"].relative_to(self.repo_root)),
                    })
                    continue
                strictest_tau = min(tau_values)

                applicable_fits = []
                for fit in fits:
                    fit_data = fit["data"]
                    if fit_data.get("hazard_id") != hazard_id or fit_data.get("severity_id") != severity_id:
                        continue
                    fit_context = fit_data.get("context_class")
                    if not fit_context:
                        failures.append({
                            "plan": plan_label,
                            "reason": "Risk fit missing context_class",
                            "hazard_id": hazard_id,
                            "severity_id": severity_id,
                            "file": str(fit["file"].relative_to(self.repo_root)),
                        })
                        continue
                    try:
                        if lattice.covers(fit_context, plan_context):
                            applicable_fits.append(fit)
                    except ContextLatticeError as exc:
                        failures.append({
                            "plan": plan_label,
                            "reason": str(exc),
                            "hazard_id": hazard_id,
                            "severity_id": severity_id,
                            "file": str(fit["file"].relative_to(self.repo_root)),
                        })

                if not applicable_fits:
                    failures.append({
                        "plan": plan_label,
                        "reason": "No risk fit covers plan context",
                        "hazard_id": hazard_id,
                        "severity_id": severity_id,
                        "file": str(plan["file"].relative_to(self.repo_root)),
                    })
                    continue

                risks = []
                for fit in applicable_fits:
                    try:
                        risk = compute_fit_risk(
                            fit["data"] | {"file": str(fit["file"].relative_to(self.repo_root))},
                            plan.get("channel_allocations"),
                        )
                        risks.append(risk)
                    except Exception as exc:
                        failures.append({
                            "plan": plan_label,
                            "reason": str(exc),
                            "hazard_id": hazard_id,
                            "severity_id": severity_id,
                            "file": str(fit["file"].relative_to(self.repo_root)),
                        })

                if not risks:
                    failures.append({
                        "plan": plan_label,
                        "reason": "No computable risk from applicable fits",
                        "hazard_id": hazard_id,
                        "severity_id": severity_id,
                        "file": str(plan["file"].relative_to(self.repo_root)),
                    })
                    continue

                worst_risk = max(risks)
                if worst_risk > strictest_tau:
                    failures.append({
                        "plan": plan_label,
                        "reason": f"Risk {worst_risk:.6g} exceeds tau {strictest_tau:.6g}",
                        "hazard_id": hazard_id,
                        "severity_id": severity_id,
                        "file": str(plan["file"].relative_to(self.repo_root)),
                    })

        if failures:
            return InvariantCheck(
                name="BUDGET_SOLVENCY",
                result=InvariantResult.FAIL,
                message=f"{len(failures)} solvency issue(s) detected",
                details={"failures": failures},
            )

        return InvariantCheck(
            name="BUDGET_SOLVENCY",
            result=InvariantResult.PASS,
            message=f"Verified {len(plans)} oversight plan(s) against lattice and tolerances",
        )
