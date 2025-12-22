# Context Lattice Semantics

This repo treats `context_class` as a string identifier whose meaning is defined
only in the context lattice registry. String patterns are not semantics.

## Registry

The canonical registry is:

`contracts/context_lattice/context_lattice_v0_1.yaml`

It defines:

- **Dimensions** that form a product lattice (set, ordered enum, boolean).
- **Contexts** as explicit descriptors over those dimensions.
- **Metadata** with RFC reference and signed approvals.

Every `context_class` used in artifacts must appear in the registry.

## Ordering and Coverage

Each dimension defines a partial order:

- **Set**: `A ≤ B` iff `A ⊆ B` (B is at least as capable).
- **Ordered enum**: `A ≤ B` iff `rank(A) ≤ rank(B)`.
- **Boolean**: `False ≤ True`.

A context `X` **covers** context `Y` if `Y ≤ X` for all dimensions. Coverage is
checked via the registry semantics, not string matching.

## Ambiguity Policy (Conservative)

When multiple covering items apply to a plan context:

- **Tolerances**: pick the strictest tolerance (minimum `tau`).
- **Risk fits**: compute risk under each applicable fit and take the maximum.

If no tolerance or no fit covers a plan context, checks fail closed.

## Unknown Contexts

Unknown `context_class` values are rejected. Fail closed:

- Unknown registry ID
- Unknown dimension
- Invalid or malformed values

This prevents new capabilities from being introduced without explicit semantics.
