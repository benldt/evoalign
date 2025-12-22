#!/usr/bin/env python3
import json
import os
from pathlib import Path

from context_scan import scan_context_classes


DEFAULT_PATHS = [
    "contracts/safety_contracts",
    "control_plane/governor/risk_fits",
    "control_plane/governor/oversight_plans",
    "control_plane/governor/sweeps",
    "deployments",
    "aars",
]


def main() -> int:
    repo_root = Path(os.environ.get("REPO_ROOT", ".")).resolve()
    output_path = Path(os.environ.get("CONTEXT_INVENTORY_OUTPUT", repo_root / "context_inventory.json"))

    results = scan_context_classes(repo_root, DEFAULT_PATHS)
    context_ids = sorted({entry["context_class"] for entry in results})

    payload = {
        "repo_root": str(repo_root),
        "context_ids": context_ids,
        "references": results,
    }

    output_path.write_text(json.dumps(payload, indent=2))

    print(f"Found {len(context_ids)} context id(s) across {len(results)} reference(s).")
    print(f"Wrote inventory to {output_path}")
    if context_ids:
        print("Contexts:")
        for context_id in context_ids:
            print(f"  - {context_id}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
