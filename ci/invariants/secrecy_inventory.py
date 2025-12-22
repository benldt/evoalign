#!/usr/bin/env python3
import json
import os
from pathlib import Path

from secrecy_utils import build_secrecy_audit


def main() -> int:
    repo_root = Path(os.environ.get("REPO_ROOT", ".")).resolve()
    output_path = Path(os.environ.get("SECRECY_AUDIT_OUTPUT", repo_root / "secrecy_audit.json"))
    fail_on_leak = os.environ.get("FAIL_ON_LEAK", "1") != "0"

    audit = build_secrecy_audit(repo_root)
    output_path.write_text(json.dumps(audit, indent=2))

    status = audit.get("status")
    print(f"Secrecy audit status: {status}")
    print(f"Wrote audit to {output_path}")

    if fail_on_leak and status == "fail":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
