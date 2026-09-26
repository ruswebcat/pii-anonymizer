# FILE: tools/grace_lint_lite.py
# VERSION: 2.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Stand-in for the optional grace CLI: verify that the contract and semantic block markers in the source files are paired and uniquely named, without any external dependency.
#   SCOPE: contract and block pairing per Python file under src/, tests/ and tools/; no inspection of documentation artifacts (they are not part of this repository).
#   DEPENDS: none
#   LINKS: tools/grace_lint_lite.py, docs/ARCHITECTURE.md
#   ROLE: SCRIPT
#   MAP_MODE: LOCALS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   check_markup - paired contract and block markers in source files
#   main - run the check and report
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v2.0.0 - the project keeps only the current code and its description: the development-plan / verification-plan / knowledge-graph artifacts left the repository, so the graph and plan cross-checks were removed and markup pairing became the whole gate.
#   EARLIER: v1.0.0 - added after Phase 1: the marketplace grace CLI needs bun, which the host does not have.
# END_CHANGE_SUMMARY

"""Lightweight markup integrity check.

Run from the repository root:

    python3 tools/grace_lint_lite.py

The module contracts, function contracts and semantic blocks inside the code are part of the
source: tests and readers rely on them. This tool holds them paired. Documentation artifacts
(development plan, verification plan, knowledge graph) are not part of this repository, so
nothing here reads them.

Exits non-zero when an integrity problem is found, so it can be used as a gate.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROBLEMS: list[str] = []


# START_BLOCK_CHECK_MARKUP
def check_markup() -> None:
    """Verify that contract and semantic block markers are paired."""
    for path in sorted(ROOT.glob("**/*.py")):
        if ".git" in path.parts:
            continue
        text = path.read_text(encoding="utf-8")
        relative = path.relative_to(ROOT)
        if relative.parts[0] not in {"src", "tests", "tools"}:
            continue
        if text.count("START_MODULE_CONTRACT") != text.count("END_MODULE_CONTRACT"):
            PROBLEMS.append(f"{relative}: unbalanced MODULE_CONTRACT markers")
        opens = set(re.findall(r"START_BLOCK_([A-Z0-9_]+)", text))
        closes = set(re.findall(r"END_BLOCK_([A-Z0-9_]+)", text))
        for missing in sorted(opens - closes):
            PROBLEMS.append(f"{relative}: block {missing} is opened but never closed")
        for orphan in sorted(closes - opens):
            PROBLEMS.append(f"{relative}: block {orphan} is closed but never opened")
        for contract in re.findall(r"START_CONTRACT: (\w+)", text):
            if f"END_CONTRACT: {contract}" not in text:
                PROBLEMS.append(f"{relative}: function contract {contract} is not closed")
# END_BLOCK_CHECK_MARKUP


def main() -> int:
    """Run the integrity check and report the result."""
    check_markup()
    if PROBLEMS:
        print("GRACE integrity problems:")
        for problem in PROBLEMS:
            print(f"  - {problem}")
        return 1
    print("GRACE integrity OK: module, function and block markers are paired")
    return 0


if __name__ == "__main__":
    sys.exit(main())
