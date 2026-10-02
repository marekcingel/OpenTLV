#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel

"""Check project source license notices: run with --fix to add missing notices.

The policy below is shared by the all-files pre-commit hook and CI. Only Git
tracked files are checked, so build outputs and downloaded dependencies are
never modified. Source templates are covered so generated C files inherit
their notices.
"""

import argparse
import fnmatch
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
COMMENT_PREFIXES = {
    ".c": "//", ".h": "//", ".cpp": "//", ".hpp": "//",
    ".rs": "//", ".js": "//", ".ts": "//", ".java": "//",
    ".go": "//", ".py": "#", ".lua": "--",
}
# Reserved locations for generated output or third-party code. No currently
# tracked sources require these exemptions. New exceptions belong here, with
# an ownership/generation reason; do not duplicate them in hook/CI filters.
EXCLUDED_PATHS = {
    "vendor/*": "third-party sources retain their original license notices",
    "third_party/*": "third-party sources retain their original license notices",
    "generated/*": "generated output; maintain notices in its source templates",
}
ENCODING = re.compile(br"^[ \t\f]*#.*?coding[:=][ \t]*[-\w.]+")


def comment_prefix(path):
    """Return the policy comment prefix, or None for an excluded file."""
    if any(fnmatch.fnmatchcase(path, pattern) for pattern in EXCLUDED_PATHS):
        return None
    source = Path(path)
    if source.suffix == ".in":
        source = source.with_suffix("")
    return COMMENT_PREFIXES.get(source.suffix)


def header_offset(data, path):
    """Preserve a UTF-8 BOM, shebang, and Python encoding declaration."""
    offset = 3 if data.startswith(b"\xef\xbb\xbf") else 0
    lines = data[offset:].splitlines(keepends=True)
    start = 1 if lines and lines[0].startswith(b"#!") else 0
    if Path(path).suffix == ".py":
        for index, line in enumerate(lines[:2]):
            if ENCODING.match(line):
                start = max(start, index + 1)
    return offset + sum(len(line) for line in lines[:start])


def check_file(path, relative, fix=False):
    prefix = comment_prefix(relative)
    if prefix is None:
        return True
    data = path.read_bytes()
    offset = header_offset(data, relative)
    notice = [f"{prefix} SPDX-License-Identifier: MIT".encode(),
              f"{prefix} Copyright (c) 2026 Marek Cingel".encode()]
    if data[offset:].splitlines()[:2] == notice:
        return True
    if fix:
        # Never insert a contradictory or duplicate license declaration.
        if b"SPDX-License-Identifier:" in data or b"Copyright" in data:
            print(f"{relative}: existing notice requires manual review")
            return False
        newline = b"\r\n" if b"\r\n" in data else b"\n"
        path.write_bytes(data[:offset] + newline.join(notice) + newline * 2 + data[offset:])
        return True
    print(f"{relative}: missing or incorrect SPDX license header")
    return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fix", action="store_true", help="add missing headers")
    args = parser.parse_args()
    tracked = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT)
    failures = 0
    checked = 0
    for relative in tracked.decode("utf-8").split("\0"):
        if relative and comment_prefix(relative) is not None:
            path = ROOT / relative
            if not path.exists():  # staged/worktree deletions
                continue
            checked += 1
            failures += not check_file(path, relative, args.fix)
    print(f"License headers: {checked} files checked, {failures} failures")
    return int(bool(failures))


if __name__ == "__main__":
    raise SystemExit(main())
