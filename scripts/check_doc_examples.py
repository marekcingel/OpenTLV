#!/usr/bin/env python3
"""Check that documented examples are identical to their compiled sources.

A Markdown code block preceded by a marker comment

    <!-- example: examples/tlv/src/quick_start.c -->

must contain exactly the contents of that file, and the file must be listed in
a CMakeLists.txt under examples/ so CI compiles it. Editing either side without
the other fails the check, so documented code cannot drift from code that
builds against the current API.

Usage: python scripts/check_doc_examples.py [--fix]

--fix rewrites mismatching blocks from their source files.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MARKER = re.compile(
    r"(<!-- example: (?P<path>\S+) -->\n+```(?P<lang>\w*)\n)(?P<body>.*?)(?P<end>```)",
    re.S,
)


def markdown_files():
    yield ROOT / "README.md"
    yield from sorted((ROOT / "docs").rglob("*.md"))


def is_built(source):
    """True if a CMakeLists.txt in the source's example tree names the file."""
    rel = source.relative_to(ROOT)
    directory = ROOT / rel.parts[0] / rel.parts[1]
    return any(
        source.relative_to(directory).as_posix() in cmake.read_text(encoding="utf-8")
        for cmake in directory.glob("CMakeLists.txt")
    )


def check(fix):
    errors = []
    blocks = 0
    for md in markdown_files():
        text = md.read_text(encoding="utf-8")
        name = md.relative_to(ROOT).as_posix()

        def replace(match):
            nonlocal blocks
            blocks += 1
            source = ROOT / match["path"]
            if not source.is_file():
                errors.append(f"{name}: example source {match['path']} does not exist")
                return match[0]
            if not match["path"].startswith("examples/") or not is_built(source):
                errors.append(f"{name}: {match['path']} is not built by an examples/ CMakeLists.txt")
            expected = source.read_text(encoding="utf-8").replace("\r\n", "\n")
            if not expected.endswith("\n"):
                expected += "\n"
            if match["body"] == expected:
                return match[0]
            if fix:
                return match[1] + expected + match["end"]
            errors.append(f"{name}: code block differs from {match['path']}")
            return match[0]

        updated = MARKER.sub(replace, text)
        if fix and updated != text:
            md.write_text(updated, encoding="utf-8", newline="\n")
            print(f"updated {name}")

    if blocks == 0:
        errors.append("no '<!-- example: PATH -->' blocks found; documented examples are unchecked")
    for error in errors:
        print(f"error: {error}", file=sys.stderr)
    if not errors:
        print(f"{blocks} documented example block(s) match their sources")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(check("--fix" in sys.argv[1:]))
