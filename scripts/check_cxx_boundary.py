#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel
"""Reject native OpenTLV dependencies in ordinary C++ consumers.

Interop consumers have exact per-symbol occurrence budgets and reasons in
cxx_boundary_baseline.json. New dependencies and stale budgets fail the audit.
C engine tests are not ordinary C++ consumers merely because their harness
uses GoogleTest.
"""

import argparse
from collections import Counter
import json
import re
from pathlib import Path, PurePosixPath

SOURCE_SUFFIXES = frozenset((".hpp", ".cpp", ".h", ".cc", ".cxx", ".inl"))
TOKEN = re.compile(r"\btlv_[A-Za-z0-9_]+\b|\bTLV_[A-Za-z0-9_]+\b|\btlv\s*::\s*(?:native|detail)\b(?:\s*::\s*[A-Za-z_][A-Za-z0-9_]*)*")
INCLUDE = re.compile(r'^\s*#\s*include\s*[<"]((?:tlv/|tlv\+\+/(?:detail/|native\.hpp))[^>"\n]*)[>"]', re.M)
FACADE_INCLUDE = re.compile(r'^\s*#\s*include\s*[<"]tlv\+\+/', re.M)
# Preserve line breaks and character offsets when masking comments and literals.
LEXICAL = re.compile(r'//[^\n]*|/\*[\s\S]*?\*/|R"([^ ()\\\t\r\n]{0,16})\([\s\S]*?\)\1"|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'')


def masked(text):
    return LEXICAL.sub(lambda match: re.sub(r"[^\n]", " ", match.group()), text)


def header_source(text):
    # Ignore commented-out includes while retaining actual header-name literals.
    def header_literal(match):
        prefix = text[text.rfind("\n", 0, match.start()) + 1:match.start()]
        if match.group().startswith('"') and re.fullmatch(r'\s*#\s*include\s*', prefix):
            return match.group()
        return re.sub(r'[^\n]', ' ', match.group())

    return LEXICAL.sub(header_literal, text)


def violations(path, text):
    # Generated capability switches are configuration, not a native execution API.
    for match in INCLUDE.finditer(header_source(text)):
        if match[1] != "tlv/config.h":
            yield {"path": path, "line": text.count("\n", 0, match.start()) + 1,
                   "symbol": match[1], "kind": "header"}
    for match in TOKEN.finditer(masked(text)):
        yield {"path": path, "line": text.count("\n", 0, match.start()) + 1,
               "symbol": re.sub(r"\s+", "", match.group()), "kind": "native"}


def load_baseline(path):
    """Load only concrete paths, symbols and positive occurrence counts."""
    document = json.loads(path.read_text(encoding="utf-8"))
    if set(document) != {"version", "files"} or document["version"] != 1:
        raise ValueError("expected baseline version 1 and a files map")
    if not isinstance(document["files"], dict):
        raise ValueError("baseline files must be a map")
    for relative, entry in document["files"].items():
        parts = PurePosixPath(relative)
        if (parts.is_absolute() or ".." in parts.parts or "\\" in relative
                or parts.as_posix() != relative or re.search(r"[*?\[\]]", relative)):
            raise ValueError(f"baseline path must be exact and repository-relative: {relative}")
        if (not isinstance(entry, dict) or set(entry) != {"reason", "symbols"}
                or not isinstance(entry["reason"], str) or not entry["reason"].strip()
                or not isinstance(entry["symbols"], dict) or not entry["symbols"]):
            raise ValueError(f"baseline needs a reason and nonempty symbol map: {relative}")
        for symbol, count in entry["symbols"].items():
            is_header = INCLUDE.fullmatch(f"#include <{symbol}>") is not None
            if (not (TOKEN.fullmatch(symbol) or is_header)
                    or re.search(r"[\s*?\[\]]", symbol)
                    or type(count) is not int or count <= 0):
                raise ValueError(f"baseline needs an exact symbol and positive count: {relative}: {symbol}")
    return document["files"]


def consumers(root):
    for folder in ("examples/tlv++", "tools/cli", "tests"):
        for path in sorted((root / folder).rglob("*")):
            if path.suffix not in SOURCE_SUFFIXES or not path.is_file():
                continue
            content = path.read_text(encoding="utf-8")
            # C engine tests using a C++ harness are not facade consumers.
            if folder == "tests" and not FACADE_INCLUDE.search(header_source(content)):
                continue
            yield path.relative_to(root).as_posix(), content


def audit(root, baseline):
    failures = []
    seen = set()
    for relative, content in consumers(root):
        seen.add(relative)
        budget = baseline.get(relative, {}).get("symbols", {})
        observed = Counter()
        for issue in violations(relative, content):
            symbol = issue["symbol"]
            observed[symbol] += 1
            allowed = budget.get(symbol, 0)
            if observed[symbol] > allowed:
                issue["message"] = (f"native consumer dependency: {symbol}"
                                    f" (baseline allows {allowed} occurrences)")
                failures.append(issue)
        for symbol, allowed in budget.items():
            if observed[symbol] < allowed:
                failures.append({"path": relative, "line": 1, "symbol": symbol,
                                 "kind": "baseline", "message":
                                 f"stale baseline: {symbol} allows {allowed}, found {observed[symbol]}; reduce or remove the budget"})
    for relative in sorted(set(baseline) - seen):
        failures.append({"path": relative, "line": 1, "symbol": "<file>",
                         "kind": "baseline", "message":
                         "stale baseline: path is missing or no longer a C++ consumer"})
    return failures


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--baseline", type=Path, help="Override the repository's checked-in interop budgets.")
    parser.add_argument("--report", type=Path, help="Write the full machine-readable audit.")
    args = parser.parse_args()
    try:
        baseline = load_baseline(args.baseline or args.root / "scripts/cxx_boundary_baseline.json")
    except (OSError, ValueError, TypeError) as error:
        parser.error(f"invalid C++ boundary baseline: {error}")
    failures = audit(args.root, baseline)
    if args.report:
        args.report.write_text(json.dumps({"baseline": baseline, "violations": failures}, indent=2) + "\n", encoding="utf-8")
    for issue in failures[:40]:
        print(f"{issue['path']}:{issue['line']}: {issue['message']}")
    print(f"C++ consumer boundary: {len(failures)} violations")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
