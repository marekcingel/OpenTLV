#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel
"""Reject native OpenTLV dependencies in ordinary C++ consumers.

Interop examples are excluded by exact path and reason. C engine tests are not
ordinary C++ consumers merely because their harness uses GoogleTest.
"""

import argparse
import json
import re
from pathlib import Path

EXCLUSIONS = {
    "examples/tlv++/src/advanced_control.cpp": "Explicit C/C++ interoperability example.",
    "tests/capabilities.cpp": "C and C++ capability composition in the same native binary.",
    "tests/integration/layers_test.cpp": "Cross-layer parity against canonical C Reader, Writer and Schema.",
    "tests/integration/builtins/dhcp/dhcpv4_cpp_test.cpp": "Legacy native DHCP rules and descriptor identity interoperability.",
    "tests/integration/builtins/nfc/type2_cpp_test.cpp": "Native NFC descriptor identity interoperability.",
    "tests/query/adversarial_equivalence.cpp": "Adversarial C backend equivalence, including C++ Document ownership.",
    "tests/query/constexpr.cpp": "Generated native plan representation and runtime compiler equivalence.",
    "tests/query/cxx_facade.cpp": "Native Query workspace, resolver and execution ABI parity.",
    "tests/unit/generator_test.cpp": "Canonical C generator parity and malformed native profiles.",
    "tests/unit/test_native_boundary.cpp": "Explicit C/C++ native conversion contract.",
    "tests/unit/test_semantic_views.cpp": "Native representation isolation and malformed native imports.",
    "tests/unit/test_tlvpp.cpp": "Legacy native-format and descriptor parity; public acceptance cases live in public_api_test.cpp.",
    "tests/unit/builtins/test_convenience.cpp": "Builtin wrappers compared directly with canonical C codecs and descriptors.",
    "tests/unit/codec/test_typed_fields.cpp": "Native codec customization and native framing failure parity.",
    "tests/unit/document/test_document.cpp": "Document ownership against mutable native Format descriptors.",
    "tests/unit/formats/test_fixed_format.cpp": "Fixed adapter compared with native configuration and descriptor lifetime.",
    "tests/unit/query/test_query_ranges.cpp": "Native feed, program and Document handle interoperability.",
    "tests/unit/reader/test_reader.cpp": "Reader and Tree Reader diagnostic/event parity with native cursors.",
    "tests/unit/reader/test_iterable_reader.cpp": "Malformed native Format initialization and range exception propagation.",
    "tests/unit/writer/test_builder.cpp": "Native Tree Writer storage and failure parity.",
    "tests/unit/writer/test_tree_writer.cpp": "Native Tree Writer callbacks and output parity.",
}
TOKEN = re.compile(r"\btlv_[A-Za-z0-9_]+\b|\bTLV_[A-Za-z0-9_]+\b|\btlv\s*::\s*(?:native|detail)\b")
INCLUDE = re.compile(r'^\s*#\s*include\s*[<"]((?:tlv/|tlv\+\+/(?:detail/|native\.hpp))[^>"\n]*)[>"]', re.M)
# Preserve line breaks and character offsets when masking comments and literals.
LEXICAL = re.compile(r'//[^\n]*|/\*[\s\S]*?\*/|R"([^ ()\\\t\r\n]{0,16})\([\s\S]*?\)\1"|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'')


def masked(text):
    return LEXICAL.sub(lambda match: re.sub(r"[^\n]", " ", match.group()), text)


def violations(path, text):
    # Generated capability switches are configuration, not a native execution API.
    # Ignore commented-out includes while retaining actual header-name literals.
    def header_literal(match):
        prefix = text[text.rfind("\n", 0, match.start()) + 1:match.start()]
        if match.group().startswith('"') and re.fullmatch(r'\s*#\s*include\s*', prefix):
            return match.group()
        return re.sub(r'[^\n]', ' ', match.group())

    headers = LEXICAL.sub(header_literal, text)
    for match in INCLUDE.finditer(headers):
        if match[1] != "tlv/config.h":
            yield {"path": path, "line": text.count("\n", 0, match.start()) + 1,
                   "symbol": match[1], "kind": "header"}
    for match in TOKEN.finditer(masked(text)):
        yield {"path": path, "line": text.count("\n", 0, match.start()) + 1,
               "symbol": match.group(), "kind": "native"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--report", type=Path, help="Write the full machine-readable audit.")
    args = parser.parse_args()
    failures = []
    for folder in ("examples/tlv++", "tools/cli", "tests"):
        for path in sorted((args.root / folder).rglob("*")):
            if path.suffix not in (".hpp", ".cpp", ".h"):
                continue
            relative = path.relative_to(args.root).as_posix()
            content = path.read_text(encoding="utf-8")
            # C engine tests using a C++ harness are not facade consumers.
            if folder == "tests" and not re.search(r'#\s*include\s*[<"]tlv\+\+/', content):
                continue
            if relative not in EXCLUSIONS:
                failures.extend(violations(relative, content))
    if args.report:
        args.report.write_text(json.dumps({"exclusions": EXCLUSIONS, "violations": failures}, indent=2) + "\n", encoding="utf-8")
    for issue in failures[:40]:
        print(f"{issue['path']}:{issue['line']}: native consumer dependency: {issue['symbol']}")
    print(f"C++ consumer boundary: {len(failures)} violations")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
