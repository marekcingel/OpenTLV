#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel

"""Check small documentation inventories against their implementation sources.

This detects additions/removals, not semantic correctness of prose or full
binding parity. No native build or third-party Python package is required.
"""

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXAMPLE_ROOTS = (
    ("examples/tlv/src", ".c"),
    ("examples/tlv++/src", ".cpp"),
    ("bindings/rust/opentlv/examples", ".rs"),
    ("bindings/python/opentlv/examples", ".py"),
    ("bindings/lua/examples", ".lua"),
    ("bindings/go/examples", ".go"),
    ("bindings/wasm/examples", ".mjs"),
)


def compare(errors, label, actual, documented, target):
    """Report additions and stale entries without hiding either direction."""
    missing = sorted(actual - documented)
    stale = sorted(documented - actual)
    if missing:
        errors.append(f"{label}: document {', '.join(missing)} in {target}")
    if stale:
        errors.append(f"{label}: remove or correct stale {', '.join(stale)} in {target}")


def check(root):
    errors = []

    def read(path):
        try:
            return (root / path).read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            errors.append(f"{path}: cannot read inventory input: {error}")
            return ""

    architecture = read("docs/concepts/architecture.md")
    components = set(re.findall(r"^#cmakedefine01 (OPENTLV_\w+)$",
                                read("tlv/resources/config.h.in"), re.M))
    options = set(re.findall(r"option\((OPENTLV_\w+)\s", read("CMakeLists.txt")))
    capability_options = {option for option in options
                          if not option.startswith("OPENTLV_BUILD_")
                          and option != "OPENTLV_WARNINGS_AS_ERRORS"}
    compare(errors, "public component configuration", capability_options, components,
            "tlv/resources/config.h.in")
    if not components:
        errors.append("tlv/resources/config.h.in: no public components found")
    for component in sorted(components):
        if component not in options:
            errors.append(f"{component}: public configuration has no root CMake option")
        if not re.search(r"^\| `" + re.escape(component) + r"` \|", architecture, re.M):
            errors.append(f"{component}: add a build-configuration row in docs/concepts/architecture.md")

    support = read("docs/formats/support.md")
    native = set()
    for header in (root / "tlv/include/tlv/builtins").rglob("*.h"):
        native.update(re.findall(r"\bconst\s+tlv_format_t\s+(tlv_format_\w+)\s*;",
                                header.read_text(encoding="utf-8")))
    if not native:
        errors.append("tlv/include/tlv/builtins: no public Format descriptors found")
    # Limit tokens to backtick declarations, not links or discussion of types.
    documented = set(re.findall(r"`(tlv_format_\w+)`", support))
    compare(errors, "native Format descriptors", native, documented, "docs/formats/support.md")

    builtin_root = root / "tlv++/include/tlv++/builtins"
    cxx = {directory.name for directory in builtin_root.iterdir() if directory.is_dir()} \
        if builtin_root.is_dir() else set()
    documented_cxx = set(re.findall(r"tlv\+\+/include/tlv\+\+/builtins/([^/]+)/", support))
    compare(errors, "C++ built-in families", cxx, documented_cxx, "docs/formats/support.md")

    cli_source = read("tools/cli/src/commands/formats_command.cpp")
    cli = set(re.findall(r'names\.push_back\("([a-z0-9-]+)"\)', cli_source))
    if not cli:
        errors.append("formats_command.cpp: no CLI formats found; update inventory derivation")
    documented_cli = set()
    for line in support.splitlines():
        cells = [cell.strip() for cell in line.split("|")[1:-1]]
        if len(cells) == 5 and "tlv_" in cells[1]:
            documented_cli.update(re.findall(r"`([a-z0-9-]+)`", cells[-1]))
    compare(errors, "CLI format identifiers", cli, documented_cli, "docs/formats/support.md")
    cli_doc = read("docs/cli/README.md")
    for name in sorted(cli):
        if f"`{name}`" not in cli_doc:
            errors.append(f"CLI {name}: add the registered identifier to docs/cli/README.md")

    nav = read("mkdocs.yml")
    bindings_root = root / "bindings"
    # Shared native ownership helpers are not a separately supported language.
    bindings = {directory.name for directory in bindings_root.iterdir()
                if directory.is_dir() and directory.name != "common"} \
        if bindings_root.is_dir() else set()
    if not bindings:
        errors.append("bindings/: no official bindings found")
    for language in sorted(bindings):
        page = "development/webassembly.md" if language == "wasm" else f"guides/{language}.md"
        if page not in nav or not (root / "docs" / page).is_file():
            errors.append(f"binding {language}: add docs/{page} and its MkDocs navigation entry")
    if "guides/cxx-examples.md" not in nav:
        errors.append("C++: add guides/cxx-examples.md to MkDocs navigation")

    examples = set()
    for path, suffix in EXAMPLE_ROOTS:
        examples.update(file.relative_to(root).as_posix()
                        for file in (root / path).rglob("*" + suffix))
    example_doc = read("docs/guides/examples.md")
    marker = re.search(r"<!-- example-inventory:start -->(.*?)<!-- example-inventory:end -->",
                       example_doc, re.S)
    if marker is None:
        errors.append("docs/guides/examples.md: missing example-inventory markers")
        documented_examples = set()
    else:
        documented_examples = set(re.findall(r"\]\(\.\./\.\./([^\s)]+)\)", marker.group(1)))
    compare(errors, "executable examples", examples, documented_examples, "docs/guides/examples.md")

    for template, public_root, extension in (
        ("tools/docs/Doxyfile.in", "tlv/include/tlv", "h"),
        ("tools/docs/Doxyfile.cxx.in", "tlv++/include/tlv++", "hpp"),
    ):
        config = read(template)
        # Require the root in INPUT, not just in STRIP_FROM_PATH or a comment.
        input_line = re.search(r"^INPUT\s*=([^\n]*(?:\\\n[^\n]*)*)", config, re.M)
        if input_line is None or f"@PROJECT_SOURCE_DIR@/{public_root}" not in input_line.group(1):
            errors.append(f"{template}: INPUT must include {public_root}")
        if not re.search(r"^RECURSIVE\s*=\s*YES\s*$", config, re.M):
            errors.append(f"{template}: enable recursive public-header discovery")
        patterns = re.search(r"^FILE_PATTERNS\s*=([^\n]+)", config, re.M)
        if patterns is None or f"*.{extension}" not in patterns.group(1).split():
            errors.append(f"{template}: FILE_PATTERNS must include *.{extension}")

    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT, help="repository root (also for fixtures)")
    args = parser.parse_args()
    errors = check(args.root.resolve())
    for error in errors:
        print(f"documentation drift: {error}", file=sys.stderr)
    if errors:
        return 1
    print("Documentation inventories match components, Formats, C++ families, CLI, bindings, examples and API inputs")
    return 0


if __name__ == "__main__":
    sys.exit(main())
