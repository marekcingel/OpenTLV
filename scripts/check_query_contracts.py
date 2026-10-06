#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel
"""Conservative Clang direct-call closure audit for the allocation-free Query boundary.

Format, resolver, codec, visitor and Source callbacks are caller-owned contracts;
this audit does not prove arbitrary function-pointer targets safe.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess

FORBIDDEN = {"malloc", "calloc", "realloc", "free", "aligned_alloc", "posix_memalign",
             "_aligned_malloc", "_aligned_realloc", "_aligned_free", "alloca", "_alloca"}


def violations(graph, roots):
    active, done, errors = [], set(), []

    def visit(name):
        if name in FORBIDDEN:
            errors.append("allocation dependency: " + " -> ".join([*active, name]))
            return
        if name in active:
            errors.append("recursive dependency: " + " -> ".join([*active, name]))
            return
        if name in done:
            return
        active.append(name)
        for target in sorted(graph.get(name, ())):
            visit(target)
        active.pop()
        done.add(name)

    for root in sorted(roots):
        visit(root)
    return errors, done


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--clang", default="clang")
    parser.add_argument("--generated", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    graph, roots, units = {}, set(), []
    for source in sorted((root / "tlv/src").rglob("*.c")):
        # Disabled builtin units cannot be compiled against a minimal config.
        # CI uses the full feature configuration for this transitive audit.
        command = [args.clang, "-std=c99", "-DTLV_STATIC_DEFINE",
                   "-I" + str(root / "tlv/include"), "-I" + str(args.generated),
                   "-Xclang", "-analyze", "-Xclang",
                   "-analyzer-checker=debug.DumpCallGraph", "-fsyntax-only", str(source)]
        result = subprocess.run(command, text=True, capture_output=True)
        if result.returncode:
            raise RuntimeError(f"{source}: {result.stderr}")
        dump = result.stdout + result.stderr
        records = re.findall(r"Function: (\S+) calls:([^\n]*)", dump)
        if not records:
            raise RuntimeError(f"Clang produced no call graph for {source}")
        units.append(str(source.relative_to(root)))
        if source.parent.name == "query":
            definitions = set(re.findall(r"\b(\w+)\s*\([^;{}]*\)\s*\{", source.read_text()))
            roots.update(definitions - {"if", "for", "while", "switch"})
        for name, calls in records:
            graph.setdefault(name, set()).update(calls.split())
            if source.parent.name == "query" and (name.startswith("tlv_query_") or
                                                   name.startswith("query_")):
                roots.add(name)
    errors, reached = violations(graph, roots)
    report = {"version": 1, "translation_units": units, "roots": sorted(roots),
              "reachable": sorted(reached), "errors": errors,
              "boundary": "direct internal calls; external callback targets excluded",
              "graph": {name: sorted(graph.get(name, ())) for name in sorted(reached)}}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if errors:
        raise SystemExit("\n".join(errors))
    print(f"Query contracts: {len(roots)} roots, {len(reached)} functions, {len(units)} units")


if __name__ == "__main__":
    main()
