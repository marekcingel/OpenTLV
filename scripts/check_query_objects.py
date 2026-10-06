#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel
"""Audit compiled archive call relocations, including transitive internal helpers.

GNU/LLVM objdump's disassembly supplies emitted direct calls and relocations.
Indirect caller callbacks remain outside this proof, as in the source audit.
Use an unstripped, non-LTO debug archive to retain function boundaries.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

from check_query_contracts import violations


def object_graph(dump):
    records, object_name, current, transfer = {}, None, None, False
    for line in dump.splitlines():
        header = re.match(r"^(\S+):\s+file format\s+", line)
        if header:
            object_name = header[1]
            current = None
            continue
        function = re.match(r"^[0-9a-fA-F]+ <([^>]+)>:$", line.strip())
        if function and object_name:
            current = (object_name, function[1])
            records.setdefault(current, set())
            continue
        if current is None:
            continue
        # External calls have a relocation, local calls have a resolved symbol.
        # Data relocations include sanitizer self-address metadata and do not
        # represent calls. An unconditional branch may be an emitted tail call.
        if re.match(r"^\s*[0-9a-fA-F]+:\s+(?:[0-9a-fA-F]{2}\s+)+", line):
            transfer = bool(re.search(r"\b(?:callq?|bl|jmpq?|b)\s", line))
        relocation = re.search(r"\bR_(?:X86_64|386|AARCH64)_\S+\s+(\S+)", line)
        if relocation and transfer:
            target = re.split(r"[+-]0x|[+-]\d", relocation[1])[0]
            if not target.startswith("."):
                records[current].add(target)
        call = re.search(r"\b(?:callq?|bl|jmpq?|b)\s+[^<]*<([^>+]+)>", line)
        if call:
            records[current].add(call[1])
    by_name = {}
    for object_name, function in records:
        by_name.setdefault(function, []).append((object_name, function))
    graph = {}
    for key, targets in records.items():
        qualified = f"{key[0]}::{key[1]}"
        graph[qualified] = set()
        for target in targets:
            local = (key[0], target)
            choices = [local] if local in records else by_name.get(target, [])
            if choices:
                graph[qualified].update(f"{obj}::{name}" for obj, name in choices)
            else:
                graph[qualified].add(target)
    return graph


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--objdump", default="objdump")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = subprocess.run([args.objdump, "-dr", str(args.archive)], capture_output=True, text=True, check=True)
    graph = object_graph(result.stdout)
    roots = {name for name in graph if name.split("::", 1)[1].startswith(("tlv_query_", "query_"))}
    if not roots:
        raise SystemExit("No compiled Query symbols found; use an unstripped non-LTO archive")
    errors, reached = violations(graph, roots)
    report = {"version": 1, "archive": str(args.archive),
              "sha256": hashlib.sha256(args.archive.read_bytes()).hexdigest(),
              "roots": sorted(roots), "reachable": sorted(reached), "errors": errors,
              "boundary": "emitted direct calls and tail calls; indirect callback targets excluded",
              "graph": {name: sorted(graph.get(name, ())) for name in sorted(reached)}}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if errors:
        raise SystemExit("\n".join(errors))
    print(f"Compiled Query contracts: {len(roots)} roots, {len(reached)} symbols")


if __name__ == "__main__":
    main()
