#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel
"""Inventory Query release requirements; require candidate evidence in strict mode."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

UNIT_RULES = {
    "Q-LANG-01": "Unit_Tlv_QueryProgram.UnsupportedFeaturesHavePreciseDiagnostics",
    "Q-ABI-01": "Unit_Tlv_QueryProgram.CallerSizedInfoPreservesUnknownAndUnavailableFields",
    "Q-BINDING-01": "Unit_Tlv_QueryProgram.TypedBindingsAreIndependentAndNeverQueryText",
    "Q-EVENT-02": "Unit_Tlv_QueryF3.S1ScopePublicationStopResumeAndMalformedSuffix",
    "Q-LIMIT-01": "Unit_Tlv_QueryProgram.ValidationAndWorkLimitsAreExplicit",
    "Q-STORAGE-01": "Unit_Tlv_QueryProgram.CapacityAndNestingBoundariesPreserveStorage",
    "Q-STORAGE-02": "Unit_Tlv_QueryF2.EnvironmentMismatchIsRejectedBeforeInput",
    "Q-VALIDATE-01": "Unit_Tlv_QueryProgram.PruningAndExistsExposePartialCoverage",
    "Q-IMAGE-01": "Unit_Tlv_QueryProgram.LoaderAuthenticatesEveryInstructionField",
}
FACADES = ["C", "CLI", "C++", "Rust", "Python", "Go", "Lua", "JS/WASM"]
CHECKS = ["conformance", "properties", "fuzz-ASan-UBSan", "MSan-or-exclusion",
          "allocation-recursion", "work-budgets-32-64", "ABI-32-64"]
ADVISORY_CHECKS = ["benchmarks"]


def evidence_errors(evidence, directory, commit, symbols, features):
    """Validate candidate provenance and contained artifacts; fail closed on malformed records."""
    errors = []
    if not isinstance(evidence, dict) or evidence.get("commit") != commit:
        return ["release evidence missing or belongs to a different candidate commit"]
    directory = directory.resolve()
    requirements = [("phases", f"F{phase}", ()) for phase in range(1, 6)]
    requirements += [("facades", name, features if name == "CLI" else symbols) for name in FACADES]
    requirements += [("checks", name, ()) for name in CHECKS]
    for category, name, capabilities in requirements:
        group = evidence.get(category, {})
        record = group.get(name) if isinstance(group, dict) else None
        label = f"{category}/{name}"
        if not isinstance(record, dict) or record.get("status") != "passed":
            errors.append(f"missing passing candidate evidence: {label}")
            continue
        artifact = record.get("artifact")
        digest = record.get("sha256")
        if not isinstance(artifact, str) or not artifact or not isinstance(digest, str):
            errors.append(f"missing evidence artifact/hash: {label}")
        else:
            relative = Path(artifact)
            path = (directory / relative).resolve()
            if relative.is_absolute() or not path.is_relative_to(directory):
                errors.append(f"artifact escapes evidence directory: {label}")
            elif (not path.is_file() or
                  hashlib.sha256(path.read_bytes()).hexdigest() != digest):
                errors.append(f"missing or changed evidence artifact: {label}")
        provided = record.get("capabilities", [])
        if (not isinstance(provided, list) or
                any(not isinstance(value, str) for value in provided) or
                set(capabilities) - set(provided)):
            errors.append(f"incomplete capabilities: {label}")
        if (category == "facades" and name not in ("C", "CLI") and
                record.get("surface") != "idiomatic"):
            errors.append(f"raw FFI is insufficient: {name}")
        if category == "checks" and name in ("work-budgets-32-64", "ABI-32-64"):
            pointer_bits = record.get("pointer_bits", [])
            if (not isinstance(pointer_bits, list) or
                    any(type(value) is not int for value in pointer_bits) or
                    set(pointer_bits) != {32, 64}):
                errors.append(f"both 32-bit and 64-bit evidence required: {name}")
    return errors


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--release", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    corpus = json.loads((root / "tests/query/corpus.json").read_text())
    contract = (root / "docs/concepts/query-language.md").read_text(encoding="utf-8")
    rules = set(re.findall(r"\*\*(Q-[A-Z]+-[0-9]+)\.\*\*", contract))
    unit_text = "\n".join(p.read_text() for p in (root / "tests/unit/query").glob("*.cpp"))
    unit_names = {f"{suite}.{name}" for suite, name in re.findall(
        r"TEST\(\s*(\w+)\s*,\s*(\w+)\s*\)", unit_text)}
    rule_map, inventory_errors = {}, []
    for rule in sorted(rules):
        tests = [case["id"] for case in corpus["cases"] if rule in case.get("rules", [])]
        if rule in UNIT_RULES:
            name = UNIT_RULES[rule]
            if name not in unit_names:
                inventory_errors.append(f"missing mapped test: {name}")
            tests.append(name)
        if not tests:
            inventory_errors.append(f"unmapped normative rule: {rule}")
        rule_map[rule] = tests
    features = {}
    for feature in corpus["f3_rules"]:
        cases = [case for case in corpus["cases"] if case.get("phase_rule") == feature]
        if {case.get("coverage") for case in cases} != {"positive", "negative"}:
            inventory_errors.append(f"incomplete feature conformance: {feature}")
        features[feature] = [case["id"] for case in cases]
    symbols = set()
    for header in (root / "tlv/include/tlv").rglob("*.h"):
        for name in re.findall(r"TLV_API\s+[\w\s*]+?\b(tlv_\w+)\s*\(", header.read_text()):
            if "query" in name:
                symbols.add(name)
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    evidence = json.loads(args.evidence.read_text()) if args.evidence else {}
    blockers = inventory_errors + evidence_errors(
        evidence, args.evidence.parent if args.evidence else root, commit, symbols, corpus["f3_rules"])
    if args.release and subprocess.check_output(["git", "status", "--porcelain"], cwd=root):
        blockers.append("release candidate worktree has uncommitted changes")
    report = {"version": 1, "commit": commit, "ready": not blockers,
              "phase_equivalents": {f"F{n}": 518 + n for n in range(1, 6)},
              "replacement_authority": "https://github.com/marekcingel/OpenTLV/issues/518",
              "normative_rules": rule_map, "features": features,
              "public_C_capabilities": sorted(symbols), "facades": FACADES,
              "required_checks": CHECKS, "advisory_checks": ADVISORY_CHECKS,
              "blockers": blockers}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Query release inventory: {len(rules)} rules, {len(features)} features, "
          f"{len(symbols)} C capabilities; ready={report['ready']}")
    if inventory_errors or (args.release and blockers):
        raise SystemExit("\n".join(blockers))


if __name__ == "__main__":
    main()
