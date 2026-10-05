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
          "allocation-recursion", "work-budgets-32-64", "benchmarks", "ABI-32-64"]


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
    blockers = list(inventory_errors)
    if evidence.get("commit") != commit:
        blockers.append("release evidence missing or belongs to a different candidate commit")
    def require(category, name, capabilities=()):
        record = evidence.get(category, {}).get(name, {})
        if record.get("status") != "passed":
            blockers.append(f"missing passing candidate evidence: {category}/{name}")
            return
        path = args.evidence.parent / record.get("artifact", "")
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != record.get("sha256"):
            blockers.append(f"missing or changed evidence artifact: {category}/{name}")
        if set(capabilities) - set(record.get("capabilities", [])):
            blockers.append(f"incomplete capabilities: {category}/{name}")
        if category == "facades" and name not in ("C", "CLI") and record.get("surface") != "idiomatic":
            blockers.append(f"raw FFI is insufficient: {name}")
    for phase in range(1, 6):
        require("phases", f"F{phase}")
    for facade in FACADES:
        require("facades", facade, symbols if facade != "CLI" else corpus["f3_rules"])
    for check in CHECKS:
        require("checks", check)
    if args.release and subprocess.check_output(["git", "status", "--porcelain"], cwd=root):
        blockers.append("release candidate worktree has uncommitted changes")
    report = {"version": 1, "commit": commit, "ready": not blockers,
              "phase_equivalents": {f"F{n}": 518 + n for n in range(1, 6)},
              "replacement_authority": "https://github.com/marekcingel/OpenTLV/issues/518",
              "normative_rules": rule_map, "features": features,
              "public_C_capabilities": sorted(symbols), "facades": FACADES,
              "required_checks": CHECKS, "blockers": blockers}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Query release inventory: {len(rules)} rules, {len(features)} features, "
          f"{len(symbols)} C capabilities; ready={report['ready']}")
    if inventory_errors or (args.release and blockers):
        raise SystemExit("\n".join(blockers))


if __name__ == "__main__":
    main()
