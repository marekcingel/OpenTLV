# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel
"""Independent fixture/oracle checks and bounded parallel native comparisons."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import random
import subprocess
import sys
from threading import Event
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "property"))
from corpus import commit_seed, write_metadata
from reference import select, v1_baseline
from minimize import minimize


def native_command(native, case, mode, split):
    command = [native, case["query"], case["wire"], mode]
    if split is not None:
        command.append(str(split))
    if case.get("variables"):
        if split is None:
            command.append(str(len(bytes.fromhex(case["wire"]))))
        command += [f"{name}:{value['type']}:{value['value']}"
                    for name, value in case["variables"].items()]
    return command


def native_check(job):
    command, case, expected, mode, split = job
    result = subprocess.run(command, capture_output=True, text=True, timeout=30)
    label = (case["id"], mode, split)
    if "diagnostic" in case:
        assert result.returncode != 0, label
        fields = list(map(int, result.stderr.split()))
        diagnostic = case["diagnostic"]
        assert fields[:2] == [diagnostic["code"], diagnostic["kind"]], (label, fields)
        if "begin" in diagnostic:
            assert fields[2:] == [diagnostic["begin"], diagnostic["end"]], (label, fields)
    else:
        assert result.returncode == 0, (label, result.stderr)
        actual = result.stdout.strip() if isinstance(expected, str) else [int(x) for x in result.stdout.split()]
        assert actual == expected, (label, actual, expected)


def generated_cases(count, seed=521):
    generator = random.Random(seed)

    def sequence(depth):
        wire = bytearray()
        for _ in range(generator.randrange(1, 4)):
            tag = generator.choice([0x70, 0x5a, 0x50]) if depth < 3 else generator.choice([0x5a, 0x50])
            value = sequence(depth + 1) if tag == 0x70 else bytes(
                generator.randrange(256) for _ in range(generator.randrange(5)))
            if len(value) > 255:
                value = b''
            wire += bytes([tag, len(value)]) + value
        return bytes(wire)

    queries = ["//70[not(5A)] | //50", "//5A/..", "//50[preceding-sibling::5A]",
               "//70/5A[last()]", "(//5A)[1]", "//5A/ancestor-or-self::*[1]",
               "//50/preceding-sibling::*[1]", "//50/following-sibling::*[last()]",
               "//70/descendant-or-self::*[last()]", "//5A/following::*",
               "//5A/preceding::*[1]", "//5A/ancestor::*[1] | //70",
               "70[count(descendant::5A)>1]", "//70[exists(50[preceding-sibling::5A])]",
               "//70//5A intersect //5A except //50", "count(//5A/..)",
               "//5A[@len > 1]", "//50[contains(value(), x'00')]",
               "//5A[starts-with(value(), x'01')]", "//50[ends-with(value(), x'ff')]",
               "//5A[tag-mask(x'5a', x'ff')]", "//5A[tag-range(x'50', x'70')]",
               "//70[tag-mask(x'5a', x'ff')]", "//70[tag-range(x'50', x'5f')]",
               "exists(//5A)", "empty(//50)", "count(//70//5A | //50)",
               "count(//5A intersect //50)", "//70/5A", "//70//5A"]
    for index in range(count):
        wire = sequence(0)
        # Independent set laws use source identities, never native VM output.
        child = select("//70/5A", wire)
        descendant = select("//70//5A", wire)
        assert set(child) <= set(descendant)
        left, right = select("//5A", wire), select("//50", wire)
        union = select("//5A | //50", wire)
        intersection = select("//5A intersect //50", wire)
        assert len(union) + len(intersection) == len(left) + len(right)
        assert union == sorted(set(union))
        for query in queries:
            yield {"id": f"property-{index}-{query}", "query": query, "wire": wire.hex(),
                   "matches": select(query, wire), "generated": True}
        variables = {"min": {"type": "int", "value": generator.randrange(-1, 5)},
                     "needle": {"type": "bytes", "value": "00"},
                     "label": {"type": "string", "value": "a"}}
        for query in ["//5A[@len > $min]", "//50[contains(value(), $needle)]",
                      "//5A[$label = 'a']"]:
            yield {"id": f"property-{index}-{query}", "query": query, "wire": wire.hex(),
                   "matches": select(query, wire, variables), "variables": variables,
                   "generated": True}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--native")
    parser.add_argument("--jobs", type=int, default=8)
    parser.add_argument("--property-cases", type=int, default=24)
    parser.add_argument("--seed", type=int)
    parser.add_argument("--commit", default="query-fixture-v1")
    parser.add_argument("--evidence", type=Path)
    args = parser.parse_args()
    seed = args.seed if args.seed is not None else commit_seed(args.commit)
    if not 0 <= seed < 2**64 or args.property_cases < 0:
        parser.error("seed must be uint64 and property count nonnegative")
    corpus = json.loads(Path(__file__).with_name("corpus.json").read_text())
    assert corpus["version"] == 1
    capabilities = set(subprocess.check_output([args.native, "--capabilities"], text=True, timeout=30).split()) if args.native else {"document", "asn1"}
    if args.native:
        implemented = set(subprocess.check_output([args.native,"--language-features"],text=True,timeout=30).split())
        assert implemented <= set(corpus["f3_rules"]), ("uncovered implemented features", implemented - set(corpus["f3_rules"]))
    for rule in corpus.get("f3_rules", []):
        covered = {case.get("coverage") for case in corpus["cases"] if case.get("phase_rule") == rule}
        assert covered == {"positive", "negative"}, ("F3 phase gate", rule, covered)
    jobs = []
    skipped = 0
    fixtures = 0
    generated = 0
    cases = [*corpus["cases"], *generated_cases(args.property_cases, seed)]
    if args.evidence:
        args.evidence.mkdir(parents=True, exist_ok=True)
        write_metadata(args.evidence / "manifest.json", {
            "contract_version": 1, "commit": args.commit, "seed": str(seed),
            "generator": "python-random-query-v2", "tree_count": args.property_cases,
            "expected_results": "expected.json", "wire_cases": "wire.json"})
        write_metadata(args.evidence / "wire.json", [
            {"id": case["id"], "wire": case["wire"], "query": case["query"],
             "variables": case.get("variables", {})} for case in cases])
        write_metadata(args.evidence / "expected.json", [
            {"id": case["id"], "matches": case.get("matches"),
             "diagnostic": case.get("diagnostic")} for case in cases])
    for case in cases:
        requirements = set(case.get("requires", []))
        if "following::" in case["query"] or "preceding::" in case["query"]:
            requirements.add("document")
        if args.native and not requirements <= capabilities:
            skipped += 1
            continue
        if case.get("generated"):
            generated += 1
        else:
            fixtures += 1
        if "diagnostic" in case:
            if args.native:
                jobs.append(([args.native, case["query"], case["wire"]], case, None, "diagnostic", None))
            continue
        wire = bytes.fromhex(case["wire"])
        expected = select(case["query"], wire, case.get("variables"))
        assert expected == case["matches"], (case["id"], expected, case["matches"])
        if case.get("v1"):
            assert v1_baseline(case["query"], wire) == expected, case["id"]
        if args.native:
            modes = [(mode, None) for mode in ("o", "u", "ro", "ru", "do", "du")]
            if "@offset" in case["query"] or "@hlen" in case["query"] or "document" not in capabilities:
                modes = [(mode, split) for mode, split in modes if 'd' not in mode]
            if case.get("generated"):
                modes += [("o", split) for split in sorted({0, len(wire)//2, len(wire)})]
            else:
                modes += [("o", split) for split in range(len(wire) + 1)]
            for mode, split in modes:
                command = native_command(args.native, case, mode, split)
                jobs.append((command, case, expected, mode, split))
    failed = Event()
    def retained_check(job):
        if failed.is_set():
            return
        try:
            native_check(job)
        except Exception as error:
            failed.set()
            if args.evidence:
                import hashlib
                key = hashlib.sha256(repr(job).encode()).hexdigest()[:16]
                write_metadata(args.evidence / f"failure-{key}.json", {
                    "command": job[0], "case": job[1], "expected": job[2],
                    "mode": job[3], "split": job[4], "seed": str(seed), "error": str(error)})
                if job[1].get("generated") and not isinstance(error, subprocess.TimeoutExpired):
                    original = subprocess.run(job[0], capture_output=True, text=True, timeout=30)
                    def boundary(candidate):
                        return None if job[4] is None else min(job[4], len(bytes.fromhex(candidate["wire"])))
                    def disagrees(candidate, expected):
                        command = native_command(args.native, candidate, job[3], boundary(candidate))
                        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
                        # Do not replace a semantic disagreement with a compiler
                        # error, or a crash with a different exit category.
                        if result.returncode != original.returncode:
                            return False
                        if result.returncode:
                            return True
                        try:
                            actual = result.stdout.strip() if isinstance(expected, str) else [int(x) for x in result.stdout.split()]
                        except ValueError:
                            return False
                        return actual != expected
                    reduced, attempts = minimize(job[1], disagrees)
                    write_metadata(args.evidence / f"failure-{key}-minimized.json", {
                        "command": native_command(args.native, reduced, job[3], boundary(reduced)),
                        "case": reduced, "expected": reduced["matches"], "mode": job[3],
                        "split": boundary(reduced), "seed": str(seed), "attempts": attempts,
                        "budget": 128, "original": f"failure-{key}.json"})
            raise
    with ThreadPoolExecutor(max_workers=max(1, args.jobs)) as executor:
        list(executor.map(retained_check, jobs))
    print(f"{fixtures} Query fixtures and {generated} generated comparisons passed ({len(jobs)} native executions, {skipped} unavailable-provider fixtures)")


if __name__ == "__main__":
    main()
