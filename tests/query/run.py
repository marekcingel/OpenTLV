# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel
"""Independent fixture/oracle checks and bounded parallel native comparisons."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import random
import subprocess
from reference import select, v1_baseline


def native_check(job):
    command, case, expected, mode, split = job
    result = subprocess.run(command, capture_output=True, text=True)
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


def generated_cases(count):
    generator = random.Random(521)

    def sequence(depth):
        wire = bytearray()
        for _ in range(generator.randrange(1, 4)):
            tag = generator.choice([0x70, 0x5a, 0x50]) if depth < 3 else generator.choice([0x5a, 0x50])
            value = sequence(depth + 1) if tag == 0x70 and generator.randrange(3) else b''
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
               "//70//5A intersect //5A except //50", "count(//5A/..)"]
    for index in range(count):
        wire = sequence(0)
        for query in queries:
            yield {"id": f"property-{index}-{query}", "query": query, "wire": wire.hex(),
                   "matches": select(query, wire), "generated": True}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--native")
    parser.add_argument("--jobs", type=int, default=8)
    parser.add_argument("--property-cases", type=int, default=24)
    args = parser.parse_args()
    corpus = json.loads(Path(__file__).with_name("corpus.json").read_text())
    assert corpus["version"] == 1
    capabilities = set(subprocess.check_output([args.native, "--capabilities"], text=True).split()) if args.native else {"document", "asn1"}
    if args.native:
        implemented = set(subprocess.check_output([args.native,"--language-features"],text=True).split())
        assert implemented <= set(corpus["f3_rules"]), ("uncovered implemented features", implemented - set(corpus["f3_rules"]))
    for rule in corpus.get("f3_rules", []):
        covered = {case.get("coverage") for case in corpus["cases"] if case.get("phase_rule") == rule}
        assert covered == {"positive", "negative"}, ("F3 phase gate", rule, covered)
    jobs = []
    skipped = 0
    fixtures = 0
    generated = 0
    for case in [*corpus["cases"], *generated_cases(args.property_cases)]:
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
        expected = select(case["query"], wire)
        assert expected == case["matches"], (case["id"], expected, case["matches"])
        if case.get("v1"):
            assert v1_baseline(case["query"], wire) == expected, case["id"]
        if args.native:
            modes = [(mode, None) for mode in ("o", "u", "ro", "ru", "do", "du")]
            if "@offset" in case["query"] or "@hlen" in case["query"] or "document" not in capabilities:
                modes = [(mode, split) for mode, split in modes if 'd' not in mode]
            if not case.get("generated"):
                modes += [("o", split) for split in range(len(wire) + 1)]
            for mode, split in modes:
                command = [args.native, case["query"], case["wire"], mode]
                if split is not None:
                    command.append(str(split))
                jobs.append((command, case, expected, mode, split))
    with ThreadPoolExecutor(max_workers=max(1, args.jobs)) as executor:
        list(executor.map(native_check, jobs))
    print(f"{fixtures} Query fixtures and {generated} generated comparisons passed ({len(jobs)} native executions, {skipped} unavailable-provider fixtures)")


if __name__ == "__main__":
    main()
