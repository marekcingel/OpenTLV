# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel
"""Applicable common corpus through the public CLI, with explicit provider exclusions."""
import argparse
import json
from pathlib import Path
import subprocess
from reference import tree


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cli", required=True)
    parser.add_argument("--evidence", type=Path)
    args = parser.parse_args()
    cases = json.loads(Path(__file__).with_name("corpus.json").read_text())["cases"]
    checks, excluded = 0, []
    for case in cases:
        # CLI names are supplied by its EMV dictionary, not a fixture registry.
        if "fixture:" in case["query"] or "name(" in case["query"]:
            excluded.append({"id": case["id"], "reason": "requires external fixture name resolver"})
            continue
        for backend in ("auto", "document"):
            if backend == "document" and any(text in case["query"] for text in ("@offset", "@hlen")):
                continue
            command = [args.cli, "query", "--query", case["query"], "--format", "ber",
                       "--hex", case["wire"], "--output", "json", "--diagnostics", "json",
                       "--backend", backend]
            for name, value in case.get("variables", {}).items():
                command += ["--var", f"{name}:{value['type']}={value['value']}"]
            result = subprocess.run(command, text=True, capture_output=True, timeout=30)
            if "diagnostic" in case:
                assert result.returncode != 0, (case["id"], backend)
                diagnostic = json.loads(result.stderr)
                expected = case["diagnostic"]
                for field in ("code", "kind", "begin", "end"):
                    if field in expected:
                        assert diagnostic[field] == expected[field], (case["id"], field, diagnostic)
            else:
                assert result.returncode in (0, 5), (case["id"], backend, result.stderr)
                output = json.loads(result.stdout)
                expected = case["matches"]
                if isinstance(expected, str):
                    value = output["value"]
                    kind = output["type"]
                    actual = (f"bool:{int(value)}" if kind == 1 else f"int:{value}" if kind == 2
                              else "bytes:" + value.lower() if kind == 3
                              else "string:" + value.encode().hex())
                elif backend == "document":
                    # Source-less CLI rows carry semantic Tag/Value. Compare the
                    # independently selected preorder identities' logical payload.
                    _, nodes = tree(bytes.fromhex(case["wire"]))
                    by_offset = {node["offset"]: node for node in nodes}
                    actual = [(row["tag"].lower(), row["value"].lower()) for row in output["matches"]]
                    expected = [(by_offset[offset]["tag"].hex(), by_offset[offset]["value"].hex())
                                for offset in expected]
                else:
                    # Auto D has source-less output too. Compare semantic rows.
                    if any(row["offset"] is None for row in output["matches"]):
                        _, nodes = tree(bytes.fromhex(case["wire"]))
                        by_offset = {node["offset"]: node for node in nodes}
                        actual = [(row["tag"].lower(), row["value"].lower()) for row in output["matches"]]
                        expected = [(by_offset[offset]["tag"].hex(), by_offset[offset]["value"].hex()) for offset in expected]
                    else:
                        actual = [row["offset"] for row in output["matches"]]
                assert actual == expected, (case["id"], backend, actual, expected)
            checks += 1
    report = {"version": 1, "facade": "CLI", "checks": checks, "exclusions": excluded}
    if args.evidence:
        args.evidence.parent.mkdir(parents=True, exist_ok=True)
        args.evidence.write_text(json.dumps(report, indent=2) + "\n")
    print(f"CLI public Query facade: {checks} common backend checks, {len(excluded)} provider exclusions")


if __name__ == "__main__":
    main()
