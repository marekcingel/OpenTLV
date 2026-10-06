# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel
"""Attach independent fixture preorder offsets for source-less Document handles."""
import argparse
import json
from pathlib import Path
from reference import tree


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    cases = json.loads(Path(__file__).with_name("corpus.json").read_text())["cases"]
    for case in cases:
        if "diagnostic" not in case:
            _, nodes = tree(bytes.fromhex(case["wire"]))
            case["offsets"] = [node["offset"] for node in nodes]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(cases) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
