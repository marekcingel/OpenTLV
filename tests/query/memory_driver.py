#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel
"""Generate a persistent sanitizer driver for the shared native Query corpus.

Each invocation reuses the ordinary C runner in one process. This avoids ASLR
shadow-map failures from thousands of independent MSan process startups. The
ordinary conformance campaign checks results against the independent oracle;
this driver checks statuses and sanitizer findings, not another semantic oracle.
"""
import argparse
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    cases = json.loads((root / "corpus.json").read_text())["cases"]
    lines = ['/* SPDX-License-Identifier: MIT */', '/* Copyright (c) 2026 Marek Cingel */',
             '#define main query_case_main',
             '#include ' + json.dumps((root / "native.c").as_posix()),
             '#undef main', 'int main(void) {', 'size_t executed = 0;']
    for case in cases:
        modes = ["o"] if "diagnostic" in case else ["o", "u", "ro", "ru", "do", "du"]
        if "@offset" in case["query"] or "@hlen" in case["query"]:
            modes = [mode for mode in modes if "d" not in mode]
        for mode in modes:
            arguments = ["memory-driver", case["query"], case["wire"], mode]
            expected_failure = int("diagnostic" in case)
            lines += ['{ char *argv[] = {' + ', '.join(json.dumps(a) for a in arguments) + ', NULL};',
                      f'int status = query_case_main({len(arguments)}, argv);',
                      f'if ((status != 0) != {expected_failure}) return 90;',
                      '++executed; }']
    lines += ['fprintf(stderr, "Persistent Query memory campaign: %zu executions passed\\n", executed);',
              'return 0;', '}']
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text('\n'.join(lines) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
