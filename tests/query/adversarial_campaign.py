#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel
"""Run deterministic API properties, retain evidence and minimize failing sequences."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess


def minimize(sequence, fails):
    """Deterministic deletion to a 1-minimal operation sequence."""
    width = max(1, len(sequence) // 2)
    while width:
        index = 0
        while index + width <= len(sequence):
            candidate = sequence[:index] + sequence[index + width:]
            if candidate and fails(candidate):
                sequence = candidate
            else:
                index += 1
        width //= 2
    return sequence


def run(command):
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=120)
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return 124, '', 'Execution exceeded the 120 second bound.\n'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--native', type=Path, required=True)
    parser.add_argument('--equivalence', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--commit', default='local-worktree')
    parser.add_argument('--msan', action='store_true')
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    results = []
    for label, binary in [('lifecycle', args.native), ('equivalence', args.equivalence)]:
        if binary is None:
            continue
        command = [str(binary.resolve())]
        for attempt in range(3 if args.msan else 1):
            status, stdout, stderr = run(command)
            (args.output / f'{label}-{attempt}.stdout').write_text(stdout)
            (args.output / f'{label}-{attempt}.stderr').write_text(stderr)
            shadow = ('MemorySanitizer can not mmap the shadow memory' in stderr
                      and 'WARNING: MemorySanitizer' not in stderr)
            if not shadow:
                break
        record = {'name': label, 'returncode': status,
                  'sha256': hashlib.sha256(binary.read_bytes()).hexdigest(), 'attempts': attempt + 1}
        match = re.search(r'trace=([BFEXRNSVP]+) ', stderr)
        if status and match:
            minimal = minimize(match[1], lambda seq: run(command + ['--sequence', seq])[0] != 0)
            record['minimal_sequence'] = minimal
            (args.output / 'regression.txt').write_text(minimal + '\n')
        results.append(record)
    report = {'version': 1, 'commit': args.commit, 'passed': all(r['returncode'] == 0 for r in results),
              'seeds': {'first': 1, 'last': 256, 'operations': 128}, 'results': results}
    (args.output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(f"Query adversarial verification: passed={report['passed']}")
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
