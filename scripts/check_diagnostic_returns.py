#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel
"""Conservative source guard for direct error returns after diagnostic initialization.

This is a lexical tripwire, not control-flow or interprocedural proof. It scans
C function bodies, ignoring comments and strings, and recognizes *_diag_init,
*_diagnostic_init and memset of a diagnostic output. Propagated results and
indirect initialization are covered by the shared runtime test helper.
A populated direct return needs an adjacent diagnostic-return: comment explaining
where its detail was set. Pre-initialization returns are deliberately excluded.
"""
import argparse
from pathlib import Path
import re


MASK = re.compile(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', re.S)
FUNCTION = re.compile(r'\b(\w+)\s*\(([^;{}]*)\)\s*\{')
PARAM = re.compile(r'\btlv_\w*diagnostic_t\s*\*\s*(\w+)')
RETURN = re.compile(r'\breturn\s+(TLV_ERR_\w+|TLV_NEED_MORE_DATA)\s*;')


def masked(source):
    return MASK.sub(lambda m: ''.join('\n' if c == '\n' else ' ' for c in m[0]), source)


def violations(source):
    clean = masked(source)
    errors = []
    end = 0
    for match in FUNCTION.finditer(clean):
        if match.start() < end:
            continue
        depth, end = 1, match.end()
        while end < len(clean) and depth:
            depth += (clean[end] == '{') - (clean[end] == '}')
            end += 1
        parameters = PARAM.findall(match[2])
        if not parameters:
            continue
        body = clean[match.end():end]
        inits = []
        for param in parameters:
            arg = r'&?\s*' + re.escape(param) + r'\b'
            pattern = r'\b(?:\w*(?:diag_init|diagnostic_init)|memset)\s*\(\s*' + arg
            inits.extend(m.start() for m in re.finditer(pattern, body))
        if not inits:
            continue
        for ret in RETURN.finditer(body):
            if ret.start() < min(inits):
                continue
            position = match.end() + ret.start()
            line = source.count('\n', 0, position) + 1
            lines = source.splitlines()
            adjacent = '\n'.join(lines[max(0, line - 3):line])
            comments = [m[0] for m in MASK.finditer(adjacent) if m[0].startswith(('/', '/*'))]
            if any(re.search(r'diagnostic-return:[ \t]*[A-Za-z][^\n]*', c) for c in comments):
                continue
            errors.append((line, match[1], ret[1]))
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('paths', nargs='*', type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    paths = args.paths or [root / 'tlv/src']
    files = sorted({p for path in paths for p in (path.rglob('*.c') if path.is_dir() else [path])})
    if not files:
        raise SystemExit('No C source files found')
    failures = []
    for path in files:
        for line, function, code in violations(path.read_text(encoding='utf-8')):
            failures.append(f'{path}:{line}: {function}: direct {code} after diagnostic initialization')
    if failures:
        raise SystemExit('\n'.join(failures))
    print(f'Diagnostic return guard: {len(files)} C files checked')


if __name__ == '__main__':
    main()
