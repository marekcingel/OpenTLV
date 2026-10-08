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

An independent lifecycle check rejects INVALID_ARG in an if branch governed by
a busy, finished, invalid or query_callbacks member. It includes query_error()
returns and runs before diagnostic initialization too. Only the immediately
governing branch is checked; propagated results and arbitrary control flow remain
outside this lexical guard. Diagnostic-return comments cannot waive this check.
"""
import argparse
from pathlib import Path
import re


MASK = re.compile(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', re.S)
FUNCTION = re.compile(r'\b(\w+)\s*\(([^;{}]*)\)\s*\{')
PARAM = re.compile(r'\btlv_\w*diagnostic_t\s*\*\s*(\w+)')
RETURN = re.compile(r'\breturn\s+(TLV_ERR_\w+|TLV_NEED_MORE_DATA)\s*;')
IF = re.compile(r'\bif\s*\(')
LIFECYCLE = re.compile(r'(?:->|\.)\s*(busy|finished|invalid|query_callbacks)\b')
INVALID_ARGUMENT = re.compile(
    r'\breturn\s+(?:TLV_ERR_INVALID_ARG\s*;|query_error\s*\([^,;]*,\s*TLV_ERR_INVALID_ARG\b)')


def masked(source):
    return MASK.sub(lambda m: ''.join('\n' if c == '\n' else ' ' for c in m[0]), source)


def delimited_end(clean, start, opening, closing):
    depth, end = 1, start + 1
    while end < len(clean) and depth:
        depth += (clean[end] == opening) - (clean[end] == closing)
        end += 1
    return end


def function_bodies(clean):
    end = 0
    for match in FUNCTION.finditer(clean):
        if match.start() < end:
            continue
        end = delimited_end(clean, match.end() - 1, '{', '}')
        yield match, end


def next_token(clean, start):
    while start < len(clean) and clean[start].isspace():
        start += 1
    return start


def statement_end(clean, start):
    start = next_token(clean, start)
    if start == len(clean):
        return start
    if clean[start] == '{':
        return delimited_end(clean, start, '{', '}')
    match = IF.match(clean, start)
    if match:
        condition_end = delimited_end(clean, match.end() - 1, '(', ')')
        end = statement_end(clean, condition_end)
        following = next_token(clean, end)
        if re.match(r'else\b', clean[following:]):
            end = statement_end(clean, following + len('else'))
        return end
    end = start
    while end < len(clean):
        if clean[end] == ';':
            return end + 1
        if clean[end] == '(':
            end = delimited_end(clean, end, '(', ')')
        elif clean[end] == '{':
            return delimited_end(clean, end, '{', '}')
        else:
            end += 1
    return end


def lifecycle_violations(source):
    clean = masked(source)
    errors = []
    for function, end in function_bodies(clean):
        body = clean[function.end():end]
        branches = []
        for match in IF.finditer(body):
            condition_end = delimited_end(body, match.end() - 1, '(', ')')
            condition = body[match.end():condition_end - 1]
            branch_end = statement_end(body, condition_end)
            branches.append((condition_end, branch_end, LIFECYCLE.search(condition)))
            following = next_token(body, branch_end)
            if re.match(r'else\b', body[following:]):
                branches.append((following, statement_end(body, following + len('else')), None))
        for ret in INVALID_ARGUMENT.finditer(body):
            governing = [b for b in branches if b[0] <= ret.start() < b[1]]
            if not governing:
                continue
            _, _, lifecycle = max(governing, key=lambda b: b[0])
            if lifecycle:
                position = function.end() + ret.start()
                errors.append((source.count('\n', 0, position) + 1, function[1], lifecycle[1]))
    return errors


def violations(source):
    clean = masked(source)
    errors = []
    for match, end in function_bodies(clean):
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
        source = path.read_text(encoding='utf-8')
        for line, function, code in violations(source):
            failures.append(f'{path}:{line}: {function}: direct {code} after diagnostic initialization')
        for line, function, member in lifecycle_violations(source):
            failures.append(f'{path}:{line}: {function}: INVALID_ARG under lifecycle member {member}; '
                            'use INVALID_STATE or separate the argument check')
    if failures:
        raise SystemExit('\n'.join(failures))
    print(f'Diagnostic return and lifecycle guards: {len(files)} C files checked')


if __name__ == '__main__':
    main()
