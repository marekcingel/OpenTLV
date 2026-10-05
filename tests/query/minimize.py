# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel
"""Bounded deterministic shrinking of generated oracle/native disagreements."""
from reference import select, tree


def wire_candidates(wire):
    """Remove subtrees or shorten primitive Values, preserving valid framing."""
    root, nodes = tree(wire)

    def encode(node, removed=None, shortened=None):
        if node is removed:
            return b""
        if node is root or node["tag"] == b"\x70":
            value = b"".join(encode(child, removed, shortened) for child in node["children"])
        else:
            value = node["value"]
            if node is shortened:
                value = value[:len(value) // 2]
        return value if node is root else node["tag"] + bytes([len(value)]) + value

    for node in nodes:
        candidate = encode(root, removed=node)
        # The command-line adapter requires a nonempty input argument.
        if candidate:
            yield candidate
        if node["tag"] != b"\x70" and node["value"]:
            yield encode(root, shortened=node)


def query_candidates(query):
    """Remove complete predicates; quotes protect literal bracket characters."""
    stack, quote, escaped = [], None, False
    for index, character in enumerate(query):
        if quote:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
        elif character in "'\"":
            quote = character
        elif character == "[":
            stack.append(index)
        elif character == "]" and stack:
            begin = stack.pop()
            yield query[:begin] + query[index + 1:]


def minimize(case, disagrees, budget=128):
    """Recompute oracle outputs for each candidate; never reuse old offsets.

    ``disagrees`` receives a valid candidate and its independent expectation.
    The budget bounds native subprocess calls. Diagnostics/provider fixtures
    are intentionally excluded: their framing is not the generated grammar.
    """
    current = dict(case)
    attempts = 0
    while attempts < budget:
        accepted = False
        wire = bytes.fromhex(current["wire"])
        candidates = (dict(current, wire=value.hex()) for value in wire_candidates(wire))
        queries = (dict(current, query=value) for value in query_candidates(current["query"]))
        from itertools import chain
        for candidate in chain(candidates, queries):
            if attempts >= budget:
                break
            try:
                expected = select(candidate["query"], bytes.fromhex(candidate["wire"]),
                                  candidate.get("variables"))
            except (ValueError, KeyError, TypeError):
                continue
            attempts += 1
            if disagrees(candidate, expected):
                current = dict(candidate, matches=expected)
                accepted = True
                break
        if not accepted:
            break
    return current, attempts
