# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel
"""Small test-only Query oracle, independent of the C program and state machine."""
import re


TOKEN = re.compile(r"\s*(x'[0-9a-fA-F]*'|//|::|!=|<=|>=|[()/\[\],|=<>]|\.|[@$]?[a-zA-Z0-9_?*-]+)")


def parse(text):
    tokens = []
    pos = 0
    while pos < len(text):
        match = TOKEN.match(text, pos)
        if not match:
            if text[pos:].isspace():
                break
            raise ValueError(f"token at {pos}")
        tokens.append(match.group(1))
        pos = match.end()
    index = 0
    precedence = {"|": 1, "intersect": 5, "except": 5, "or": 2, "and": 3, "=": 4, "!=": 4, "<": 4,
                  "<=": 4, ">": 4, ">=": 4, "/": 6, "//": 6}

    def expression(minimum=0):
        nonlocal index
        if index >= len(tokens):
            raise ValueError("missing expression")
        token = tokens[index]
        index += 1
        if token in ("/", "//"):
            left = (token, ("root",), expression(7))
        elif token == "(":
            left = expression()
            if index >= len(tokens) or tokens[index] != ")":
                raise ValueError("missing )")
            index += 1
        elif token.startswith("x'"):
            left = ("bytes", bytes.fromhex(token[2:-1]))
        elif token.startswith("@"):
            left = ("meta", token[1:])
        elif index < len(tokens) and tokens[index] == "(":
            index += 1
            args = []
            if index < len(tokens) and tokens[index] != ")":
                while True:
                    args.append(expression())
                    if index >= len(tokens) or tokens[index] != ",":
                        break
                    index += 1
            if index >= len(tokens) or tokens[index] != ")":
                raise ValueError("missing call )")
            index += 1
            left = ("call", token, args)
        elif index < len(tokens) and tokens[index] == "::":
            index += 1
            left = ("test", token, tokens[index])
            index += 1
        else:
            left = ("test", "child", token)
        while index < len(tokens):
            token = tokens[index]
            if token == "[":
                index += 1
                predicate = expression()
                if index >= len(tokens) or tokens[index] != "]":
                    raise ValueError("missing ]")
                index += 1
                left = ("filter", left, predicate)
                continue
            rank = precedence.get(token, -1)
            if rank < minimum:
                break
            index += 1
            right = expression(rank + 1)
            left = (token, left, right)
        return left

    result = expression()
    if index != len(tokens):
        raise ValueError("trailing token")
    return result


def tree(wire, constructed=(0x70,)):
    """Fixture-only one-byte Tag/Length TLV decoder; no C calls."""
    root = {"children": [], "parent": None, "offset": -1, "tag": b"", "depth": -1}
    nodes = []

    def sequence(begin, end, parent):
        pos = begin
        while pos < end:
            if end - pos < 2 or pos + 2 + wire[pos + 1] > end:
                raise ValueError("malformed fixture wire")
            stop = pos + 2 + wire[pos + 1]
            node = {"tag": wire[pos:pos + 1], "value": wire[pos + 2:stop],
                    "offset": pos, "depth": parent["depth"] + 1,
                    "index": len(parent["children"]), "children": [], "parent": parent}
            parent["children"].append(node)
            nodes.append(node)
            if wire[pos] in constructed:
                sequence(pos + 2, stop, node)
            pos = stop
    sequence(0, len(wire), root)
    return root, nodes


def descendants(node):
    for child in node["children"]:
        yield child
        yield from descendants(child)


def raw_test(spelling, node):
    if spelling == "*":
        return True
    tag = node["tag"]
    if len(spelling) != len(tag) * 2:
        return False
    return all(spelling[2 * i:2 * i + 2] == "??" or
               int(spelling[2 * i:2 * i + 2], 16) == byte for i, byte in enumerate(tag))


def evaluate(ast, context, universe):
    op = ast[0]
    if op == "root":
        node = context
        while node["parent"] is not None:
            node = node["parent"]
        return [node]
    if op == "test":
        axis, spelling = ast[1:]
        if spelling == ".":
            return [context]
        if axis == "ancestor":
            candidates = []
            parent = context["parent"]
            while parent is not None and parent["parent"] is not None:
                candidates.append(parent)
                parent = parent["parent"]
        elif axis == "self":
            candidates = [context]
        else:
            candidates = context["children"]
        return [node for node in candidates if raw_test(spelling, node)]
    if op in ("/", "//"):
        parents = evaluate(ast[1], context, universe)
        result = []
        for parent in parents:
            if op == "/":
                result.extend(evaluate(ast[2], parent, universe))
            else:
                # Descendant abbreviation: evaluate the next child selection
                # at this context and each of its descendant contexts.
                for inner in [parent, *descendants(parent)]:
                    result.extend(evaluate(ast[2], inner, universe))
        identities = {node["offset"] for node in result}
        return [node for node in universe if node["offset"] in identities]
    if op == "filter":
        return [node for node in evaluate(ast[1], context, universe)
                if evaluate(ast[2], node, universe)]
    if op == "|":
        identities = {node["offset"] for branch in ast[1:]
                      for node in evaluate(branch, context, universe)}
        return [node for node in universe if node["offset"] in identities]
    if op in ("intersect", "except"):
        left = {node["offset"] for node in evaluate(ast[1], context, universe)}
        right = {node["offset"] for node in evaluate(ast[2], context, universe)}
        identities = left & right if op == "intersect" else left - right
        return [node for node in universe if node["offset"] in identities]
    if op == "bytes":
        return ast[1]
    if op == "meta":
        return len(context["value"]) if ast[1] == "len" else 2 if ast[1] == "hlen" else context[ast[1]]
    if op in ("=", "!=", "<", "<=", ">", ">="):
        def scalar(value):
            if value[0] == "test" and re.fullmatch(r"-?[0-9]+", value[2]):
                return int(value[2])
            return evaluate(value, context, universe)
        a, b = scalar(ast[1]), scalar(ast[2])
        return {"=": lambda: a == b, "!=": lambda: a != b, "<": lambda: a < b,
                "<=": lambda: a <= b, ">": lambda: a > b, ">=": lambda: a >= b}[op]()
    if op in ("and", "or"):
        a = bool(evaluate(ast[1], context, universe))
        b = bool(evaluate(ast[2], context, universe))
        return a and b if op == "and" else a or b
    if op == "call":
        name = ast[1]
        args = [int(arg[2]) if name == "substr" and i and arg[0] == "test" and arg[2].isdecimal()
                else evaluate(arg, context, universe) for i, arg in enumerate(ast[2])]
        if name == "value":
            return context["value"]
        if name == "len":
            return len(args[0]) if args else len(context["value"])
        if name == "not":
            return not args[0]
        if name == "starts-with":
            return args[0].startswith(args[1])
        if name == "ends-with":
            return args[0].endswith(args[1])
        if name == "contains":
            return args[1] in args[0]
        if name == "substr":
            return args[0][args[1]:args[1] + args[2]] if len(args) == 3 else args[0][args[1]:]
        if name in ("tag-mask", "tag-range"):
            selected = []
            for node in context["children"]:
                tag = node["tag"]
                if name == "tag-range":
                    matches = args[0] <= tag <= args[1]
                else:
                    matches = len(tag) == len(args[0]) == len(args[1]) and all(
                        t & mask == pattern & mask for t, pattern, mask in zip(tag, *args))
                if matches:
                    selected.append(node)
            return selected
        raise ValueError("unsupported function")
    raise ValueError("unsupported expression")


def select(query, wire):
    root, nodes = tree(wire)
    return [node["offset"] for node in evaluate(parse(query), root, nodes)]


def v1_baseline(query, wire):
    """Frozen exact-path behavior: compare the entire ancestor tag sequence."""
    _, nodes = tree(wire)
    path = [bytes.fromhex(step) for step in query.split("/")]
    result = []
    for node in nodes:
        ancestry = []
        current = node
        while current["parent"] is not None:
            ancestry.append(current["tag"])
            current = current["parent"]
        if ancestry[::-1] == path:
            result.append(node["offset"])
    return result
