# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel
"""Small test-only Query oracle, independent of the C program and state machine."""
import re
import datetime


TOKEN = re.compile(r"\s*(x'[0-9a-fA-F]*'|'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"|//|::|!=|<=|>=|[()/\[\],|=<>]|\.\.|\.|[a-zA-Z][a-zA-Z0-9_-]*:[a-zA-Z][a-zA-Z0-9_-]*|[@$]?[a-zA-Z0-9_?*-]+)")


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
            left = ("group", left)
        elif token.startswith("x'"):
            left = ("bytes", bytes.fromhex(token[2:-1]))
        elif token.startswith(("'", '\"')):
            left = ("string", re.sub(r"\\(.)", r"\1", token[1:-1]))
        elif token in ("true", "false"):
            left = ("bool", token == "true")
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
            left = ("test", token, tokens[index], "explicit")
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
    if ':' in spelling:
        spelling = {"fixture:leaf":"5A", "fixture:container":"70"}[spelling]
    tag = node["tag"]
    if len(spelling) != len(tag) * 2:
        return False
    return all(spelling[2 * i:2 * i + 2] == "??" or
               int(spelling[2 * i:2 * i + 2], 16) == byte for i, byte in enumerate(tag))


def evaluate(ast, context, universe, position=1, last=1):
    op = ast[0]
    if op == "group":
        value = evaluate(ast[1], context, universe, position, last)
        return sorted(value, key=lambda n: n["offset"]) if isinstance(value, list) else value
    if op == "root":
        node = context
        while node["parent"] is not None:
            node = node["parent"]
        return [node]
    if op == "test":
        axis, spelling = ast[1:3]
        if spelling == ".":
            return [context]
        if spelling == "..":
            return [context["parent"]] if context["parent"] is not None else []
        if axis in ("ancestor", "ancestor-or-self"):
            candidates = [context] if axis == "ancestor-or-self" and context["parent"] is not None else []
            parent = context["parent"]
            while parent is not None and parent["parent"] is not None:
                candidates.append(parent)
                parent = parent["parent"]
        elif axis == "parent":
            parent = context["parent"]
            candidates = [parent] if parent is not None and parent["parent"] is not None else []
        elif axis in ("descendant", "descendant-or-self"):
            candidates = ([context] if axis == "descendant-or-self" and context["parent"] is not None else []) + list(descendants(context))
        elif axis in ("following-sibling", "preceding-sibling"):
            siblings = context["parent"]["children"] if context["parent"] else []
            candidates = [n for n in siblings if n["index"] > context.get("index", -1)] if axis == "following-sibling" else [n for n in reversed(siblings) if n["index"] < context.get("index", -1)]
        elif axis in ("following", "preceding"):
            if context["parent"] is None:
                candidates = []
            elif axis == "following":
                excluded = {id(n) for n in descendants(context)}
                candidates = [n for n in universe if n["offset"] > context["offset"] and id(n) not in excluded]
            else:
                ancestors = set()
                parent = context["parent"]
                while parent:
                    ancestors.add(id(parent))
                    parent = parent["parent"]
                candidates = [n for n in reversed(universe) if n["offset"] < context["offset"] and id(n) not in ancestors]
        elif axis == "self":
            candidates = [context] if context["parent"] is not None else []
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
        root = context
        while root["parent"] is not None:
            root = root["parent"]
        return [node for node in [root, *universe] if node["offset"] in identities]
    if op == "filter":
        selected = evaluate(ast[1], context, universe)
        result = []
        for index, node in enumerate(selected, 1):
            predicate = ast[2]
            value = int(predicate[2]) if predicate[0] == "test" and len(predicate) == 3 and predicate[1] == "child" and re.fullmatch(r"-?[0-9]+", predicate[2]) else evaluate(predicate, node, universe, index, len(selected))
            if (value == index if type(value) is int else bool(value)):
                result.append(node)
        return result
    if op == "|":
        identities = {node["offset"] for branch in ast[1:]
                      for node in evaluate(branch, context, universe)}
        root = context
        while root["parent"] is not None:
            root = root["parent"]
        return [node for node in [root, *universe] if node["offset"] in identities]
    if op in ("intersect", "except"):
        left = {node["offset"] for node in evaluate(ast[1], context, universe)}
        right = {node["offset"] for node in evaluate(ast[2], context, universe)}
        identities = left & right if op == "intersect" else left - right
        root = context
        while root["parent"] is not None:
            root = root["parent"]
        return [node for node in [root, *universe] if node["offset"] in identities]
    if op in ("bool", "string"):
        return ast[1]
    if op == "bytes":
        return ast[1]
    if op == "meta":
        return len(context["value"]) if ast[1] == "len" else 2 if ast[1] == "hlen" else context[ast[1]]
    if op in ("=", "!=", "<", "<=", ">", ">="):
        def scalar(value):
            if value[0] == "test" and len(value) == 3 and re.fullmatch(r"-?[0-9]+", value[2]):
                return int(value[2])
            return evaluate(value, context, universe, position, last)
        a, b = scalar(ast[1]), scalar(ast[2])
        return {"=": lambda: a == b, "!=": lambda: a != b, "<": lambda: a < b,
                "<=": lambda: a <= b, ">": lambda: a > b, ">=": lambda: a >= b}[op]()
    if op in ("and", "or"):
        a = bool(evaluate(ast[1], context, universe, position, last))
        b = bool(evaluate(ast[2], context, universe, position, last))
        return a and b if op == "and" else a or b
    if op == "call":
        name = ast[1]
        args = [int(arg[2]) if name == "substr" and i and arg[0] == "test" and arg[2].isdecimal()
                else evaluate(arg, context, universe, position, last) for i, arg in enumerate(ast[2])]
        if name in ("count", "exists", "empty"):
            return len(args[0]) if name == "count" else bool(args[0]) if name == "exists" else not args[0]
        if name in ("position", "last"):
            return position if name == "position" else last
        if name in ("value", "tag", "constructed", "num", "bcd", "text", "date", "class", "number"):
            value = args[0] if args else [context]
            if isinstance(value, list):
                if len(value) != 1 or value[0]["parent"] is None:
                    raise ValueError("cardinality")
                node = value[0]
                value = node["tag"] if name in ("tag", "class", "number") else node["value"]
                if name == "constructed":
                    return node["tag"] == b"\x70"
            if name in ("value", "tag"):
                return value
            if name == "class":
                return value[0] >> 6
            if name == "number":
                if value[0] & 31 != 31:
                    return value[0] & 31
                number = 0
                for byte in value[1:]:
                    number = (number << 7) | (byte & 127)
                return number
            if name == "date":
                return int(datetime.datetime.strptime(value.decode('ascii'), '%Y%m%d%H%M%SZ').replace(tzinfo=datetime.timezone.utc).timestamp())
            if name == "num":
                if not value or len(value) > 8:
                    raise ValueError("integer size")
                return int.from_bytes(value, "big", signed=True)
            if name == "bcd":
                digits = value.hex()
                if not digits.isdecimal():
                    raise ValueError("BCD")
                return int(digits)
            if name == "text":
                return value.decode("utf-8")
        if name == "name":
            spelling = args[0] + ':' + args[1]
            return [n for n in context["children"] if raw_test(spelling,n)]
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
    value = evaluate(parse(query), root, nodes)
    if isinstance(value, list):
        return sorted({node["offset"] for node in value if node["parent"] is not None})
    if isinstance(value, bool):
        return f"bool:{int(value)}"
    if isinstance(value, int):
        return f"int:{value}"
    if isinstance(value, str):
        return "string:" + value.encode().hex()
    return "bytes:" + value.hex()


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
