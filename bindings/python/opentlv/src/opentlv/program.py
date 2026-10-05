# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel
"""Immutable full-language C Query programs and independent bounded executions."""
from dataclasses import dataclass
from types import MappingProxyType
import _opentlv as _native
from opentlv.cursor import TreeReader, Visit
from opentlv.element import Element
from opentlv.error import _from_native, EndOfBufferError
from opentlv.format import _resolve_format
from opentlv.tag import Tag


def _call(function, *args):
    try:
        return function(*args)
    except _native.Error as error:
        raise _from_native(error) from None


@dataclass(frozen=True)
class QueryMatch:
    """Owned event snapshot; copied bytes remain valid after reset/input replacement."""
    element: Element
    depth: int
    offset: int
    constructed: bool


def _match(raw):
    kind, tag, value, depth, offset = raw
    return QueryMatch(Element(Tag(tag), memoryview(value)), depth, offset, kind == 0)


class QueryProgram:
    """Full compiled language, independent of the legacy V1 Query matcher.

    C owns syntax, types, optimizer and evaluation. Owning Python storage and
    copied results allocate; the C compiler/VM remain allocation-free. Names
    map scoped spellings to raw Tag bytes and are copied during compilation.
    Builtin Format, generic NUM/BCD/TEXT and ASN.1 tag/DATE capabilities are
    explicit through ``format``. Internal images are version-limited.
    """
    __slots__ = ("_capsule", "_format", "_declarations", "_names", "_options")

    def __init__(self, text, *, format=None, variables=None, names=None, **options):
        if not isinstance(text, str):
            raise TypeError("Query text must be str")
        self._initialize(text.encode("utf-8"), format, variables, names, options, False)

    def _initialize(self, data, format, variables, names, options, image):
        self._format = _resolve_format(format)
        kinds = {int: 2, bytes: 3, str: 4}
        self._declarations = {name: kinds[kind] for name, kind in (variables or {}).items()}
        if any(not isinstance(name, str) or "\0" in name for name in self._declarations):
            raise ValueError("variable names must be NUL-free str")
        self._names = {name: bytes(tag.data if isinstance(tag, Tag) else tag)
                       for name, tag in (names or {}).items()}
        allowed = {"max_text", "max_tokens", "max_nesting", "max_states", "max_pattern",
                   "max_resolved_tag", "optimize"}
        if options.keys() - allowed:
            raise TypeError(f"unknown compile options: {options.keys() - allowed}")
        self._options = dict(options)
        self._capsule = _call(_native.program_create, data, int(self._format),
                              self._declarations, self._names, self._options, image)

    @classmethod
    def load(cls, image, *, format=None, variables=None, names=None, **options):
        """Validate and own a copy of a same-release image with original compile options."""
        result = cls.__new__(cls)
        result._initialize(bytes(image), format, variables, names, options, True)
        return result

    @property
    def info(self):
        """Immutable whole-expression requirements and referenced variable types."""
        info = _call(_native.program_info, self._capsule)
        info["variables"] = tuple(info["variables"])
        return MappingProxyType(info)

    def format(self):
        """Canonical language spelling from C."""
        return _call(_native.program_render, self._capsule, 0)

    def explain(self):
        """Implementation-specific C plan details."""
        return _call(_native.program_render, self._capsule, 1)

    def image(self):
        """Copy release-specific native-layout bytes; no persistent compatibility promise."""
        return _call(_native.program_render, self._capsule, 2)

    def execution(self, *, max_depth=64, max_nodes=1024, max_work=10000000,
                  retained=True, workspace=None):
        """Create separate S0/S1 or retained S0-S2/D state with explicit resource bounds.

        ``workspace`` pins a contiguous writable aligned caller buffer; short or
        misaligned buffers fail through C. No backend fallback occurs.
        """
        return QueryExecution(self, max_depth, max_nodes, max_work, retained, workspace)

    def workspace_size(self, *, max_depth=64, max_nodes=1024, retained=True):
        """Return exact native (bytes, alignment) for an explicit caller workspace."""
        return _call(_native.execution_size, self._capsule, max_depth, max_nodes, retained)

    def evaluate(self, data, *, bindings=None, **limits):
        """Evaluate complete input, returning owned scalar or ordered owned event snapshots."""
        execution = self.execution(**limits)
        for name, value in (bindings or {}).items():
            execution.bind(name, value)
        reader = TreeReader(data, self._format, max_depth=execution._limits[0],
                            frame_capacity=execution._limits[0], max_elements=execution._limits[1])
        matches = []
        execution.visit(reader, matches.append)
        return matches if self.info["result_kind"] == 0 else execution.result()


class QueryExecution:
    """Independent continuation; pins program, typed bindings and every input window.

    STOP and NEED_MORE_DATA preserve continuation. Exceptions propagate only
    after returning through C; a visitor error invalidates state until reset.
    Tree callback/pull results and scalars are owned copies. Document pulls
    return checked Nodes and reject edits or destruction before native access.
    """
    __slots__ = ("_program", "_capsule", "_limits", "_retained", "_workspace", "_document")

    def __init__(self, program, depth, nodes, work, retained, workspace):
        self._program = program
        self._limits = (depth, nodes, work)
        self._retained = retained
        self._workspace = workspace
        self._document = None
        self.reset()

    def _check(self):
        if self._document is not None and self._document._capsule is None:
            raise ReferenceError("Query Document has been closed")

    def reset(self):
        """Discard continuation, borrowed windows, bindings and Document snapshot."""
        if hasattr(self, "_capsule"):
            _call(_native.execution_info, self._capsule)  # Reject callback reentry.
        self._capsule = _call(_native.execution_create, self._program._capsule,
                              *self._limits, self._retained, self._workspace)
        self._document = None

    def bind(self, name, value):
        """Bind an integer, bytes or UTF-8 string before input; no interpolation."""
        self._check()
        if not isinstance(name, str) or "\0" in name:
            raise ValueError("binding names must be NUL-free str")
        kind = {int: 2, bytes: 3, str: 4}.get(type(value))
        if kind is None:
            raise TypeError("binding must be int, bytes or str")
        _call(_native.execution_bind, self._capsule, name, kind,
              value.encode("utf-8") if kind == 4 else value)
        return self

    def context(self, ordinal):
        """Set a relative traversal context before consuming input."""
        self._check()
        _call(_native.execution_control, self._capsule, 0, ordinal)
        return self

    def pruning(self, enabled=True):
        """Explicitly permit proven pruning; skipped content has partial coverage."""
        self._check()
        _call(_native.execution_control, self._capsule, 1, int(enabled))
        return self

    @property
    def info(self):
        """Counters and full/partial structural-validation coverage."""
        self._check()
        return MappingProxyType(_call(_native.execution_info, self._capsule))

    def visit(self, reader, callback):
        """Visit owned snapshots; return Visit.CONTINUE/STOP/ERROR or None."""
        self._check()
        if not isinstance(reader, TreeReader):
            raise TypeError("TreeReader required")
        _call(_native.execution_visit, self._capsule, reader._capsule,
              lambda raw: callback(_match(raw)), 0)

    def feed(self, event):
        """Feed a complete canonical TreeEvent, pinning its bytes and original Source.

        Immediate S0/S1 selection returns an owned QueryMatch; retained execution
        publishes only after finish(). Failed structural feeds invalidate state.
        """
        self._check()
        item = event.item
        raw = _call(_native.execution_feed, self._capsule, int(event.kind),
                    item.element.tag.data if item else b"",
                    bytes(item.element.value) if item else b"", event.depth, event.offset,
                    item.decoded._source if item else None, event.skipped)
        return None if raw is None else _match(raw)

    def finish(self):
        """Require balanced final events and finalize retained evaluation."""
        self._check()
        _call(_native.execution_finish, self._capsule)

    def exists(self, reader, *, early_return=False):
        """Drain input by default; early success requires inspecting partial coverage."""
        self._check()
        if not isinstance(reader, TreeReader):
            raise TypeError("TreeReader required")
        return _call(_native.execution_visit, self._capsule, reader._capsule,
                     None, 2 if early_return else 1)

    def evaluate_document(self, document, *, context=None, value_capacity=None):
        """Finalize against an immutable Document revision with explicit Value storage."""
        self._check()
        if document._capsule is None:
            raise ReferenceError("Query Document has been closed")
        capacity = document.encoded_size if value_capacity is None else value_capacity
        _call(_native.execution_document, self._capsule, document._capsule,
              document._node_ptr(context), capacity)
        self._document = document
        return self

    def result(self):
        """Return an owned finalized scalar; node results use next()."""
        self._check()
        return _call(_native.execution_result, self._capsule)

    def next(self, reader=None):
        """Pull one match; END_OF_BUFFER becomes StopIteration, not NEED_MORE_DATA."""
        self._check()
        try:
            if reader is not None:
                if self._program.info["result_kind"] != 0:
                    raise TypeError("node Query required")
                selected = []
                self.visit(reader, lambda match: (selected.append(match), Visit.STOP)[1])
                if not selected:
                    raise StopIteration
                return selected[0]
            raw = _call(_native.execution_next, self._capsule)
            return self._document._wrap(raw) if self._document is not None else _match(raw)
        except EndOfBufferError:
            raise StopIteration from None

    def __iter__(self):
        return self

    def __next__(self):
        return self.next()
