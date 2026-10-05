# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel
import gc
import pytest
from opentlv import (QueryProgram, TreeReader, Visit, Document, InvalidArgError,
                     NeedMoreDataError, LimitError, BufferTooShortError)

WIRE = bytes.fromhex("70065a01015001025a0103")


def test_full_language_variables_scalar_and_image_roundtrip():
    program = QueryProgram("count(//5A[@len >= $minimum])", variables={"minimum": int})
    assert program.info["variables"] == (("minimum", 2),)
    assert program.evaluate(WIRE, bindings={"minimum": 1}) == 2
    loaded = QueryProgram.load(program.image(), variables={"minimum": int})
    assert loaded.format() == program.format()
    assert loaded.evaluate(WIRE, bindings={"minimum": 2}) == 0
    with pytest.raises(InvalidArgError) as error:
        QueryProgram.load(program.image()[:-1], variables={"minimum": int})
    assert error.value.query is not None
    assert "instructions" in program.info
    assert program.explain()


def test_typed_bytes_strings_and_scoped_names_are_copied():
    names = {"fixture:leaf": bytes.fromhex("5a")}
    program = QueryProgram("//fixture:leaf[contains(value(), $needle)]",
                           names=names, variables={"needle": bytes})
    names.clear()
    assert [match.offset for match in program.evaluate(WIRE, bindings={"needle": b"\x03"})] == [8]
    assert QueryProgram("text(x'610062')").evaluate(WIRE) == "a\0b"
    assert QueryProgram("value(//5A[1])").evaluate(bytes.fromhex("5a020001")) == b"\0\x01"


def test_stop_pull_resume_and_owned_results_survive_reset():
    execution = QueryProgram("//5A").execution(retained=False)
    reader = TreeReader(WIRE)
    first = execution.next(reader)
    assert first.offset == 2
    assert not execution.info["finished"]
    assert execution.next(reader).offset == 8
    with pytest.raises(StopIteration):
        execution.next(reader)
    assert execution.info["full_validation"]
    execution.reset()
    gc.collect()
    assert bytes(first.element.value) == b"\x01"


def test_incremental_retention_pins_replaced_input_and_propagates_status():
    execution = QueryProgram("(//5A)[last()]").execution()
    reader = TreeReader(WIRE[:8], final_input=False)
    with pytest.raises(NeedMoreDataError):
        execution.visit(reader, lambda match: Visit.CONTINUE)
    reader.set_input(WIRE, final_input=True)
    gc.collect()
    assert execution.next(reader).offset == 8
    with pytest.raises(StopIteration):
        execution.next(reader)


def test_callback_exception_reentry_terminal_failure_and_reset():
    execution = QueryProgram("//5A").execution(retained=False)
    def callback(match):
        execution.reset()
    with pytest.raises(RuntimeError):
        execution.visit(TreeReader(WIRE), callback)
    assert execution.info["invalid"]
    execution.reset()
    assert execution.exists(TreeReader(WIRE))
    assert execution.info["full_validation"]


def test_explicit_short_workspace_candidate_limit_and_early_coverage():
    program = QueryProgram("//5A")
    with pytest.raises(BufferTooShortError):
        program.execution(workspace=bytearray(1))
    execution = program.execution(max_nodes=1)
    with pytest.raises(LimitError) as error:
        execution.visit(TreeReader(WIRE), lambda match: None)
    assert error.value.query["limit"] == "candidates"
    assert execution.info["invalid"]
    execution = program.execution(retained=False)
    broken = TreeReader(bytes.fromhex("5a005002"))
    assert execution.exists(broken, early_return=True)
    assert not execution.info["full_validation"]
    with pytest.raises(Exception) as error:
        execution.exists(broken)
    assert error.value.query["query_kind"] == 7


def test_document_reverse_axis_revision_context_and_close_guards():
    document = Document(WIRE)
    execution = QueryProgram("//50[preceding-sibling::5A]").execution()
    execution.evaluate_document(document)
    assert execution.next().tag.data == b"\x50"
    with pytest.raises(StopIteration):
        execution.next()
    execution.reset()
    execution.evaluate_document(document)
    document.insert(b"\x5a", b"x")
    with pytest.raises(InvalidArgError):
        execution.next()
    scalar = QueryProgram("count(//5A)").execution()
    scalar.evaluate_document(document)
    assert scalar.result() == 3
    document.close()
    with pytest.raises(ReferenceError):
        scalar.result()


def test_canonical_feed_source_lifetime_and_exact_external_workspace():
    program = QueryProgram("count(//5A[@offset >= 2])")
    size, alignment = program.workspace_size(max_depth=4, max_nodes=20)
    import ctypes
    storage = bytearray(size + alignment)
    address = ctypes.addressof(ctypes.c_char.from_buffer(storage))
    start = (-address) % alignment
    workspace = memoryview(storage)[start:start + size]
    execution = program.execution(max_depth=4, max_nodes=20, workspace=workspace)
    reader = TreeReader(WIRE)
    while True:
        try:
            event = reader.next_event()
        except StopIteration:
            break
        assert execution.feed(event) is None
    del event, reader
    gc.collect()
    execution.finish()
    assert execution.result() == 2
    with pytest.raises(BufferTooShortError):
        program.execution(max_depth=4, max_nodes=20, workspace=workspace[:-1])


def test_document_select_owns_checked_handles_and_scalar_values():
    document = Document(WIRE)
    assert document.select(QueryProgram("count(//5A)")) == 2
    nodes = document.select(QueryProgram("//5A"))
    assert len({node.identity for node in nodes}) == 2
    assert bytes(nodes[0].value) == b"\x01"
