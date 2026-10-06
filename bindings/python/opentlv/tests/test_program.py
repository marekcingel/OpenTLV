# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel
import gc
import pytest
from opentlv import (QueryProgram, TreeReader, Visit, Document, InvalidArgError,
                     NeedMoreDataError, LimitError, BufferTooShortError, QueryProvider,
                     InvalidValueError, QueryRule, QuerySchema, SchemaError, UnsupportedTypeError)

WIRE = bytes.fromhex("70065a01015001025a0103")


def test_query_schema_buffer_document_owned_diagnostics_and_limits():
    context = QueryProgram("//5A")
    schema = QuerySchema([QueryRule(context, QueryProgram("num(.) = 1"), "one")])
    good = bytes.fromhex("70035a0101")
    bad = bytearray.fromhex("70035a0102")
    schema.validate_buffer(good)
    schema.validate_document(Document(good))
    QuerySchema([QueryRule(QueryProgram("//5B"), QueryProgram("1 = 0"))]).validate_buffer(bad)
    with pytest.raises(SchemaError) as caught:
        schema.validate_buffer(bad)
    detail = caught.value.schema
    assert caught.value.rule == 0
    assert detail["kind_name"] == "assertion" and detail["code"] == caught.value.code
    assert detail["tag"] == b"\x5a" and detail["path"] == (b"\x70",)
    assert detail["offset"] == 2 and detail["field"] == "one"
    assert detail["expected"] == "contextual Query assertion true"
    document = Document(bad)
    with pytest.raises(SchemaError) as document_failure:
        schema.validate_document(document)
    assert document_failure.value.schema["offset"] is None
    document.close()
    bad[:] = b"\0" * len(bad)
    del schema, context
    gc.collect()
    assert document_failure.value.schema["path"] == (b"\x70",)
    assert detail["tag"] == b"\x5a" and detail["field"] == "one"
    schema = QuerySchema([QueryRule(QueryProgram("//5A"), QueryProgram("1 = 1"))])
    with pytest.raises(LimitError) as limit:
        schema.validate_buffer(good, max_contexts=0)
    assert limit.value.query["limit"] == "schema-contexts"
    with pytest.raises(LimitError):
        schema.validate_buffer(good, max_work=1)
    with pytest.raises(InvalidArgError):
        QuerySchema([QueryRule(QueryProgram("//5A"), QueryProgram("count(.)"))]).validate_buffer(good)
    reverse = QuerySchema([QueryRule(QueryProgram("//5A[2]"),
                                    QueryProgram("exists(preceding::5A)"))])
    siblings = bytes.fromhex("70065a01015a0102")
    with pytest.raises(UnsupportedTypeError):
        reverse.validate_buffer(siblings)
    reverse.validate_document(Document(siblings))
    empty_root = QueryProgram("value(//70)").execution(max_depth=0)
    empty_root.evaluate_document(Document(b"\x70\0"))
    assert empty_root.result() == b""


def test_query_schema_provider_lifetime_exception_reentry_and_document_guards():
    document = Document(bytes.fromhex("70035a0101"))
    node = document.first.first_child
    actions = []
    def decode(value, metadata):
        assert metadata.element.tag.data == b"\x5a"
        for action in actions:
            with pytest.raises(RuntimeError):
                action()
        return value[0]
    providers = {"num": QueryProvider(201, decode)}
    assertion = QueryProgram("num(.) = 1", providers=providers)
    schema = QuerySchema([QueryRule(QueryProgram("//5A"), assertion)])
    del assertion, providers
    gc.collect()
    actions.extend([document.close, node.erase, lambda: setattr(node, "value", b"x"),
                    lambda: schema.validate_document(document)])
    schema.validate_document(document)
    assert bytes(node.value) == b"\x01"
    actions.clear()
    schema.validate_buffer(bytes.fromhex("5a0101"))
    sentinel = ValueError("schema provider failure")
    def fail(value, metadata):
        raise sentinel
    failed = QuerySchema([QueryRule(QueryProgram("//5A"),
                                    QueryProgram("num(.) = 1", providers={"num": QueryProvider(202, fail)}))])
    with pytest.raises(ValueError) as caught:
        failed.validate_document(document)
    assert caught.value is sentinel
    document.close()


def test_custom_conversion_provider_lifetime_images_and_backends():
    calls = []
    def decode(value, metadata):
        calls.append((value, metadata))
        return value[0] * 10
    providers = {"num": QueryProvider(101, decode)}
    program = QueryProgram("num(//5A)", providers=providers)
    providers.clear()
    gc.collect()
    assert program.evaluate(bytes.fromhex("5a0103")) == 30
    assert calls[-1][1].offset == 0
    assert calls[-1][1].element.tag.data == b"\x5a"
    loaded = QueryProgram.load(program.image(), providers={"num": QueryProvider(101, decode)})
    assert loaded.evaluate(bytes.fromhex("5a0104")) == 40
    with pytest.raises(InvalidArgError):
        QueryProgram.load(program.image())
    execution = program.execution()
    document = Document(bytes.fromhex("5a0102"))
    execution.evaluate_document(document)
    assert execution.result() == 20


def test_custom_text_provider_has_exact_bounded_result_scratch():
    provider = QueryProvider(102, lambda value, metadata: "a\0b", max_result_bytes=3)
    assert QueryProgram("text(//5A)", providers={"text": provider}).evaluate(b"\x5a\0") == "a\0b"
    short = QueryProvider(102, provider.decode, max_result_bytes=2)
    with pytest.raises(InvalidValueError) as error:
        QueryProgram("text(//5A)", providers={"text": short}).evaluate(b"\x5a\0")
    assert error.value.query["codec"] == 2


def test_provider_exception_and_execution_reentry_are_preserved():
    execution = None
    def decode(value, metadata):
        execution.reset()
        return 1
    program = QueryProgram("num(//5A)", providers={"num": QueryProvider(103, decode)})
    execution = program.execution()
    reader = TreeReader(b"\x5a\0")
    with pytest.raises(RuntimeError, match="active in a callback"):
        execution.visit(reader, lambda match: None)
    execution.reset()
    def failure(value, metadata):
        raise LookupError("provider failed")
    with pytest.raises(LookupError, match="provider failed"):
        QueryProgram("num(//5A)", providers={"num": QueryProvider(104, failure)}).evaluate(b"\x5a\0")


def test_completed_document_edits_preserve_short_selection_and_overlap():
    wire = bytes.fromhex("70065a01015a01025a0103")
    document = Document(wire)
    old_node = document.first.first_child
    execution = QueryProgram("//5A").execution().evaluate_document(document)
    with pytest.raises(BufferTooShortError) as failure:
        execution.edit_document("replace", value=b"\x09", target_capacity=2)
    assert failure.value.applied == 0 and document.encode() == wire
    assert execution.edit_document("replace", value=b"\x09", target_capacity=3) == 3
    with pytest.raises(ValueError, match="no longer valid"):
        old_node.value
    assert document.encode() == bytes.fromhex("70065a01095a01095a0109")
    with pytest.raises(InvalidArgError):
        execution.next()
    execution.reset()
    execution.evaluate_document(document)
    assert execution.edit_document("insert_after", tag=b"\x5b", value=b"\x04") == 3
    assert QueryProgram("count(//5B)").execution().evaluate_document(document).result() == 3
    ancestor = QueryProgram("//70 | //5A").execution().evaluate_document(document)
    assert ancestor.edit_document("remove") == 2
    assert document.encode() == b"\x5b\x01\x04"


def test_invalid_constructed_query_replacement_is_atomic():
    wire = bytes.fromhex("70035a0101")
    document = Document(wire)
    execution = QueryProgram("//70").execution().evaluate_document(document)
    with pytest.raises(BufferTooShortError) as failure:
        execution.edit_document("replace", value=b"\x5a")
    assert failure.value.applied == 0 and document.encode() == wire
    execution.reset()
    execution.evaluate_document(document)
    assert execution.edit_document("replace", value=b"\x5a\x00") == 1


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
