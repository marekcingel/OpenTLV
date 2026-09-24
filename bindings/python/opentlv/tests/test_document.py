import pytest

from opentlv import BufferTooShortError, Document, Format, Node, Tag, Writer


def test_parses_and_iterates_top_level_nodes():
    data = bytes([0x01, 0x02, 0xAA, 0xBB, 0x02, 0x00])
    doc = Document(data)
    assert len(doc) == 2
    nodes = list(doc)
    assert len(nodes) == 2
    assert nodes[0].tag == Tag(b"\x01")
    assert nodes[0].value == b"\xaa\xbb"
    assert nodes[0].is_constructed is False
    assert nodes[1].value == b""


def test_empty_document_has_no_nodes():
    doc = Document()
    assert len(doc) == 0
    assert doc.first is None
    assert list(doc) == []


def test_set_value_and_encode():
    doc = Document(bytes([0x01, 0x02, 0xAA, 0xBB]))
    doc.first.value = b"\xcc"
    assert doc.encode() == bytes([0x01, 0x01, 0xCC])
    assert doc.encoded_size == len(doc.encode())


def test_insert_appends_by_default():
    doc = Document(bytes([0x01, 0x00]))
    node = doc.insert(Tag(b"\x02"), b"\x99")
    assert list(doc)[-1] == node
    assert node.value == b"\x99"


def test_insert_before_an_existing_sibling():
    doc = Document(bytes([0x02, 0x00]))
    existing = doc.first
    doc.insert(Tag(b"\x01"), b"", before=existing)
    tags = [node.tag for node in doc]
    assert tags == [Tag(b"\x01"), Tag(b"\x02")]


def test_erase_removes_a_node_and_its_descendants():
    doc = Document(bytes([0x01, 0x00, 0x02, 0x00]))
    first, second = list(doc)
    first.erase()
    assert len(doc) == 1
    assert list(doc) == [second]


def test_erase_via_document_insert_result_round_trips():
    doc = Document()
    node = doc.insert(Tag(b"\x01"), b"\xaa")
    assert doc.encode() == bytes([0x01, 0x01, 0xAA])
    node.erase()
    assert doc.encode() == b""


def test_nested_ber_navigation():
    inner = Writer(Format.BER)
    inner.write(Tag(b"\x81"), b"\xAA")
    outer = Writer(Format.BER)
    outer.write(Tag(b"\xA0"), inner.bytes())

    doc = Document(outer.bytes(), Format.BER)
    top = doc.first
    assert top.is_constructed is True
    assert top.value == b""
    child = top.first_child
    assert child.tag == Tag(b"\x81")
    assert child.value == b"\xAA"
    assert child.parent == top
    assert list(top) == [child]


def test_find_and_find_path():
    inner = Writer(Format.BER)
    inner.write(Tag(b"\x81"), b"\xAA")
    outer = Writer(Format.BER)
    outer.write(Tag(b"\xA0"), inner.bytes())
    doc = Document(outer.bytes(), Format.BER)

    top = doc.find(Tag(b"\xA0"))
    assert top == doc.first
    child = doc.find(Tag(b"\x81"), parent=top)
    assert child == top.first_child
    assert doc.find_path("A0/81") == child
    assert doc.find(Tag(b"\x99")) is None
    assert doc.find_path("99") is None


def test_next_same_tag_skips_other_tags():
    doc = Document(bytes([0x01, 0x00, 0x02, 0x00, 0x01, 0x00]))
    first, second, third = list(doc)
    assert first.next_same_tag() == third
    assert second.next_same_tag() is None


def test_insert_a_constructed_value_from_raw_nested_encoding():
    grandchild = Writer(Format.BER)
    grandchild.write(Tag(b"\x82"), b"\x01")
    doc = Document(format=Format.BER)
    node = doc.insert(Tag(b"\xA1"), grandchild.bytes())
    assert node.is_constructed is True
    assert node.first_child.tag == Tag(b"\x82")


def test_node_equality_and_hash():
    doc = Document(bytes([0x01, 0x00, 0x02, 0x00]))
    first, second = list(doc)
    assert first == doc.first
    assert first != second
    assert first != "not a node"
    assert hash(first) == hash(doc.first)


def test_node_encode_and_encoded_size():
    doc = Document(bytes([0x01, 0x02, 0xAA, 0xBB]))
    node = doc.first
    assert node.encode() == bytes([0x01, 0x02, 0xAA, 0xBB])
    assert node.encoded_size == 4


def test_close_invalidates_the_document():
    with Document(bytes([0x01, 0x00])) as doc:
        assert len(doc) == 1
    with pytest.raises(ValueError):
        len(doc)


def test_repr_shows_count_and_tag():
    doc = Document(bytes([0x01, 0x00, 0x02, 0x00]))
    assert repr(doc) == "Document(count=2)"
    assert "Tag(01)" in repr(doc.first)
    assert "primitive" in repr(doc.first)


def test_document_parse_reports_buffer_too_short():
    with pytest.raises(BufferTooShortError):
        Document(bytes([0x01, 0x05, 0xAA]))


def test_document_accepts_bytearray_and_memoryview():
    for data in (bytearray([0x01, 0x00]), memoryview(bytes([0x01, 0x00]))):
        doc = Document(data)
        assert len(doc) == 1


def test_isinstance_node():
    doc = Document(bytes([0x01, 0x00]))
    assert isinstance(doc.first, Node)
