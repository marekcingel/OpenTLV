from opentlv import Entry, Tag


def test_exposes_tag_and_value():
    tag = Tag(b"\x5a")
    entry = Entry(tag, memoryview(b"\x01\x02\x03"))
    assert entry.tag == tag
    assert bytes(entry.value) == b"\x01\x02\x03"


def test_equality_compares_tag_and_value():
    a = Entry(Tag(b"\x01"), memoryview(b"\xaa"))
    b = Entry(Tag(b"\x01"), memoryview(b"\xaa"))
    c = Entry(Tag(b"\x02"), memoryview(b"\xaa"))
    assert a == b
    assert a != c
    assert a != "not an entry"


def test_repr_shows_tag_and_value():
    entry = Entry(Tag(b"\x9f\x02"), memoryview(b"\xde\xad"))
    assert repr(entry) == "Entry(tag=Tag(9F02), value=b'\\xde\\xad')"
