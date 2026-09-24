import pytest

from opentlv import codec


def test_decode_amount_matches_the_emv_format_n12_example():
    assert codec.decode_amount(bytes.fromhex("000000012345")) == 12345


def test_encode_amount_matches_the_emv_format_n12_example():
    assert codec.encode_amount(12345) == bytes.fromhex("000000012345")


def test_amounts_round_trip():
    for value in (0, 1, 999999999999):
        assert codec.decode_amount(codec.encode_amount(value)) == value


def test_decode_amount_rejects_the_wrong_length():
    with pytest.raises(codec.CodecError) as excinfo:
        codec.decode_amount(b"\x00\x00\x01")
    assert isinstance(excinfo.value.code, int)
    assert str(excinfo.value)


def test_encode_amount_rejects_a_value_that_does_not_fit():
    with pytest.raises(codec.CodecError):
        codec.encode_amount(10**13)
