"""A narrow Codec binding: the one concrete value codec the public OpenTLV C
API exports.

`tlv/include/tlv/codec/codec.h` defines a generic `tlv_codec_t` mechanism,
but the only concrete codec built from it and exported publicly is
`tlv_emv_codec_amount` (`tlv/include/tlv/builtins/emv/emv_codec.h`), for EMV
format n12 amounts. Every other EMV value kind (dates, Track 2, AFL, CVM
results, and so on) is decoded internally by functions declared only in a
private header under `tlv/src/`, not in `tlv/include/`, so binding them here
would mean reimplementing that logic instead of calling into C for it. See
[Using OpenTLV from Python](https://marekcingel.github.io/OpenTLV/guides/python/#codec).
"""

from __future__ import annotations

import opentlv_native as _native


class CodecError(Exception):
    """A failed value conversion, mapped from a non-zero `tlv_codec_result_t`.

    This is a separate error domain from `OpenTLVError`: codec conversion
    errors are independent of TLV framing errors.
    """

    def __init__(self, code: int) -> None:
        super().__init__(_native.codec_strerror(code))
        self.code = code


def decode_amount(data: bytes) -> int:
    """Decodes 6 bytes of BCD (EMV format n12) into an unscaled minor-unit amount.

    Wraps the public C `tlv_emv_codec_amount` codec.

    >>> decode_amount(bytes.fromhex("000000012345"))
    12345
    """
    try:
        return _native.emv_decode_amount(data)
    except _native.CodecError as native_error:
        (code,) = native_error.args
        raise CodecError(code) from None


def encode_amount(value: int) -> bytes:
    """Encodes an unscaled minor-unit amount as 6 bytes of BCD (EMV format n12).

    >>> encode_amount(12345).hex()
    '000000012345'
    """
    try:
        return _native.emv_encode_amount(value)
    except _native.CodecError as native_error:
        (code,) = native_error.args
        raise CodecError(code) from None
