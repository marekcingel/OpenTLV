"""Decodes and encodes an EMV format n12 amount (BCD, tag 9F02 "Amount,
Authorised") with opentlv.codec, the one concrete value codec the public
OpenTLV C API exports; see docs/guides/python.md#codec for why the rest of
the EMV value model is not bound.

Run with `python examples/codec.py` from `bindings/python/opentlv`, after
installing both packages.
"""

import opentlv
from opentlv import codec

# 9F02 06 00 00 00 01 23 45 -- an "Amount, Authorised" entry for 12345
# (unscaled minor units, e.g. EUR 123.45).
ENTRY = bytes([0x9F, 0x02, 0x06, 0x00, 0x00, 0x00, 0x01, 0x23, 0x45])


def main() -> None:
    (entry,) = list(opentlv.Reader(ENTRY, opentlv.Format.BER))
    amount = codec.decode_amount(bytes(entry.value))
    print(f"tag {entry.tag}: amount = {amount}")
    assert amount == 12345

    assert codec.encode_amount(amount) == bytes(entry.value)

    try:
        codec.decode_amount(b"\x00\x00\x01")  # wrong length for format n12
    except codec.CodecError as error:
        print(f"rejected: {error}")


if __name__ == "__main__":
    main()
