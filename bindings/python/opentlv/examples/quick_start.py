# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel

"""The simplest possible round trip: write one element with the
configurable fixed-width format, then read it back. See parse.py and
write.py for a nested BER document, and the C `quick_start.c`, C++
`quick_start.cpp` and Rust `quick_start.rs` examples for the same round
trip in those languages.

Run with `python examples/quick_start.py` from `bindings/python/opentlv`,
after installing both packages (see ../../../README.md or
docs/development/python.md).
"""

import opentlv


def main() -> None:
    # One tag byte and one length byte.
    format = opentlv.FixedFormat(1, 1)
    tag = opentlv.Tag(b"\x01")
    value = b"\xaa\xbb\xcc"

    writer = opentlv.Writer(format)
    writer.write(tag, value)
    encoded = writer.bytes()
    print(f"wrote {len(encoded)} bytes: {encoded.hex(' ').upper()}")

    reader = opentlv.Reader(encoded, format)
    (element,) = list(reader)
    assert element.tag == tag
    assert bytes(element.value) == value
    print(f"read tag {element.tag} value {bytes(element.value).hex(' ').upper()}")


if __name__ == "__main__":
    main()
