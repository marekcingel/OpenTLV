"""Wire formats shared by `Reader` and `Writer`."""

from __future__ import annotations

import enum


class Format(enum.IntEnum):
    """The wire format a `Reader` or `Writer` uses.

    Values match the format IDs `opentlv_native` expects; do not renumber
    them.
    """

    DEFAULT = 0
    """One-byte tag and a definite BER length."""

    BER = 1
    """BER-TLV."""

    CER = 2
    """Canonical Encoding Rules."""

    DER = 3
    """Distinguished Encoding Rules."""

    FIXED_1BYTE = 4
    """One-byte tag and one-byte length."""
