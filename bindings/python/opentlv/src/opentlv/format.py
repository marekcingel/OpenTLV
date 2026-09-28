"""Wire formats shared by `Reader` and `Writer`."""

from __future__ import annotations

import enum
import opentlv_native


class Format(enum.IntEnum):
    """The wire format a `Reader` or `Writer` uses.

    Values match the format IDs `opentlv_native` expects; do not renumber
    them.
    """

    if opentlv_native.HAS_BER:
        BER = 1
        """BER-TLV."""

    if opentlv_native.HAS_CER:
        CER = 2
        """Canonical Encoding Rules."""

    if opentlv_native.HAS_DER:
        DER = 3
        """Distinguished Encoding Rules."""

    if opentlv_native.HAS_LLDP:
        LLDP = 4
        """LLDP packed header framing, without LLDPDU semantic validation."""


def _resolve_format(format):
    """Use BER by default, or require an explicit format when unavailable."""
    if format is not None:
        return format
    if opentlv_native.HAS_BER:
        return Format.BER
    raise ValueError("format is required when BER is disabled")
