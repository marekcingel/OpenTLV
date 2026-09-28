# DHCPv4 option framing

Include `tlv/builtins/dhcp/dhcpv4.h` and select `tlv_format_dhcpv4`.
C++ callers can include `tlv++/builtins/dhcp/dhcpv4.hpp` and use
`tlv::dhcpv4_format()` with the existing Reader and Writer wrappers.
The independent CMake option `OPENTLV_DHCP` defaults to `ON`;
`tlv_config_dhcp()` reports the compiled library's availability.

The descriptor implements the option framing in
[RFC 2132 sections 2, 3.1 and 3.2](https://www.rfc-editor.org/rfc/rfc2132.html#section-2):

| Code | Wire representation | Logical Value size |
| --- | --- | --- |
| 1..254 | Code, Length, Value | 0..255 bytes |
| 0 (Pad) | Code only | 0 |
| 255 (End) | Code only | 0 |

For example, `35 01 01` decodes to identifier byte `35` and Value byte `01`.
`00` and `FF` each decode to one element with an empty Value. `FE 00` is a
normal empty option and retains an explicit Length field.

## Element and source contracts

The canonical `tlv_element_t` contains a borrowed Tag and Value;
`element.value.size` is the logical Value byte count. No DHCP-specific state
is added. The descriptor and its configuration have static lifetime, while
the caller owns the input and must keep it alive and immutable while views
or source records are retained. No operation allocates or copies on decode.

For normal options, Header covers two bytes, Tag is `(0, 1)`, Length is
`(1, 1)`, and Value starts at offset 2. For Pad/End, Header and Tag cover
`(0, 1)`, Length is absent, and Value and Trailer are present empty ranges
at offset 1. Offsets are relative to the individual element.

Measurement accepts Value sizes without accessing Value bytes. Encoding
rejects identifiers with widths other than one, normal Values larger than
255 bytes and nonempty Pad/End Values. Decoding rejects incomplete Length
and Value fields. `tlv_source_preserve()` copies the original representation
only when the supplied element remains semantically unchanged.

## Scope and composition

Pass only the option region, excluding the DHCP packet header and magic
cookie. Reader returns Pad and End as ordinary elements. The caller decides
when to stop at End; Reader can continue through the remaining supplied bytes.
The format does not require End or validate padding after it.

Values stay opaque. This feature does not validate individual option semantics,
join RFC 3396 fragments, process option overload, recurse into suboptions,
or implement DHCPv6 framing. Other language binding presets are not added.

The implementation configures `tlv_tagged_binary_layout_t` with two tag-only
identifiers, `00` and `FF`. The generic primitive selects by byte identity and
delegates all other elements to the existing binary TLV layout. Its table can
use different identifiers and widths; no core Reader/Writer logic knows DHCP.
The table, its identifier bytes and the layout are borrowed immutable storage
when applications initialize their own descriptors with
`tlv_tagged_binary_format_init()`.

See the [compiled C example](../../../examples/tlv/src/dhcpv4.c) for reading
options, writing them back and applying caller-controlled End handling.
