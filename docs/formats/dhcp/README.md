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

## Option definitions

Include `tlv/builtins/dhcp/options.h` to use `tlv_dhcpv4_options` with the
generic Definition API:

```c
const tlv_definition_t* definition =
    tlv_definition_find(&tlv_dhcpv4_options, &element.tag);
```

For `35 01 03`, the decoded Tag is `35`, Value is `03`, and the definition's
name is `"DHCP Message Type"`. For `E0 02 AA BB`, decoding still succeeds with
opaque Value `AA BB`; lookup returns `NULL` because Code `E0` is not listed.

The initial registry covers Pad, Subnet Mask, Router, Domain Name Server,
Host Name, Domain Name, Requested IP Address, IP Address Lease Time,
DHCP Message Type, Server Identifier, Parameter Request List, Maximum DHCP
Message Size, Renewal Time Value, Rebinding Time Value, Vendor Class Identifier,
Client Identifier and End, as defined in [RFC 2132](https://www.rfc-editor.org/rfc/rfc2132.html).
It is not an exhaustive option registry.

The registry requires `OPENTLV_DHCP=ON`. Entries, identifier bytes and names
have static lifetime; lookup allocates nothing and needs no Reader or Writer.
Definitions only describe identifiers: they do not decode Values, validate
option lengths or control Pad/End handling. Framing does not consult the registry.

## Value codecs

Include `tlv/builtins/dhcp/codec.h` for the DHCP Message Type codec and
`tlv/codec/values.h` for fundamental integer and byte representations.
Include `tlv/codec/ipv4.h` for IPv4 addresses and address lists:

| Value | Codec | C representation |
| --- | --- | --- |
| IPv4 address (for example options 1, 50, 54) | `tlv_codec_ipv4` | `tlv_ipv4_t`, four network-order octets |
| IPv4 list (3, 6) | `tlv_codec_ipv4_list` | `tlv_ipv4_list_t`, borrowed bytes |
| Unsigned byte | `tlv_codec_uint8` | `uint8_t` |
| Unsigned 16-bit integer (57) | `tlv_codec_uint16_be` | `uint16_t` |
| Unsigned 32-bit integer (51, 58, 59) | `tlv_codec_uint32_be` | `uint32_t` |
| DHCP Message Type (53) | `tlv_dhcpv4_codec_message_type` | `uint8_t` |
| Parameter Request List (55), opaque identifiers (60, 61) | `tlv_codec_bytes` | borrowed `tlv_value_t` |

For `35 01 03`, Reader exposes raw Value `03`. Decode that Value with
`tlv_dhcpv4_codec_message_type` to obtain `TLV_DHCPV4_REQUEST`.
Use a `uint8_t` object, not an enum object, for this codec. Constants name
the eight RFC 2132 message types; all other byte values are preserved too.
The codec does not validate DHCP exchange state or require a known type.

All codecs support decode, encode and validated encode size queries through
`tlv_codec_decode()` and `tlv_codec_encode()`. Convert
`element.value.size` with `tlv_size_to_native()` before passing it to a codec.
For size queries, pass a NULL destination and zero capacity. Invalid
representations fail even when no bytes are requested; errors report zero
bytes written.

Byte sequences and IPv4 lists borrow input storage, which must remain alive
and immutable. Encoding preserves all bytes, including order and duplicates.
Use `tlv_ipv4_list_at()` for checked address access without allocation.
An IPv4 list must contain a multiple of four bytes. Generic lists and byte
sequences permit empty values and impose no DHCP length limits. Option-specific
constraints (such as a nonempty Router list) require separate validation.
Parameter Request Lists preserve unknown option Codes. Opaque identifiers
are retained whole, without interpreting hardware types or vendor payloads.

Generic codecs are available with `OPENTLV_DHCP=OFF`; only the DHCP Message
Type descriptor requires DHCP support. Codec selection is explicit and does
not change Format or Definition behavior.

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
