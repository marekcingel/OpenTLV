# Packed Tag/Length configuration

`tlv/formats/packed.h` supplies a generic definite Format for unsigned Tag and
Length fields sharing a 1–8-byte header. It is always built, independently of
LLDP and other protocol options. Reader, Writer, Document and Query consume its
ordinary `tlv_format_t` descriptor.

```c
#include <tlv/formats/packed.h>

static const uint8_t tags[16] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
};
static const tlv_packed_layout_t layout = {
    2,
    {2, 12, 4, TLV_BYTE_ORDER_BIG_ENDIAN},
    {2, 0, 12, TLV_BYTE_ORDER_BIG_ENDIAN},
    TLV_LENGTH_SCOPE_VALUE,
    tags, 1, sizeof(tags)
};
static const tlv_format_t format = {
    &layout, tlv_packed_decode, tlv_packed_measure, tlv_packed_encode, NULL
};
```

This configuration decodes `B0 03 07 08 09` as canonical Tag `0B` and Value
`07 08 09`. The [executable tests](../../tests/unit/formats/packed_test.cpp)
cover this vector, little-endian storage, all header widths, multi-byte Tags,
length scopes, truncated inputs and invalid configurations.

## Configuration and lifetime

Both fields must use `header_size` backing bytes and the same explicit byte
order. Offsets count from the least significant bit of that integer. Field bits
must not overlap; byte envelopes may overlap. Unused bits are ignored on decode
and set to zero on encode. Exact unchanged-source preservation remains available
through `tlv_source_preserve()`.

`tag_storage` holds every canonical identifier in numeric order. Entry `i` is
the unsigned big-endian encoding of `i` in exactly `tag_size` bytes, independent
of header byte order. Leading zero bytes are allowed. `tag_size` is at least
`ceil(tag.bit_width / 8)` and at most eight. `tag_storage_size` supplies the
available byte capacity; the required size is `2^tag.bit_width * tag_size`.
Wide Tag fields therefore require exponentially large tables. Unrepresentable
table sizes are rejected without shifting or multiplying past native limits.

Call `tlv_packed_layout_validate()` to check configuration and capacity. It does
not scan the table. The caller must populate every canonical entry; decode
rejects an incorrect selected entry. Callbacks also validate the layout.

The library never allocates table storage. Configuration and table must remain
immutable and alive for every operation and retained decoded Tag, including
shallow copies. Value bytes borrow input. Tags use `TLV_TAG_BINDING_FORMAT`.
Encoding uses Tag bytes rather than pointer identity, so owned Document Tags
and independently copied canonical identifiers work normally.

## Length and source ranges

`TLV_LENGTH_SCOPE_VALUE` counts Value bytes. `TLV_LENGTH_SCOPE_TAG_AND_VALUE`
counts Value bytes plus the **wire Tag byte envelope**: the number of header
bytes touched by the Tag bits. A byte shared with Length is counted once in
that envelope. This is unrelated to the canonical `tag_size`.

For a nine-bit Tag at bit offset seven, its envelope is two bytes. A count of
two therefore denotes an empty Value under Tag-plus-Value scope, even if a
wider canonical identifier representation is configured. Counts below the
envelope size are invalid.

Header covers the complete backing integer. Tag and Length source ranges are
their minimal byte envelopes, adjusted for byte order; Value begins immediately
after Header and Trailer is empty. Measurement rejects Tags and scoped counts
outside their field widths. Decode bounds-checks Value before native narrowing.

## Protocol and binding scope

[LLDP](lldp/README.md) is a two-byte big-endian configuration with seven-bit
Type, nine-bit Value length and a static 128-byte identifier table. Its existing
presets, diagnostics and source ranges are preserved. Constructed classification
and protocol validation remain separate from packed framing; declarative field
policies are described in the
[policy design note](../concepts/field-policies.md) for #542.

Existing LLDP language presets continue to use `tlv_format_lldp`. General
packed configuration is currently C API functionality, available in C++ through
explicit native Format interop. Idiomatic configuration constructors in the
language facades remain a tracked coverage gap in the
[support matrix](support.md#language-framing-presets).
