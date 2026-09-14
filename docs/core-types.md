# C core types

Include `<tlv/types.h>` for format-independent types and the common
`tlv_result_t` error codes from `<tlv/error.h>`. Tags and their configuration
are declared in `<tlv/tag.h>`, which can also be included directly.

- `tlv_buffer_t` is a read-only, non-owning range (`data`, `length`). A null
  pointer is valid only for an empty range.
- `tlv_tag_t` stores raw tag bytes in wire order and their actual `size`.
  It performs no integer conversion or profile-specific validation.
- `tlv_view_t` stores a tag inline and a borrowed `value` buffer. The caller
  must keep the value storage alive while using the view. Copying the view
  copies the tag and pointer, not the value bytes.

All types support zero initialization and require no dynamic allocation.
An empty tag has size zero; individual formats decide whether it is valid.

Define `TLV_TAG_MAX_SIZE` at compile time to change the default capacity of
8 bytes, for example with the compiler option `-DTLV_TAG_MAX_SIZE=16`
(`/DTLV_TAG_MAX_SIZE=16` with MSVC). The allowed range is 1–255 because the
actual size is stored in a `uint8_t`. Use the same definition in the library
and every consumer: changing capacity changes the layout and ABI of tags and
views. This is a preprocessor setting, not a CMake cache option.

The reader returns `tlv_view_t`: it copies the tag into inline storage and
borrows the value directly from the input buffer. The writer accepts
`tlv_tag_t`, and the C++ layer uses the same type for tags and codec keys.
Tag and length restrictions depend on the selected format; the default format
uses one tag byte, while BER and DER support multi-byte tags.
See [memory ownership and lifetime](memory.md) for shared buffer rules.

## Tag comparison and numeric conversion

All `tlv_tag_equal*` functions return `int`: 1 for equality, 0 for mismatch
or invalid input. Null required pointers and sizes above capacity return 0.

`tlv_tag_equal(a, b)` compares the size and valid bytes, ignoring unused
storage. Two empty tags compare equal. It supports the full configured capacity,
including tags longer than 8 bytes.

`tlv_tag_equal_bytes(tag, data, size)` compares a tag against an array
without constructing another `tlv_tag_t`. Length and leading zeros are
significant. `data` may be null only when `size` is zero; otherwise the caller
must provide `size` readable bytes. Sizes above `TLV_TAG_MAX_SIZE` are invalid.

```c
const uint8_t expected[] = {0x82};
if (tlv_tag_equal_bytes(tag, expected, sizeof(expected))) {
    /* The length and bytes match exactly. */
}
```

`tlv_tag_to_u64(tag, order, &value)` interprets 1 to 8 bytes using the explicit
`tlv_byte_order_t` from `<tlv/endian.h>`. With `TLV_BYTE_ORDER_BIG_ENDIAN`,
`9F 02` becomes `0x9F02`; with `TLV_BYTE_ORDER_LITTLE_ENDIAN`, it becomes
`0x029F`. It does not decode the ASN.1 tag number.
Null arguments return `TLV_ERR_NULL_ARG`; empty tags, sizes exceeding capacity,
and tags longer than 8 bytes return `TLV_ERR_INVALID_TAG`. The output stays
unchanged on failure, including for long tags with zero padding. Unknown or
invalid byte order returns `TLV_ERR_INVALID_ARG`.

`tlv_tag_to_u8`, `tlv_tag_to_u16`, and `tlv_tag_to_u32` provide checked
conversions into `uint8_t`, `uint16_t`, and `uint32_t`. They use the same input
rules as `tlv_tag_to_u64` and return `TLV_ERR_INVALID_TAG` if the numeric value
exceeds the destination type's maximum, leaving the output unchanged.
Zero padding at the most significant end is accepted within the 8-byte input
limit: big-endian `00 FF` and little-endian `FF 00` both fit in `uint8_t`.

`tlv_tag_equal_u8`, `tlv_tag_equal_u16`, `tlv_tag_equal_u32`, and
`tlv_tag_equal_u64` compare against a value of the corresponding unsigned type.
Their final argument is the explicit input byte order, e.g.
`tlv_tag_equal_u16(tag, 0x9F02, TLV_BYTE_ORDER_BIG_ENDIAN)`.
They use `tlv_tag_to_u64` and return 0 if conversion fails or values differ.
The tag value is never truncated to the argument type.
With big-endian input, leading zeros do not affect numeric equality: `00 82` and `82` both equal
`0x82` numerically, but differ under exact comparison. All helpers are
allocation-free and available in C and C++.

`tlv_endian_native()` reports the executing platform's byte order (or
`TLV_BYTE_ORDER_UNKNOWN` for mixed byte order). Pass it explicitly only when
the input represents a native integer's storage. Protocol byte order remains
independent of the host. Raw tag and byte-array comparisons do not take a byte
order and still compare exact bytes and length.

## Constructing tags

`tlv_tag_from_bytes(data, size, &tag)` copies up to `TLV_TAG_MAX_SIZE` bytes.
Zero size creates an empty tag and permits null `data`. Source and destination
may overlap. Excessive size returns `TLV_ERR_INVALID_TAG`; missing required
pointers return `TLV_ERR_NULL_ARG`.

`tlv_tag_from_u8/u16/u32/u64(value, size, order, &tag)` encodes an unsigned
value into exactly `size` bytes (1..8, within capacity). Size is explicit:
`0x82` can become `82`, big-endian `00 82`, or little-endian `82 00`.
A size too small for the value returns `TLV_ERR_INVALID_TAG`, as does an invalid
size. Unsupported byte order returns `TLV_ERR_INVALID_ARG`.

All constructors leave the destination unchanged on failure and zero unused
storage on success. They allocate no memory and do not validate BER or EMV rules.

```c
tlv_tag_t tag;
if (tlv_tag_from_u16(0x9F02, 2, TLV_BYTE_ORDER_BIG_ENDIAN, &tag) == TLV_OK) {
    /* tag contains the exact bytes 9F 02. */
}
```
