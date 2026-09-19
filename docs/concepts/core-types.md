# C core types

Include `<tlv/view.h>` for `tlv_view_t`, `<tlv/value.h>` for `tlv_value_t`, and
`<tlv/length.h>` for `tlv_length_t`, or `<tlv/tlv.h>` to pull in all of them
along with the rest of the public API. The common `tlv_result_t` error codes
come from `<tlv/error.h>`. Tags and their configuration are declared in
`<tlv/tag.h>`, which can also be included directly.

- `tlv_length_t` is a fixed 64-bit unsigned logical TLV value length, with
  the same numeric range on every platform regardless of the current build's
  `size_t` width. See [logical TLV value lengths](length.md) for its checked
  conversions and the x86/x64 divergence in what fits `size_t`.
- `tlv_value_t` is a read-only, non-owning value (`data`, `length` as
  `tlv_length_t`). A null `data` pointer is valid only when `length` is zero.
  See [borrowed TLV values](value.md) for checked construction and
  validation.
- There is no separate native byte-range struct. Native byte ranges in the
  public API are passed as an explicit `const uint8_t*`/`size_t` pair, for
  example `tlv_copy_encoded(encoded_data, encoded_length, ...)`.
- `tlv_tag_t` stores raw tag bytes in wire order and their actual `size`.
  It performs no integer conversion or profile-specific validation.
- `tlv_view_t` (in `<tlv/view.h>`) stores a tag inline and a borrowed
  `tlv_value_t` value. The caller must keep the value storage alive while
  using the view. Copying the view copies the tag and the value's pointer
  and length, not the value bytes. `tlv_view_t`/`tlv_value_t` are plain
  structs containing a pointer; unlike `tlv_length_t`'s numeric range, their
  in-memory layout is **not** guaranteed to match across architectures, and
  must never be treated as a portable wire encoding.

All types support zero initialization and require no dynamic allocation.
An empty tag has size zero; individual formats decide whether it is valid.

`TLV_TAG_MAX_SUPPORTED_SIZE` is the fixed representation limit `UINT8_MAX`
(255), imposed by the `uint8_t size` field. It is not configurable and is not
a protocol limit. `TLV_TAG_CAPACITY` is the compile-time inline storage
capacity (default 8); `tag.size` is the current number of valid bytes (0 through
capacity). Empty tags are valid for raw construction and comparison; numeric
conversion and TLV I/O require nonempty tags.

Define `TLV_TAG_CAPACITY` at compile time, for example `-DTLV_TAG_CAPACITY=16`
(`/DTLV_TAG_CAPACITY=16` with MSVC). The allowed range is 1 through
`TLV_TAG_MAX_SUPPORTED_SIZE`; configurations outside it fail preprocessing.
Use the same capacity in the library and every C/C++ consumer: capacity affects
structure layout and ABI. Rebuild both when changing it. This is a preprocessor
setting, not a CMake cache option.

Migrate existing `TLV_TAG_MAX_SIZE` definitions to `TLV_TAG_CAPACITY`.
The old name is no longer supported or provided as an alias. Only
`TLV_TAG_CAPACITY` configures storage; leaving it undefined selects 8.
Equal capacities retain the existing structure layout.

Direct assignment to the public `size` field can truncate values outside the
`uint8_t` range before the library can validate them (for example, 256 becomes
zero). Use construction helpers with `size_t` lengths for checked input. These
validate the length before narrowing, including lengths 256 and 257 at capacity 255.

The reader returns `tlv_view_t`: it copies the tag into inline storage and
borrows the value directly from the input buffer. The writer accepts
`tlv_tag_t`, and the C++ layer uses the same type for tags and codec keys.
Tag and length restrictions depend on the selected format; the default format
uses one tag byte, while BER and DER support multi-byte tags.
See [memory ownership and lifetime](../guides/memory.md) for shared buffer rules.

## Tag comparison and numeric conversion

All `tlv_tag_equal*` functions return `tlv_result_t` and take a final `int* equal`
output argument. A valid comparison returns `TLV_OK` and stores 1 for equality
or 0 for mismatch. Mismatch is not an error. Null required pointers return
`TLV_ERR_NULL_ARG`; sizes above capacity return `TLV_ERR_INVALID_TAG_SIZE`.
The output remains unchanged on every failure. Supply a writable `int`.

When migrating from the predicate API, add `&equal` and check the returned
status before using `equal`; do not use the status itself as a boolean match.

`tlv_tag_equal(a, b, &equal)` compares the size and valid bytes, ignoring unused
storage. Two empty tags compare equal. It supports the full configured capacity,
including tags longer than 8 bytes.

`tlv_tag_equal_bytes(tag, data, size, &equal)` compares a tag against an array
without constructing another `tlv_tag_t`. Length and leading zeros are
significant. `data` may be null only when `size` is zero; otherwise the caller
must provide `size` readable bytes. Sizes above `TLV_TAG_CAPACITY` are invalid.

```c
const uint8_t expected[] = {0x82};
int equal;
if (tlv_tag_equal_bytes(tag, expected, sizeof(expected), &equal) == TLV_OK && equal) {
    /* The length and bytes match exactly. */
}
```

`tlv_tag_to_u64(tag, order, &value)` interprets 1 to 8 bytes using the explicit
`tlv_byte_order_t` from `<tlv/endian.h>`. With `TLV_BYTE_ORDER_BIG_ENDIAN`,
`9F 02` becomes `0x9F02`; with `TLV_BYTE_ORDER_LITTLE_ENDIAN`, it becomes
`0x029F`. It does not decode the ASN.1 tag number.
Null arguments return `TLV_ERR_NULL_ARG`; empty tags, sizes exceeding capacity,
and tags longer than 8 bytes return `TLV_ERR_INVALID_TAG_SIZE`. The output stays
unchanged on failure, including for long tags with zero padding. Unknown or
invalid byte order returns `TLV_ERR_INVALID_BYTE_ORDER`.

`tlv_tag_to_u8`, `tlv_tag_to_u16`, and `tlv_tag_to_u32` provide checked
conversions into `uint8_t`, `uint16_t`, and `uint32_t`. They use the same input
rules as `tlv_tag_to_u64` and return `TLV_ERR_OVERFLOW` if the numeric value
exceeds the destination type's maximum, leaving the output unchanged.
Zero padding at the most significant end is accepted within the 8-byte input
limit: big-endian `00 FF` and little-endian `FF 00` both fit in `uint8_t`.

`tlv_tag_equal_u8`, `tlv_tag_equal_u16`, `tlv_tag_equal_u32`, and
`tlv_tag_equal_u64` compare against a value of the corresponding unsigned type.
Pass the explicit input byte order before the output argument, e.g.
`tlv_tag_equal_u16(tag, 0x9F02, TLV_BYTE_ORDER_BIG_ENDIAN, &equal)`.
They use `tlv_tag_to_u64` and propagate its errors, including
`TLV_ERR_INVALID_BYTE_ORDER`. Required pointers are validated before tag size,
then byte order. Valid unequal values return `TLV_OK` with `*equal == 0`.
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

`tlv_tag_from_bytes(data, size, &tag)` copies up to `TLV_TAG_CAPACITY` bytes.
Zero size creates an empty tag and permits null `data`. Source and destination
may overlap. Excessive size returns `TLV_ERR_INVALID_TAG_SIZE`; missing required
pointers return `TLV_ERR_NULL_ARG`.

`tlv_tag_from_u8/u16/u32/u64(value, size, order, &tag)` encodes an unsigned
value into exactly `size` bytes (1..8, within capacity). Size is explicit:
`0x82` can become `82`, big-endian `00 82`, or little-endian `82 00`.
A value that does not fit the requested size returns `TLV_ERR_OVERFLOW`;
zero size, size above capacity, or size above 8 returns `TLV_ERR_INVALID_TAG_SIZE`. Unsupported byte order returns `TLV_ERR_INVALID_BYTE_ORDER`.

All constructors leave the destination unchanged on failure and zero unused
storage on success. They allocate no memory and do not validate BER or EMV rules.

```c
tlv_tag_t tag;
if (tlv_tag_from_u16(0x9F02, 2, TLV_BYTE_ORDER_BIG_ENDIAN, &tag) == TLV_OK) {
    /* tag contains the exact bytes 9F 02. */
}
```

## Tag errors

`TLV_ERR_INVALID_TAG_SIZE` identifies sizes unsupported by an operation.
`TLV_ERR_OVERFLOW` identifies an otherwise valid numeric value or input that
does not fit the requested destination type or encoded width.
`TLV_ERR_INVALID_TAG` identifies malformed tag encoding. Size failures
previously returning `TLV_ERR_INVALID_TAG` now return `TLV_ERR_INVALID_TAG_SIZE`,
and numeric range failures previously returning `TLV_ERR_INVALID_TAG` now return
`TLV_ERR_OVERFLOW`; update callers that check specific errors. `TLV_ERR_INVALID_LENGTH`
remains a value-length error, and invalid schema definitions retain schema-specific
errors. Comparison helpers still return 0 for invalid inputs. Existing error-code
numeric values are unchanged.

See also the [C API reference: core types](../reference/c-api.md#core-types-and-utilities).
