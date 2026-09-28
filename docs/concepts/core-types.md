# C core types

Include `<tlv/element.h>` for `tlv_element_t`, `<tlv/value.h>` for `tlv_value_t`, and
`<tlv/size.h>` for `tlv_size_t`, or `<tlv/tlv.h>` to pull in all of them
along with the rest of the public API. The common `tlv_result_t` error codes
come from `<tlv/error.h>`. Tags and their configuration are declared in
`<tlv/tag.h>`, which can also be included directly.

- `tlv_size_t` is a fixed 64-bit unsigned logical TLV value length, with
  the same numeric range on every platform regardless of the current build's
  `size_t` width. See [logical TLV value lengths](length.md) for its checked
  conversions and the x86/x64 divergence in what fits `size_t`.
- `tlv_value_t` is a read-only, non-owning value (`data`, `size` as
  `tlv_size_t`). A null `data` pointer is valid only when `size` is zero.
  See [borrowed TLV values](value.md) for checked construction and
  validation.
- Native buffers use a `const uint8_t*`/`size_t` pair. Source fields use
  optional buffer-relative `tlv_range_t` offsets and extents.
- `tlv_tag_t` is a small non-owning type: a `const uint8_t* data` pointer and
  a `size_t size`. It represents arbitrary raw tag bytes in wire order and
  nothing else. It owns no memory, allocates none, has no storage capacity or
  maximum length, and carries no format-specific metadata.
- `tlv_length_t` (in `<tlv/length.h>`) borrows the original encoded length
  field through `const uint8_t* data` and native `size_t size`. It preserves
  nonminimal encodings and termination markers without numeric interpretation.
- `tlv_element_t` (in `<tlv/element.h>`) has exactly two fields: `tag` and
  `value`. All bytes are borrowed. `value.size` is the resolved
  logical value byte count (`tlv_size_t`), excluding header and trailer framing.
  The format defines how the raw length maps to this count: Bluetooth's length
  also counts the tag, while BER indefinite length has no numeric wire count.
  Copying an element copies descriptors only. The source must remain alive
  and unchanged while any copy is used.

```c
typedef uint64_t tlv_size_t;
typedef struct { const uint8_t* data; size_t size; } tlv_tag_t;
typedef struct { const uint8_t* data; size_t size; } tlv_length_t;
typedef struct { const uint8_t* data; tlv_size_t size; } tlv_value_t;
typedef struct {
    tlv_tag_t tag;
    tlv_value_t value;
} tlv_element_t;
```

The logical quantities and raw bytes are independent of host endianness.
Pointer-containing structures have native layouts and must never be used as
portable wire encodings. `tlv_copy_element()` regenerates the length for the
destination format; `tlv_copy_encoded()` preserves an original encoded range.

Raw fields and complete framing belong to separate `tlv_source_t`, returned
with the semantic element by `tlv_format_decode()`. See the
[Format/Element contract](format-contract.md) for mutation and preservation.

All types support zero initialization and require no dynamic allocation.

## Tags are borrowed

`tlv_tag_t` refers to bytes that somebody else owns, exactly as `tlv_value_t`
does for values:

- Copying a `tlv_tag_t` copies the pointer and the size, not the bytes.
- The referenced bytes must stay valid, and unchanged, for as long as the tag
  is used.
- OpenTLV functions never retain a tag past the call unless their
  documentation says so.
- `{ NULL, 0 }` is the empty tag. `{ NULL, size }` with `size > 0` is invalid.
- Reader-produced tags normally reference the input buffer that was parsed, so
  reading stays zero-copy. A tag stays valid only as long as that buffer does.

```c
static const uint8_t bytes[] = {0x9F, 0x02};
tlv_tag_t tag = tlv_tag(bytes, sizeof(bytes));   /* borrows `bytes` */
tlv_tag_t same = TLV_TAG(0x9F, 0x02);            /* literal bytes, no allocation */
```

`tlv_tag(data, size)` builds a tag from runtime data and checks nothing.
`TLV_TAG(0x9F, 0x02)` builds a tag from constant bytes without allocating. In
C++ the bytes have static storage duration, so the tag can be stored and
returned freely. In C it is a compound literal that lives until the end of its
enclosing block, so do not return it from a function. `TLV_TAG()` is not a
constant expression; for a static table in C, declare a `static const uint8_t`
array and initialize the tag as `{ bytes, sizeof(bytes) }`.

Several layers are involved, and each has its own job:

| Layer | What it decides |
| ----- | --------------- |
| `tlv_tag_t` | Nothing: it is arbitrary raw bytes with a length. |
| A **format** | How tags are encoded and which tag lengths are valid. BER and DER accept 1 to 8 bytes, and a format defined at runtime can accept 12. A tag a format does not support is rejected by that format, for example with `TLV_ERR_INVALID_TAG_SIZE`. Whether an empty tag is valid is also the format's decision. |
| A **schema** | Which tags are allowed or required and how long their values may be. |

A `tlv_tag_t` of any length can be created, compared, stored in a schema and
passed to a format; only a format rejects lengths it does not support.

There is no `TLV_TAG_CAPACITY` and no `TLV_TAG_MAX_SUPPORTED_SIZE`. The layout
of `tlv_tag_t` no longer depends on a compile-time setting, so the library and
its consumers, including other languages' bindings, never have to be rebuilt to
agree on it, and tests for different tag lengths run in a single build.

The reader returns `tlv_element_t` with Value borrowed from the input buffer.
Tag borrows either input or immutable format-supplied identifier storage under
the [decoded identifier contract](format-contract.md#decoded-identifier-consistency).
The writer accepts `tlv_tag_t` by value and only reads it during the
call, and the C++ layer uses the same type for tags. A codec registry, or any
container that has to keep a tag, must copy the bytes.
See [memory ownership and lifetime](../guides/memory.md) for shared buffer rules.

## Tag comparison

Comparison is by contents, never by pointer identity, so tags backed by
different memory compare as equal when their bytes match.

`bool tlv_tag_equal(lhs, rhs)` is true when both tags have the same size and
bytes. Two empty tags are equal, whatever their pointers. Both functions require valid tags (see
below): an invalid tag is a contract violation, not a comparable value.

`int tlv_tag_compare(lhs, rhs)` orders tags lexicographically by their bytes,
comparing them as unsigned values. If one tag is a prefix of the other, the
shorter one orders first. It returns a negative value, zero or a positive value.
The bytes are never read as an integer, so the result does not depend on the
host's byte order: `01 FF` orders before `02 00`, and `01 00 00` orders before
`02`. `tlv_tag_equal(a, b)` is true exactly when `tlv_tag_compare(a, b) == 0`.
Validate input at the API boundary; the comparison itself does no checking.

```c
if (tlv_tag_equal(element.tag, TLV_TAG(0x9F, 0x02))) {
    /* The same bytes, wherever they are stored. */
}
```

A tag is identity, not a number: `tlv_tag_t` has no integer conversion and no
byte order. To compare against a known tag, compare its wire bytes with
`TLV_TAG(0x9F, 0x02)` rather than an integer. A format or profile that needs a
numeric view of its own tags, such as the ASN.1 tag number of
`tlv_der_tag_number()`, provides it in its own layer.

## Other tag operations

`tlv_tag_is_empty(tag)` tests whether `tag.size` is zero.

`tlv_tag_hash(tag)` hashes a tag's bytes for use as a key in a caller-provided
hash table; two tags for which `tlv_tag_equal()` is true always hash equal.
The hash is not a wire encoding and may differ across builds, platforms and
OpenTLV versions, so never persist it or send it to another process.

`tlv_tag_copy(tag, data, capacity, &written)` copies a tag's bytes into
caller-owned storage, following the same query-size-with-`NULL`,
`TLV_ERR_BUFFER_TOO_SHORT` and overlap-safe conventions as `tlv_copy_encoded()`
(see [memory ownership and lifetime](../guides/memory.md)); there is no
generic `TLV_TAG_MAX_SIZE`, since `tlv_tag_t` imposes no maximum length --
size the destination from a prior `tlv_tag_copy(tag, NULL, 0, &written)`
query, or from a format's own tag-size limit such as `TLV_ASN1_TAG_MAX_SIZE`.

## Constructing tags

Use `tlv_tag(data, size)` or `TLV_TAG(...)` to describe bytes you already have;
no copy is made. Constructors of a format, such as `tlv_der_tag_make()`, write
the bytes into caller-provided storage and return a tag that borrows it, so the
storage must outlive the tag. They allocate no memory.

## Tag errors

`TLV_ERR_INVALID_TAG_SIZE` identifies a tag length a format does not support; it
is never produced because a tag is "too long for `tlv_tag_t`".
`TLV_ERR_INVALID_TAG` identifies malformed tag encoding.

See also the [C API reference: core types](../reference/c-api.md#core-types-and-utilities).

### C++ element access

`tlv::element` aliases semantic `tlv_element_t` with 64-bit `value.size`.
`tlv::decode()` returns separate source information for raw field inspection. Access bytes through `element.value.data`. When a C++
codec or range operation needs `tlv::bytes`, use the checked conversion:

```cpp
auto value = tlv::as_bytes(element.value);
if (!value) return; // Null data with nonzero size, or size above SIZE_MAX.
// *value is a borrowed tlv::bytes span; keep the source storage alive.
```
