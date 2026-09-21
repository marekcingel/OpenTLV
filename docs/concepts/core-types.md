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
- `tlv_tag_t` is a small non-owning type: a `const uint8_t* data` pointer and
  a `size_t size`. It represents arbitrary raw tag bytes in wire order and
  nothing else. It owns no memory, allocates none, has no storage capacity or
  maximum length, and carries no format-specific metadata.
- `tlv_view_t` (in `<tlv/view.h>`) holds a borrowed `tlv_tag_t` and a
  borrowed `tlv_value_t` value. The caller must keep the storage of both alive
  while using the view; for a reader-produced view that is the input buffer.
  Copying the view copies only the tag's and value's pointers and lengths, not
  any bytes. `tlv_view_t`/`tlv_value_t` are plain structs containing pointers;
  unlike `tlv_length_t`'s numeric range, their in-memory layout is **not**
  guaranteed to match across architectures, and must never be treated as a
  portable wire encoding.

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
| A **format** | How tags are encoded and which tag lengths are valid. The default format accepts one byte, BER and DER accept 1 to 8 bytes, and a format defined at runtime can accept 12. A tag a format does not support is rejected by that format, for example with `TLV_ERR_INVALID_TAG_SIZE`. Whether an empty tag is valid is also the format's decision. |
| A **schema** | Which tags are allowed or required and how long their values may be. |

A `tlv_tag_t` of any length can be created, compared, stored in a schema and
passed to a format; only a format rejects lengths it does not support.

There is no `TLV_TAG_CAPACITY` and no `TLV_TAG_MAX_SUPPORTED_SIZE`. The layout
of `tlv_tag_t` no longer depends on a compile-time setting, so the library and
its consumers, including other languages' bindings, never have to be rebuilt to
agree on it, and tests for different tag lengths run in a single build.

The reader returns `tlv_view_t` with the tag and value borrowed from the input
buffer. The writer accepts `tlv_tag_t` by value and only reads it during the
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
if (tlv_tag_equal(view.tag, TLV_TAG(0x9F, 0x02))) {
    /* The same bytes, wherever they are stored. */
}
```

A tag is identity, not a number: `tlv_tag_t` has no integer conversion and no
byte order. To compare against a known tag, compare its wire bytes with
`TLV_TAG(0x9F, 0x02)` rather than an integer. A format or profile that needs a
numeric view of its own tags, such as the ASN.1 tag number of
`tlv_der_tag_number()`, provides it in its own layer.

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
