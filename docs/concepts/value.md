# Borrowed TLV values

Include `tlv/value.h` (also available through `tlv/tlv.h`) for `tlv_value_t`,
a read-only, non-owning TLV value, and its checked construction and
validation. See [logical TLV value lengths](length.md) for the `tlv_length_t`
type it uses, and [core types](core-types.md) for how it fits into
`tlv_view_t`.

```c
typedef struct {
    const uint8_t* data;
    tlv_length_t length;
} tlv_value_t;
```

The caller owns the storage `data` points into and must keep it alive; no
allocation, copying, or ownership transfer occurs. `data` may be NULL only
when `length` is zero. `length` may exceed what the current build's `size_t`
can address; validate with `tlv_length_validate_native()` or convert with
`tlv_length_to_size()` before pointer arithmetic, memory access, or narrowing.

| Function | Purpose |
| --- | --- |
| `tlv_value_init(data, length, &value)` | Checked construction into caller-owned storage. |
| `tlv_value_validate(&value)` | Checked validation of an existing `tlv_value_t`. |

```c
#include "tlv/value.h"

uint8_t storage[] = {0x12, 0x34, 0x56};
tlv_value_t value;
if (tlv_value_init(storage + 1, 2, &value) == TLV_OK) {
    /* value.data == storage + 1, value.length == 2 */
}
```

`tlv_value_init()` requires `value` and, unless `length` is zero, `data`;
missing either returns `TLV_ERR_NULL_ARG`, checked before the native-length
range. A `length` that cannot be represented by the current build's `size_t`
returns `TLV_ERR_INVALID_LENGTH`. `*value` is unchanged on every failure.
Actual allocation bounds for `data` remain the caller's responsibility; no
memory is accessed.

`tlv_value_validate()` checks the same representation and pointer
requirements on an existing `tlv_value_t`: `data` non-NULL unless `length` is
zero, and `length` representable by the current build's `size_t`. It does not
access memory and does not prove sufficient allocation bounds -- a `value`
describing a range longer than its actual backing storage still validates.
A NULL `value` returns `TLV_ERR_NULL_ARG`.

## Relationship to `tlv_view_t`

`tlv_view_t.value` is a `tlv_value_t`:

```c
typedef struct {
    tlv_tag_t tag;
    tlv_value_t value;
} tlv_view_t;
```

Readers construct `view.value` directly (its fields, not through
`tlv_value_init()`) after validating a decoded length against the input
buffer, so an internal reader-produced view is always representation-valid.
`tlv_value_init()`/`tlv_value_validate()` exist for consumers building or
checking a `tlv_view_t` by hand, for example in tests or custom format
integrations. There is no separate native byte-range struct in the public
API: a native `const uint8_t*`/`size_t` pair is passed directly where one is
needed, for example in `tlv_copy_encoded()`.

See also the [C API reference: core types](../reference/c-api.md#core-types-and-utilities).
