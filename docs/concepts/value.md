# Borrowed TLV values

Include `tlv/value.h` (also available through `tlv/tlv.h`) for `tlv_value_t`,
a read-only, non-owning TLV value, and its checked construction and
validation. See [logical TLV value lengths](length.md) for the `tlv_size_t`
type it uses, and [core types](core-types.md) for how it fits into
`tlv_element_t`.

```c
typedef struct {
    const uint8_t* data;
    tlv_size_t size;
} tlv_value_t;
```

The caller owns the storage `data` points into and must keep it alive; no
allocation, copying, or ownership transfer occurs. `data` may be NULL only
when `size` is zero. `size` may exceed what the current build's `size_t`
can address; validate with `tlv_size_validate_native()` or convert with
`tlv_size_to_native()` before pointer arithmetic, memory access, or narrowing.

| Function | Purpose |
| --- | --- |
| `tlv_value_init(data, length, &value)` | Checked construction into caller-owned storage. |
| `tlv_value_validate(&value)` | Checked validation of an existing `tlv_value_t`. |
| `tlv_value_equal(lhs, rhs)` | Content equality; two empty values are equal. |
| `tlv_value_compare(lhs, rhs)` | Lexicographic ordering by bytes, like `tlv_tag_compare()`. |
| `tlv_value_is_empty(value)` | Whether `value.size` is zero. |
| `tlv_value_slice(value, offset, length, &out)` | A borrowed sub-view, without copying. |
| `tlv_value_copy(value, data, capacity, &written)` | Checked copy into caller-owned storage. |

```c
#include "tlv/value.h"

uint8_t storage[] = {0x12, 0x34, 0x56};
tlv_value_t value;
if (tlv_value_init(storage + 1, 2, &value) == TLV_OK) {
    /* value.data == storage + 1, value.size == 2 */
}
```

`tlv_value_init()` requires `value` and, unless `length` is zero, `data`;
missing either returns `TLV_ERR_NULL_ARG`, checked before the native-length
range. A `length` that cannot be represented by the current build's `size_t`
returns `TLV_ERR_NATIVE_SIZE`. `*value` is unchanged on every failure.
Actual allocation bounds for `data` remain the caller's responsibility; no
memory is accessed.

`tlv_value_validate()` checks the same representation and pointer
requirements on an existing `tlv_value_t`: `data` non-NULL unless `size` is
zero, and `size` representable by the current build's `size_t`. It does not
access memory and does not prove sufficient allocation bounds -- a `value`
describing a range longer than its actual backing storage still validates.
A NULL `value` returns `TLV_ERR_NULL_ARG`.

## Comparing, slicing and copying values

`tlv_value_equal(lhs, rhs)` and `tlv_value_compare(lhs, rhs)` compare values by
their bytes, not by pointer identity, exactly like `tlv_tag_equal()` and
`tlv_tag_compare()` do for tags: `tlv_value_equal(a, b)` is true exactly when
`tlv_value_compare(a, b) == 0`. Both require valid values (`tlv_value_validate()`
returns `TLV_OK`); an invalid value is a contract violation, not a comparable
one. `tlv_value_is_empty(value)` is a plain `value.size == 0` check and
imposes no such precondition.

```c
tlv_value_t part;
if (tlv_value_slice(value, 1, 3, &part) == TLV_OK) {
    /* part borrows value.data + 1, part.size == 3 */
}
```

`tlv_value_slice(value, offset, length, &out)` builds a borrowed sub-view
without copying; `offset + length` must not exceed `value.size`, checked
with overflow-safe `tlv_size_t` arithmetic (`TLV_ERR_OVERFLOW` if the sum
itself overflows, `TLV_ERR_INVALID_LENGTH` if it fits but exceeds
`value.size`). `tlv_value_copy(value, data, capacity, &written)` instead
copies the bytes into caller-owned storage, with the same
query-size-with-`NULL`, `TLV_ERR_BUFFER_TOO_SHORT` and overlap-safe
conventions as `tlv_copy_encoded()`; `tlv_copy_value()` is defined in terms of
it.

## Relationship to `tlv_element_t`

`tlv_element_t.value` is a `tlv_value_t`:

```c
typedef struct {
    tlv_tag_t tag;
    tlv_value_t value;
} tlv_element_t;
```

`element.tag` is a borrowed `tlv_tag_t`: like the value, it points into the input
the view was read from and must not outlive it.

Formats construct `element.value` directly (its fields, not through
`tlv_value_init()`) after validating a decoded length against the input
buffer, so an internal reader-produced view is always representation-valid.
`tlv_value_init()`/`tlv_value_validate()` exist for consumers building or
checking a `tlv_element_t` by hand, for example in tests or custom format
integrations. Native buffers are passed as `const uint8_t*`/`size_t` pairs,
for example in `tlv_copy_encoded()`. Source framing uses buffer-relative
`tlv_range_t` fields separately from semantic Value.

See also the [C API reference: core types](../reference/c-api.md#core-types-and-utilities).
