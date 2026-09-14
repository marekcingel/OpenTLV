# Logical TLV value lengths

Include `tlv/length.h` (also available through `tlv/tlv.h`) for `tlv_length_t`,
a fixed 64-bit unsigned logical TLV value length, and its checked conversions
to and from the current build's native `size_t`.

```c
typedef uint64_t tlv_length_t;
```

`tlv_length_t` always has the same 64-bit unsigned numeric range, independent
of build configuration, the current build's `size_t` width, or wire format.
It may hold a value that cannot be used as an in-memory buffer length in the
current build; use the conversions below before native-size use.

| Function | Purpose |
| --- | --- |
| `tlv_length_from_size(size, &length)` | Convert a native `size_t` into `tlv_length_t`. |
| `tlv_length_to_size(length, &size)` | Convert a `tlv_length_t` into the current build's `size_t`. |
| `tlv_length_validate_native(length)` | Check whether `length` fits `size_t`, without converting it. |

```c
#include "tlv/length.h"

size_t native = sizeof(some_buffer);
tlv_length_t length;
tlv_length_from_size(native, &length); /* always succeeds */

size_t size;
if (tlv_length_to_size(length, &size) == TLV_OK) {
    /* size is now safe to use for pointer arithmetic or allocation sizing. */
}
```

`tlv_length_from_size()` is lossless and cannot fail for its numeric domain:
every `size_t` value fits `tlv_length_t`. Its only failure is a NULL `length`
output pointer, which returns `TLV_ERR_NULL_ARG`.

`tlv_length_to_size()` rejects a `length` greater than `SIZE_MAX` in the
current build with `TLV_ERR_INVALID_LENGTH`, leaving `*size` unchanged. A NULL
`size` output pointer returns `TLV_ERR_NULL_ARG`, checked before the range
comparison. Passing this conversion does not prove that a buffer of that size
exists, is accessible, or has sufficient capacity; actual bounds remain the
caller's responsibility.

`tlv_length_validate_native()` reports the same range check as
`tlv_length_to_size()`, without an output parameter and without accessing any
memory: `TLV_OK` when `length` fits `size_t`, `TLV_ERR_INVALID_LENGTH`
otherwise.

## x86 and x64

The *numeric range* of `tlv_length_t` is identical on every platform, but
`size_t` is narrower on a 32-bit build. `UINT32_MAX + 1` is a real,
representable `tlv_length_t` value everywhere, yet `tlv_length_to_size()` and
`tlv_length_validate_native()` reject it on an x86 build (where it exceeds
`SIZE_MAX`) and accept it on an x64 build. `UINT64_MAX` itself is accepted on
x64 without attempting any allocation or memory access, since it equals
`SIZE_MAX` there.

Readers ([`tlv_read()`](../tlv/include/tlv/reader/reader.h) and its callers)
decode using native `size_t` internally -- format callbacks are unchanged --
and convert the final length to `tlv_length_t` with `tlv_length_from_size()`
before returning a [`tlv_view_t`](value.md). That conversion cannot fail.
Consumers that need a native `size_t` back out of `view.value.length`, for
pointer arithmetic, memory access, or a call into an API that still takes
`size_t`, must convert first with `tlv_length_to_size()` and handle the
failure case, rather than narrowing implicitly. See
[borrowed TLV values](value.md) and [core types](core-types.md) for how
`tlv_value_t` and `tlv_view_t` use `tlv_length_t`.
