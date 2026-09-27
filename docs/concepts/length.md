# Logical TLV value lengths

Include `tlv/size.h` (also available through `tlv/tlv.h`) for `tlv_size_t`,
a fixed 64-bit unsigned logical TLV value length, and its checked conversions
to and from the current build's native `size_t`.

```c
typedef uint64_t tlv_size_t;
```

`tlv_size_t` always has the same 64-bit unsigned numeric range, independent
of build configuration, the current build's `size_t` width, or wire format.
It may hold a value that cannot be used as an in-memory buffer length in the
current build; use the conversions below before native-size use.

| Function | Purpose |
| --- | --- |
| `tlv_size_from_native(size, &length)` | Convert a native `size_t` into `tlv_size_t`. |
| `tlv_size_to_native(length, &size)` | Convert a `tlv_size_t` into the current build's `size_t`. |
| `tlv_size_validate_native(length)` | Check whether `length` fits `size_t`, without converting it. |
| `tlv_size_add(a, b, &sum)` | Add two lengths, detecting `tlv_size_t` overflow. |

```c
#include "tlv/size.h"

size_t native = sizeof(some_buffer);
tlv_size_t length;
tlv_size_from_native(native, &length); /* always succeeds */

size_t size;
if (tlv_size_to_native(length, &size) == TLV_OK) {
    /* size is now safe to use for pointer arithmetic or allocation sizing. */
}
```

`tlv_size_from_native()` is lossless and cannot fail for its numeric domain:
every `size_t` value fits `tlv_size_t`. Its only failure is a NULL `length`
output pointer, which returns `TLV_ERR_NULL_ARG`.

`tlv_size_to_native()` rejects a `length` greater than `SIZE_MAX` in the
current build with `TLV_ERR_INVALID_LENGTH`, leaving `*size` unchanged. A NULL
`size` output pointer returns `TLV_ERR_NULL_ARG`, checked before the range
comparison. Passing this conversion does not prove that a buffer of that size
exists, is accessible, or has sufficient capacity; actual bounds remain the
caller's responsibility.

`tlv_size_validate_native()` reports the same range check as
`tlv_size_to_native()`, without an output parameter and without accessing any
memory: `TLV_OK` when `length` fits `size_t`, `TLV_ERR_INVALID_LENGTH`
otherwise.

`TLV_SIZE_MAX` is `UINT64_MAX`, the largest value a `tlv_size_t` can hold;
it is distinct from `SIZE_MAX`, which bounds `tlv_size_to_native()` instead.
`tlv_size_add(a, b, &sum)` adds two lengths and returns `TLV_ERR_OVERFLOW`
if `a + b` would exceed `TLV_SIZE_MAX`, for composing lengths (such as a
header length and a value length) before a native-size conversion, without
risking silent `tlv_size_t` wraparound.

## x86 and x64

The *numeric range* of `tlv_size_t` is identical on every platform, but
`size_t` is narrower on a 32-bit build. `UINT32_MAX + 1` is a real,
representable `tlv_size_t` value everywhere, yet `tlv_size_to_native()` and
`tlv_size_validate_native()` reject it on an x86 build (where it exceeds
`SIZE_MAX`) and accept it on an x64 build. `UINT64_MAX` itself is accepted on
x64 without attempting any allocation or memory access, since it equals
`SIZE_MAX` there.

Raw length-field bytes are represented separately by `tlv_length_t`
(`data`, native `size`) in `<tlv/length.h>`. They preserve the original wire
representation; they are not the decoded value size.

Readers and format callbacks decode logical value sizes into `tlv_size_t`.
The reader checks the decoded count against the available input before any
native narrowing or pointer arithmetic, then publishes `element.value.size`.
A count larger than the supplied buffer returns `TLV_ERR_BUFFER_TOO_SHORT`
without modifying the output element or consumed count.
Consumers that need a native `size_t` back out of `element.value.size`, for
pointer arithmetic, memory access, or a call into an API that still takes
`size_t`, must convert first with `tlv_size_to_native()` and handle the
failure case, rather than narrowing implicitly. See
[borrowed TLV values](value.md) and [core types](core-types.md) for how
`tlv_value_t` and `tlv_element_t` use `tlv_size_t`.

See also the [C API reference: core types](../reference/c-api.md#core-types-and-utilities).
