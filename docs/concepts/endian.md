# Integer byte-order conversions

Include `tlv/endian.h` (also available through `tlv/tlv.h`) to convert raw
value bytes to and from native unsigned integers. The helpers are independent
of TLV framing and profiles; the caller chooses the byte order explicitly.

| Integer | Big-endian | Little-endian |
| --- | --- | --- |
| Read 16-bit | `tlv_read_u16_be(data)` | `tlv_read_u16_le(data)` |
| Read 32-bit | `tlv_read_u32_be(data)` | `tlv_read_u32_le(data)` |
| Read 64-bit | `tlv_read_u64_be(data)` | `tlv_read_u64_le(data)` |
| Write 64-bit | `tlv_write_u64_be(data, value)` | `tlv_write_u64_le(data, value)` |
| Write 16-bit | `tlv_write_u16_be(data, value)` | `tlv_write_u16_le(data, value)` |
| Write 32-bit | `tlv_write_u32_be(data, value)` | `tlv_write_u32_le(data, value)` |

Reads return `uint16_t`, `uint32_t`, or `uint64_t`; writes return `void`. Supply a non-null
pointer to at least 2, 4, or 8 readable/writable bytes respectively. When reading
a `tlv_view_t`, check `view.value.length` before passing `view.value.data`; convert
it with `tlv_length_to_size()` (see [logical TLV value lengths](length.md)) first if
you need a native `size_t` bound.
These helpers do not validate pointers or lengths and require no alignment.

```c
#include "tlv/endian.h"

uint8_t bytes[sizeof(uint32_t)];
tlv_write_u32_be(bytes, UINT32_C(0x12345678)); /* 12 34 56 78 */
uint32_t value = tlv_read_u32_be(bytes);     /* 0x12345678 */
tlv_write_u32_le(bytes, value);             /* 78 56 34 12 */
```

All operations access individual bytes and use integer shifts, so their
results are identical on big-endian and little-endian hosts.

## Checked variable-width integers

`tlv_read_uint(data, width, order, &value)` reads into a `uint64_t`.
`tlv_write_uint(data, width, order, value)` writes a `uint64_t` using exactly
`width` bytes. Widths 1 through 8 are supported, including 3, 5, 6, and 7.
Choose `TLV_BYTE_ORDER_BIG_ENDIAN` or `TLV_BYTE_ORDER_LITTLE_ENDIAN` explicitly.

Both return `TLV_OK` on success. Validation checks required pointers first
(`TLV_ERR_NULL_ARG`), then width (`TLV_ERR_INVALID_LENGTH`), then byte order
(`TLV_ERR_INVALID_BYTE_ORDER`, including `TLV_BYTE_ORDER_UNKNOWN`). Writes
also return `TLV_ERR_OVERFLOW` for values that do not fit; they never truncate. All failures leave outputs
unchanged. Reads accept zero padding and finish reading before storing the
result. Writes pad with zero bytes at the most significant end.

The caller must supply `width` accessible bytes and, for reads, a writable
`uint64_t` output object. The helpers cannot check allocation bounds. Byte
buffers may be unaligned. Operations allocate no memory and access only the
specified bytes, independently of host byte order.

```c
uint8_t bytes[3];
uint64_t value;
if (tlv_write_uint(bytes, 3, TLV_BYTE_ORDER_BIG_ENDIAN, 0x1234) == TLV_OK) {
    /* bytes are 00 12 34 */
    tlv_read_uint(bytes, 3, TLV_BYTE_ORDER_BIG_ENDIAN, &value);
}
```

Tag capacity, protocol bounds, framing, canonical encodings, and public error
mapping remain the calling module's responsibility. BER accepts padded length
payloads longer than eight bytes when the decoded length fits `size_t`;
the BER module validates excess padding before using these helpers. DER
continues to apply its stricter canonical length rules.

See also the [C API reference: core types](../reference/c-api.md#core-types-and-utilities).
