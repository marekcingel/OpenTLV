# Integer byte-order conversions

Include `tlv/endian.h` (also available through `tlv/tlv.h`) to convert raw
value bytes to and from native unsigned integers. The helpers are independent
of TLV framing and profiles; the caller chooses the byte order explicitly.

| Integer | Big-endian | Little-endian |
| --- | --- | --- |
| Read 16-bit | `tlv_read_u16_be(data)` | `tlv_read_u16_le(data)` |
| Read 32-bit | `tlv_read_u32_be(data)` | `tlv_read_u32_le(data)` |
| Write 16-bit | `tlv_write_u16_be(data, value)` | `tlv_write_u16_le(data, value)` |
| Write 32-bit | `tlv_write_u32_be(data, value)` | `tlv_write_u32_le(data, value)` |

Reads return `uint16_t` or `uint32_t`; writes return `void`. Supply a non-null
pointer to at least 2 or 4 readable/writable bytes respectively. When reading
a `tlv_view_t`, check `view.value.length` before passing `view.value.data`.
These helpers do not validate pointers or lengths and require no alignment.

```c
#include "tlv/endian.h"

uint8_t bytes[4];
tlv_write_u32_be(bytes, UINT32_C(0x12345678)); /* 12 34 56 78 */
uint32_t value = tlv_read_u32_be(bytes);     /* 0x12345678 */
tlv_write_u32_le(bytes, value);             /* 78 56 34 12 */
```

All operations access individual bytes and use integer shifts, so their
results are identical on big-endian and little-endian hosts.
