# Explicit TLV copies

Include `tlv/copy.h` to copy data into storage owned by the caller. These
helpers never allocate memory. The normal reader still returns a zero-copy
view: copying is a separate, explicit operation.

- `tlv_copy_value()` copies just a view's value bytes.
- `tlv_copy_view()` serializes a complete element using a selected format.
- `tlv_copy_encoded()` copies an exact byte range, including the original
  header. Pass the original input pointer and the consumed length from a
  successful read, or input plus the offset returned by a scan. This helper
  does not validate framing; the caller determines the range.

All three accept `NULL, 0` as the destination to query the required size.
For an actual copy, pass a non-NULL destination and its capacity in bytes.
On success, the final argument receives the required size or bytes written.
On failure it remains unchanged. Insufficient capacity returns
`TLV_ERR_BUFFER_TOO_SHORT` and leaves destination bytes unchanged.

```c
#include "tlv/copy.h"
#include "tlv/reader.h"

uint8_t input[] = {1, 2, 0xAB, 0xCD};
uint8_t storage[16];
tlv_view_t view;
size_t consumed, required, written;
tlv_result_t result = tlv_read(input, sizeof(input), &tlv_format_fixed_1byte,
                               &view, &consumed);
if (result == TLV_OK) {
    result = tlv_copy_value(&view, NULL, 0, &required);
    if (result == TLV_OK && required <= sizeof(storage)) {
        result = tlv_copy_value(&view, storage, sizeof(storage), &written);
        if (result == TLV_OK) {
            /* Retain the inline tag and point the view at the owned copy. */
            view.value.data = storage;
            view.value.length = written;
            /* input may now be reused; storage must outlive view. */
        }
    }
}
```

A view does not retain the original encoded header. Serializing it can change
the wire representation, for example by shortening a nonminimal BER length.
Use `tlv_copy_encoded()` when byte-for-byte preservation matters.

Value and encoded-range copies support overlapping byte ranges. View
serialization follows `tlv_write()` and requires a nonoverlapping source
value and destination; format callback errors may partially modify the
destination. Output size pointers and source descriptors must not overlap
destination storage, and size pointers must not alias source storage.
