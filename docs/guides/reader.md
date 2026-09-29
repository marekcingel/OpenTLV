# Pull-based Reader

`tlv_reader_t` is the canonical allocation-free cursor over caller-owned bytes.
The caller requests one element at a time and decides how to process or retain
it. Format alone interprets wire representation. Reader performs no I/O,
buffering, recovery, schema validation or semantic Value decoding.

```c
#include "tlv/formats/fixed.h"
#include "tlv/reader/reader.h"

const tlv_fixed_format_t config = {
    .tag_size = 1, .length_size = 1, .length_order = TLV_BYTE_ORDER_BIG_ENDIAN};
tlv_format_t format;
tlv_reader_t reader;
const uint8_t data[] = {1, 1, 0xAB, 2, 0};
tlv_result_t rc = tlv_fixed_format_init(&format, &config);
if (rc != TLV_OK) return 1;
rc = tlv_reader_init(&reader, data, sizeof(data), &format);
if (rc != TLV_OK) return 1;

for (;;) {
    tlv_element_t element;
    rc = tlv_reader_next(&reader, &element);
    if (rc == TLV_OK) {
        /* Process or retain the borrowed element here. */
        continue;
    }
    if (rc == TLV_ERR_END_OF_BUFFER) break;
    if (rc == TLV_ERR_BUFFER_TOO_SHORT) {
        /* Incomplete input at reader.pos; the caller owns further input. */
        return 1;
    }
    /* A parsing or argument error; reader.pos has not advanced. */
    return 1;
}
```

## Outcomes and state

| Result | Meaning | Cursor and element output |
| --- | --- | --- |
| `TLV_OK` | One complete element is available | Publish element; advance by its full encoded size, including any trailer |
| `TLV_ERR_END_OF_BUFFER` | All supplied bytes have been consumed | Unchanged |
| `TLV_ERR_BUFFER_TOO_SHORT` | Format requires more bytes at this position | Unchanged |
| Any other result | Specific parsing or argument error | Unchanged |

These are the same result codes exposed by the single-element `tlv_read()`
primitive. Custom Format decoders must distinguish incomplete input from
malformed wire data. Reader does not infer that distinction from tag or length
bytes. Repeated calls with unchanged input and cursor state produce the same
outcome; Reader never skips a failing element or searches for another boundary.

End means the end of the supplied buffer, not an I/O end-of-stream event.
An empty buffer is immediately at end. Incomplete input at a known final
boundary is truncation that the caller must handle. This foundation does not
provide a feed, buffering or incremental transport API. Reinitialization resets
the cursor to position zero without taking ownership of input.

## Source and diagnostics

`reader.pos` is the byte offset of the next element within `reader.data`.
`tlv_reader_next_diag()` reports structured errors with absolute offsets within
that buffer, including any known field positions, declared length and available
bytes. A successful call leaves the diagnostic unchanged.

Use `tlv_reader_next_source_diag()` to obtain an element and `tlv_source_t`
from the same decode. Source ranges remain relative to `source.data`, the
element start. Capture `reader.pos` before the call to locate that source in
the original buffer. Non-success leaves both success outputs unchanged.

## Ownership and composition

Input storage belongs to the caller and must stay alive and unchanged while
borrowed results are retained. Tag may instead borrow immutable Format-supplied
storage, which must also outlive retained results. Reader borrows Format and its
context; retained sources also require them. Advancing, reinitializing or
discarding the cursor does not by itself invalidate previously returned elements.
See [memory ownership](memory.md).

Walker composes Reader for sequential and tree traversal. Query uses that
traversal and Document uses Reader for sequential parsing. These higher layers
retain their own traversal, storage and validation responsibilities.

## Migration from Scanner

The public Scanner API, `tlv_scan()` and `tlv/reader/scanner.h`, has been removed
in #391. Applications needing resynchronization choose candidate offsets and
call `tlv_read()` themselves. Candidate acceptance and recovery policy belong
to the application. The CLI retains its `--recover` behavior through such a
local policy.
