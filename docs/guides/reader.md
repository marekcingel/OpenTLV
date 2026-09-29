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
| `TLV_ERR_END_OF_BUFFER` | Final input has been consumed | Unchanged |
| `TLV_NEED_MORE_DATA` | Non-final input is exhausted or incomplete | Unchanged |
| `TLV_ERR_BUFFER_TOO_SHORT` | Final input contains an incomplete element | Unchanged |
| Any other result | Specific parsing or argument error | Unchanged |

The single-element `tlv_read()` primitive retains its complete-buffer behavior;
only a non-final Reader maps input shortage to `TLV_NEED_MORE_DATA`. Custom Format decoders must distinguish incomplete input from
malformed wire data. Reader does not infer that distinction from tag or length
bytes. Repeated calls with unchanged input and cursor state produce the same
outcome; Reader never skips a failing element or searches for another boundary.

`tlv_reader_init()` treats the supplied buffer as complete and final, preserving
its existing behavior. `tlv_reader_init_incremental()` starts an open input:
empty or incomplete input yields `TLV_NEED_MORE_DATA`, and `at_end()` stays false.
Malformed data returns its specific error immediately, even before EOF.

## Incremental input windows

`tlv_reader_set_input(reader, data, size, discard, final_input)` supplies the
next contiguous window. `discard` removes only a consumed prefix of the old
window; use `tlv_reader_consumed()` to determine how much has been consumed.
The new window must preserve the entire remaining old prefix byte-for-byte,
then may append new bytes. Reader validates sizes and state, but does not compare
prefix contents or access the old buffer. The caller may relocate that buffer
before supplying the new pointer, provided no old borrowed view is still used.

Set `final_input` to 1 to declare EOF. Repeating an incomplete read then reports
`TLV_ERR_BUFFER_TOO_SHORT`; fully consumed final input reports
`TLV_ERR_END_OF_BUFFER`. EOF cannot be reopened or extended without
reinitializing Reader. Discarding consumed bytes or rebinding the same final
extent is still permitted. A rejected update leaves Reader unchanged.

Reader consumes only complete elements. A failed or incomplete decode consumes
zero additional bytes and retains no partial parser storage. The next attempt
retries Format decoding at the same element start. This is resumable parsing,
not a guarantee of constant work per appended byte; a Format may rescan the
retained prefix, including indefinite constructed contents.

The whole stream need not be resident, but the next complete encoded element
must be contiguous before it can be returned. This includes the full contents
and trailer of a constructed element. A ring-buffer element crossing the wrap
must be made contiguous by the caller. No hidden copying or I/O occurs.

Moving or overwriting storage invalidates every borrowed element, source and
diagnostic referring to it. Updating Reader does not redirect old views to new
storage. Release such views before compacting or reusing their bytes; retaining
an old view is safe if its original backing storage remains alive and unchanged.

See the compiled [incremental Reader example](../../examples/tlv/src/incremental_reader.c):
it processes a six-byte input using four bytes of caller-owned sliding storage.

## Source and diagnostics

`tlv_reader_consumed()` (also `reader.pos`) is the consumed prefix size within
the current window. `tlv_reader_offset()` is the absolute logical stream
position: `reader.base_offset + reader.pos`. Discarding a consumed prefix
advances the base and reduces the local position by the same amount. Offsets
use the existing `size_t` domain; any window update exceeding `SIZE_MAX` returns
`TLV_ERR_OVERFLOW`, including on 32-bit hosts.
`tlv_reader_next_diag()` reports structured errors with absolute offsets within
the logical stream across window replacements, including known field positions,
declared length and available bytes. `has_required`/`required` describe the
required size of the failing region when Format knows it; it is not a total
stream size or an additional byte count. Unknown extents remain unset.
Need-more-data diagnostics have informational severity. A successful call
leaves the diagnostic unchanged.

Use `tlv_reader_next_source_diag()` to obtain an element and `tlv_source_t`
from the same decode. Source ranges remain relative to `source.data`, the
element start. Capture `tlv_reader_offset()` before the call to locate that source in
the logical stream. Non-success leaves both success outputs unchanged.

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
