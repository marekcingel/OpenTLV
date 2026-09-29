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

## Pull-based tree traversal

`tlv_tree_reader_t` is the canonical iterative preorder traversal cursor. Include
`tlv/reader/tree.h`, provide an array of `tlv_tree_frame_t`, and initialize with
`tlv_tree_reader_init()` or `tlv_tree_reader_init_incremental()`. Each successful
`tlv_tree_reader_next()` returns a `tlv_tree_item_t` containing the complete
borrowed Element, Source, depth, absolute element-start offset, and Format's
constructed classification. Root depth is zero. Only Format interprets framing
and identifies constructed values; a missing classification callback makes all
values opaque.

The stream has **no separate ENTER or LEAVE events**. Each element appears once,
before its children. A decrease in the next item's depth closes prior scopes;
final end closes the remaining scopes. Empty constructed values still appear
once. Higher layers that need exit notifications can derive them from depth
transitions and final end. `NEED_MORE_DATA` is not an end event.

### Storage and limits

`TLV_TREE_DEFAULT_DEPTH` is a suggested default of 64, not a hard maximum.
The caller supplies both a runtime `max_depth` and a frame array with explicit
capacity. Each entered nonempty constructed value needs one frame; the root
sequence needs none. Capacity and depth are independent bounds. A larger array
and runtime limit allow deeper traversal without recompiling OpenTLV. Formats
may have their own framing limits, such as BER indefinite-length nesting.

Frames hold only absolute value-end and sibling-resume offsets. They do not
retain Elements, Tags, Sources, or pointers into the input. Frames must remain
writable and alive throughout traversal and must not overlap input or the
cursor. Copying a cursor does not copy its frame array; independent traversals
need independent structural storage. The caller may release or overwrite a
returned item object immediately; this does not alter traversal state.

`max_elements` bounds the total number of published items, including parents.
Zero permits only empty input. Depth or storage exhaustion returns
`TLV_ERR_LIMIT` when attempting to descend, after the parent has been returned.
Errors and `NEED_MORE_DATA` preserve the cursor, frames, and item output.
`tlv_tree_reader_next_diag()` retains Reader diagnostics and absolute offsets
without decoding again. Tree argument/resource errors leave the diagnostic
unchanged.

### Skipping and incremental input

After receiving a nonempty constructed item, call
`tlv_tree_reader_skip_subtree()` to continue after its complete encoded extent.
The skipped descendants are neither decoded nor counted. The same operation is
available after a failed descent while that subtree remains pending. Calling it
without a pending subtree returns `TLV_ERR_INVALID_ARG`. Skipping does not
validate descendants; Format may already have inspected their framing while
establishing the complete parent's extent. Closing enclosing scopes uses an
iterative loop bounded by the active depth.

Tree input updates follow the sequential Reader contract:
`tlv_tree_reader_set_input()` preserves the unconsumed prefix and accepts an
explicit final-input flag. Use `tlv_tree_reader_consumed()` to find the prefix
no longer needed by traversal, and `tlv_tree_reader_offset()` for its absolute
frontier. After publishing a parent, its unvisited value remains unconsumed.
You can relocate the retained bytes even while nested: frames use absolute
logical offsets. Release any borrowed results referring to moved or overwritten
storage first, including parents whose Values cover those bytes.

The complete-element contract from incremental Reader still applies. **An
incomplete child delays publication of its enclosing constructed parent.**
Tree Reader cannot return a complete borrowed parent and then wait for bytes
inside that parent's Value. Once published, that parent bounds child reads as
final input; a child exceeding the bound returns `TLV_ERR_BUFFER_TOO_SHORT`,
not `TLV_NEED_MORE_DATA`. More bytes outside the parent cannot repair it.
Incremental traversal resumes across complete subtrees and incomplete subsequent
roots, without requiring the entire stream in memory. It does not provide an
early-header stream or partial Elements.

See the compiled [Tree Reader example](../../examples/tlv/src/tree_reader.c)
for caller-owned frames, incomplete input, subtree skipping, window replacement,
and EOF.

### Walker compatibility

`tlv_walk_tree()` and `tlv_walk_tree_diag()` now adapt the canonical Tree Reader
to existing callbacks; they contain no independent traversal algorithm.
`tlv_walk()` remains a callback adapter over sequential Reader. The compatibility
Walker owns a fixed stack of `TLV_WALK_MAX_DEPTH` frames. That name describes
only the adapter's capacity: use Tree Reader directly for runtime depths beyond
it, caller-owned traversal storage, incremental input, or subtree skipping.
Existing Query and other Walker consumers therefore use Tree Reader through
the adapter. Their own public limits and higher-level APIs remain unchanged.

## Ownership and composition

Input storage belongs to the caller and must stay alive and unchanged while
borrowed results are retained. Tag may instead borrow immutable Format-supplied
storage, which must also outlive retained results. Reader borrows Format and its
context; retained sources also require them. Advancing, reinitializing or
discarding the cursor does not by itself invalidate previously returned elements.
See [memory ownership](memory.md).

Tree Reader composes Reader for nested traversal; Walker is a callback adapter.
Query uses that traversal and Document uses Reader for sequential parsing. These higher layers
retain their own traversal, storage and validation responsibilities.

## Migration from Scanner

The public Scanner API, `tlv_scan()` and `tlv/reader/scanner.h`, has been removed
in #391. Applications needing resynchronization choose candidate offsets and
call `tlv_read()` themselves. Candidate acceptance and recovery policy belong
to the application. The CLI retains its `--recover` behavior through such a
local policy.
