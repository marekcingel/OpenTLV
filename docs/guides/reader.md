# Pull-based Reader

Prerequisite: Complete the [quick start](../getting-started/README.md#quick-start) first.

```text
input --Reader + Format--> one borrowed Element at a time
```

See [Choose a processing API](processing.md) for ownership, nesting, resumable
input, construction and editing choices.

`tlv_reader_t` is the canonical allocation-free cursor over caller-owned bytes.
The caller requests one element at a time and decides how to process or retain
it. Format alone interprets wire representation. Reader performs no I/O,
buffering, recovery, schema validation or semantic Value decoding.

```c
#include "tlv/formats/fixed.h"
#include "tlv/reader/reader.h"

const tlv_fixed_format_t config = {.identifier = {1}, .length = {1, TLV_BYTE_ORDER_BIG_ENDIAN}};
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

## C++ iteration and parsing ranges

`tlv::reader<F>` is a C++11 single-pass input range over the canonical C Reader.
It yields `tlv::element_view`, borrowing Tag and Value bytes without allocating
or copying Value contents on successful reads. Iteration is flat: constructed
Values remain opaque. Use Tree Reader for nested traversal.

```cpp
#include "tlv++/tlv.hpp"

tlv::reader<tlv::ber::format> reader(data); // data is a borrowed tlv::bytes
for (auto element : reader) {
    process(element.tag(), element.value());
}

for (auto element : tlv::ber::parse(data)) {
    process(element.tag(), element.value());
}
```

The generic helpers are `tlv::parse<F>(data)` for default configuration and
`tlv::parse(data, format)` for an explicit C++ Format, borrowed `tlv::format`
view or native descriptor. Built-in namespaces provide `ber::parse`,
`der::parse`, `cer::parse`, `bluetooth::parse`, `dhcp::parse`, `emv::parse`,
`lldp::parse` and `nfc::parse` under `tlv`, when their components are enabled.
They select framing only; Schema, container policy and Value codecs remain
explicit. For example, NFC NULL and Terminator are yielded as ordinary Elements.
The existing `tlv::ber` namespace precludes a function named `tlv::ber(data)`.

`begin()` reads and consumes one element from the current cursor position;
`++` reads the next. Dereferencing does not parse again. Calling `begin()`
again continues rather than restarting. A `break` leaves the published element
consumed; explicit `next()` then reads the following element. `end()` does not
parse. Only one traversal may be active per cursor. Advancing an iterator
invalidates other copies, except that `*it++` exposes the previous borrowed
Element. Explicit `next()`, `next_source()`, `visit()`, successful `set_input()`,
and cursor destruction invalidate active iterators. Retained Element copies
remain usable while their original backing storage remains alive and unchanged.

Only genuine final EOF ends iteration. Initialization errors, malformed or
truncated data, and `TLV_NEED_MORE_DATA` throw `tlv::parse_error` from `begin()`
or increment. The failing element is not consumed; a successful prefix remains
consumed. Even a custom decoder returning `TLV_ERR_END_OF_BUFFER` inside
nonempty input produces an exception.

```cpp
try {
    for (auto element : tlv::ber::parse(data)) {
        process(element.tag(), element.value());
    }
} catch (const tlv::parse_error& failure) {
    report(failure.code(), failure.offset(), failure.diagnostic());
}
```

`code()` preserves the C result. `offset()` identifies the unconsumed element's
absolute start; `diagnostic()` preserves the C diagnostic, whose field offset
may differ. Diagnostic byte views remain borrowed, and constructing an exception
may allocate. Applications needing result-based control or incremental input
should keep using `next()`, `next_source()` and `set_input()`. An incremental
Reader can be iterated, but exhaustion requests more data through an exception,
even at an element boundary. After supplying input, start a new iteration.

Parsing helpers treat input as final and return an internal range that owns its
C++ Format configuration inline. The range supports move construction in C++11
without relying on copy elision; it cannot be copied or assigned. Moving preserves
the cursor position and rebuilds its internal Format addresses, but invalidates
iterators and views borrowing its previous owned Format storage. Storage borrowed
by the Format remains the caller's responsibility. Runtime Format descriptors
and contexts are borrowed. Input must outlive every retained Element or diagnostic;
the range must also outlive any result borrowing its owned Format. Construction
or movement of an application Format may itself allocate; the range machinery
does not. Typed `reader<F>` continues to prohibit copying and moving.

See the compiled [basic example](../../examples/tlv++/src/basic_usage.cpp),
[custom Format example](../../examples/tlv++/src/formats/custom_format.cpp), and
[runtime Fixed example](../../examples/tlv++/src/formats/fixed_format_runtime.cpp).

## Pull-based tree traversal

`tlv_tree_reader_t` is the canonical iterative structural cursor. Include
`tlv/reader/tree.h`, supply caller-owned `tlv_tree_frame_t` storage, and initialize
with `tlv_tree_reader_init()` or `tlv_tree_reader_init_incremental()`.
`tlv_tree_reader_next_event()` returns `tlv_tree_event_t` from the shared
`tlv/tree.h` contract:

- `BEGIN` carries a complete constructed Element and opens its children.
- `ELEMENT` carries a complete primitive Element.
- `END` closes the innermost container without retaining a borrowed parent.

Root depth is zero; END has the depth of the node being closed. Empty containers
emit BEGIN then END. Source metadata belongs to node events; END's offset is the
absolute Value end before any trailer. Format alone decides framing and constructed
classification. A missing classification callback makes values opaque.
Known END events are delivered before `NEED_MORE_DATA` or final EOF.

`tlv_tree_reader_next()` remains a node-only projection returning `tlv_tree_item_t`:
Element, Source, depth, absolute start offset and constructed classification.
It hides END events for existing node consumers. Use event pulls for transformations
instead of reconstructing closure from depth; do not mix the two projections while
expecting a balanced stream. See the [structural event contract](../concepts/processing-pipeline.md#canonical-structural-events-402).

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

`max_elements` bounds published nodes, including BEGIN parents; END does not count.
Zero permits only empty input. Exceeding the depth budget returns `TLV_ERR_LIMIT`;
insufficient frame storage returns `TLV_ERR_BUFFER_TOO_SHORT` when attempting
to descend, after the parent has been returned.
Event errors and `NEED_MORE_DATA` preserve the cursor, frames, and event output.
The node-only projection may first consume pending ENDs left by a Builder.
`tlv_tree_reader_next_diag()` retains Reader diagnostics and absolute offsets
without decoding again. Tree argument/resource errors leave the diagnostic
unchanged.

### Skipping and incremental input

After receiving a nonempty constructed item, call
`tlv_tree_reader_skip_subtree()` to continue after its complete encoded extent.
The skipped descendants are neither decoded nor counted. The same operation is
available after a failed descent while that subtree remains pending. Calling it
without a pending subtree returns `TLV_ERR_INVALID_STATE`. Event mode still emits
the matching END with `skipped=1`; Writer and Document reject omitted content.
Node-only mode hides this closure. Skipping does not
validate descendants; Format may already have inspected their framing while
establishing the complete parent's extent. Closing enclosing scopes uses an
iterative loop bounded by the active depth.

Tree input updates follow the sequential Reader contract:
`tlv_tree_reader_set_input()` preserves the undiscarded suffix and accepts an
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

### Resumable Visitor adapters

Include `tlv/reader/visitor.h` and use `tlv_reader_visit()` or
`tlv_tree_reader_visit()` with an initialized cursor. Their `_diag` variants
preserve the original Reader diagnostics without another decode. The tree
adapter accepts a NULL callback for validation only; the sequential adapter
requires a callback. No adapter allocates, buffers input or recurses by nesting
depth. Recursion explicitly performed by application callbacks is outside this
library guarantee.

CONTINUE keeps pulling. STOP returns `TLV_OK`; ERROR or an unknown callback
result returns `TLV_ERR_VISITOR`. The current item is already published in all
three cases. Another call resumes without replaying it. After STOP on a parent,
resumption visits its children; the application can instead call
`tlv_tree_reader_skip_subtree()` before resuming. Do not mutate the active cursor,
input, Format or frames inside a callback.

`TLV_NEED_MORE_DATA` returns control to the application. Supply a replacement
window through the cursor's `set_input()` and call the adapter again. Final
exhaustion succeeds; incomplete final input remains an error. Parents are still
published only once their complete encoded extent is available. Offsets remain
absolute after discarding a consumed prefix. Limits and publication counts
belong to the cursor and persist across adapter calls.

The callback's Element pointer is temporary, but an Element copied by value has
the same borrowed lifetime as a direct pull result. Keep its original input and
any Format-supplied Tag storage alive and unchanged while retaining it.
Diagnostics are cleared at each adapter entry; Reader outcomes fill them,
whereas visitor and tree resource errors leave them clear. Tree `error_offset`
reports the published item for visitor errors and the frontier for pull failures
or need-more-data; it is unchanged on success.

See the runnable [Visitor example](../../examples/tlv/src/visitor.c) for STOP,
resumption and incremental input replacement.

## Ownership and composition

Input storage belongs to the caller and must stay alive and unchanged while
borrowed results are retained. Tag may instead borrow immutable Format-supplied
storage, which must also outlive retained results. Reader borrows Format and its
context; retained sources also require them. Advancing, reinitializing or
discarding the cursor does not by itself invalidate previously returned elements.
See [memory ownership](memory.md).

Tree Reader composes Reader for nested traversal; Visitor is a callback adapter.
Query, Schema and Document compose Tree Reader for nested traversal. These higher layers
retain their own traversal, storage and validation responsibilities.

## Migration from Scanner

The public Scanner API, `tlv_scan()` and `tlv/reader/scanner.h`, has been removed
in #391. Applications needing resynchronization choose candidate offsets and
call `tlv_read()` themselves. Candidate acceptance and recovery policy belong
to the application. The CLI retains its `--recover` behavior through such a
local policy.

## Migration from Walker (#394)

The generic `tlv_walk*()` functions, `TLV_WALK_MAX_DEPTH`, `reader/walker.h`
and the C++ Walker wrapper have been removed. Include `reader/visitor.h`,
initialize a Reader or Tree Reader, then call `tlv_reader_visit()` or
`tlv_tree_reader_visit()` (or their diagnostic variants). C++ uses
`cursor.visit(callback)`. Supply frame storage explicitly for tree
processing. `TLV_TREE_DEFAULT_DEPTH` is a suggested default, not a maximum.

Query's buffer convenience function owns `TLV_QUERY_MAX_STEPS` frames; use
`tlv_query_visit()` with a caller-owned cursor and matcher for resumable input
or greater traversal capacity. The query path itself still has its documented
inline capacity. Schema validators and structure codecs have their own bounded
storage (`TLV_SCHEMA_MAX_DEPTH` and `TLV_STRUCTURE_MAX_DEPTH`); exhaustion is a
resource error at actual descent, not rejection of a larger requested limit.
The WASM presentation adapter retains its own 64-level output capacity.

Callback convenience APIs use Visitor naming consistently:

| Previous API | Replacement |
| --- | --- |
| Lua `opentlv.walk_tree` | `opentlv.visit_tree` |
| `tlv_der_walk` / `tlv_der_walk_strict` | `tlv_der_visit` / `tlv_der_visit_strict` |
| `tlv_cer_walk` / `tlv_cer_walk_strict` | `tlv_cer_visit` / `tlv_cer_visit_strict` |
| `tlv_query_walk` | `tlv_query_visit_buffer` |
| `tlv::query::walk` | `tlv::query::visit_buffer` |

These are renames without compatibility aliases; callback and validation behavior
is unchanged. `tlv_query_visit` remains the resumable cursor-based API.

## Next step

Next: [Writer](writer.md) to create output, or [Document](document.md) to own and edit it.
