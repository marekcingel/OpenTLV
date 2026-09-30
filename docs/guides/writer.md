# Bounded Tree Writer

`tlv_tree_writer_t` builds nested output through explicit `begin()`,
`write_element()` and `end()` operations. It is iterative and allocation-free,
using a destination buffer, a frame array and a separate scratch buffer supplied
by the caller. Include `tlv/writer/tree.h`; C++ exposes `tlv::tree_writer` in
`tlv++/writer/tree.hpp` with the same storage and operation contracts.

`begin()` requires a Tag classified as constructed by the destination Format.
It retains that borrowed Tag until the matching successful `end()`. Keep Tag
bytes immutable and outside all writable writer storage. `write_element()`
accepts primitive Elements and already-complete constructed Elements; it does
not retain their content or traverse complete subtrees. Schema validation is a
separate operation. `finish()` checks for unmatched `begin()` calls and does not
close them automatically or seal the cursor.

## Storage and unknown parent lengths

Children accumulate in the destination buffer. Closing a parent copies its
complete Value to scratch, then delegates measurement and encoding of the whole
parent to the existing Writer and Format. The input Value never overlaps the
encoder's output. Variable-width length transitions need no patching, reserved
maximum header, or format-specific code in Tree Writer. Formats whose measurement
depends on Value content receive the actual bytes, including for empty Values.

- Destination capacity must accommodate the final encoding.
- Scratch capacity must accommodate the largest Value closed by `end()`.
  A zero-sized workspace supports empty parents and complete-element writes.
- Each open parent needs one frame, including an empty parent. Frame capacity
  and runtime `max_depth` are independent limits.
- Item depths start at zero. `max_depth == 0` permits root Elements and empty
  root parents, but no children. `TLV_TREE_DEFAULT_DEPTH` is a suggested limit,
  not a hard maximum. An empty parent at depth N still requires N+1 frames.
- `max_elements` counts successful `begin()` and `write_element()` calls.
  Writing a complete subtree counts once; `end()` does not increment the count.

All writable storage must be disjoint. Values passed to `write_element()` must
not overlap output. No storage is allocated internally. Nested ancestors can
copy their descendants repeatedly, giving O(bytes * depth) worst-case work
and O(depth) frame storage, in addition to destination and scratch buffers.

## Publication, errors and offsets

`tlv_tree_writer_size()` returns only the completed root prefix. Bytes in an
open root are provisional and can move when ancestors acquire their headers.
Do not treat them as a final wire representation or retain pointers into them.

`begin()` failures leave all state and output unchanged. Failed writes do not
advance or count an Element; encoder errors can change unused output bytes.
Failed `end()` calls preserve the active frames, cursor and all accumulated
output bytes. This includes restoring Value bytes after an encoder has partially
overwritten them. Scratch and unused output bytes may change. A failed parent
remains open; there is no implicit close, discard or allocation. Repeating an
operation under the same conditions yields the same result for deterministic
Format callbacks. This API does not resize or replace storage mid-construction;
insufficient capacity requires restarting with suitably sized caller storage.

The `_diag` operations preserve Format error codes, regions and field offsets.
Offsets are absolute in the **current destination buffer**. For an open subtree
they are not predictions of final positions after ancestor headers are inserted.
A workspace shortage reports `TLV_WRITER_OP_END` with scratch `available` and
`required` byte counts. Successful operations leave diagnostics unchanged.

## Bounded output versus streaming

The current Format contract encodes a complete contiguous Element. Every
writable Format therefore uses bounded construction here, including BER
indefinite and CER; Tree Writer does not expose a streaming sink.

| Wire requirements | What true one-pass output would additionally need |
| --- | --- |
| Definite parent length, unknown at begin | Prior measurement of transformed children and a Format operation that can emit framing separately, or bounded staging as implemented here |
| Header depends on Value content | Sufficient prior content/measurement; a byte count alone may not suffice |
| Terminated/indefinite parent | Header independent of future content, an appendable Value and a separately emit-able trailer; any trailer state must also be bounded |

Indefinite framing alone is not a streaming API capability. The present
descriptor has no separate header/trailer operations, and Tree Writer neither
infers capabilities from Format identity nor bypasses `measure/encode`.
Format policy still applies to complete-element writes: the BER indefinite
preset only encodes constructed elements, while CER selects definite framing
for primitive elements and indefinite framing for constructed elements.

## Reader → transform → Writer

A Tree Reader returns complete Elements in preorder with an item depth. Before
processing each item, close writer parents until the number of open parents
equals that depth. For a constructed item, call `begin()` with its destination
Tag; for a primitive item, transform its content and call `write_element()`.
At final Reader exhaustion, close the remaining parents and call `finish()`.
An empty constructed item is opened and closed by the same depth transitions.

Alternatively, write an unchanged complete subtree with `write_element()` and
call `tlv_tree_reader_skip_subtree()` before advancing, when that subtree is
nonempty. Its descendants must not be written a second time. Input and output
remain separate, and input-backed Tags retained by `begin()` must stay alive
until their parents close. Non-final `TLV_NEED_MORE_DATA` does not close scopes.
No Document is required; this remains subject to Tree Reader's complete-parent
input contract. Format conversion may reject destination identifiers or content.

## Example

This self-checking example works without optional builtins:

<!-- example: examples/tlv/src/tree_writer.c -->
```c
/* Nested output with caller-owned frames, destination and scratch storage. */
#include "tlv/writer/tree.h"
#include "tlv/formats/fixed.h"
#include <string.h>

static int constructed(const void* context, const tlv_tag_t* tag) {
    (void)context;
    return tag->size == 1 && tag->data[0] >= 0x80;
}

int main(void) {
    const tlv_fixed_format_t config = {
        .tag_size = 1, .length_size = 1, .length_order = TLV_BYTE_ORDER_BIG_ENDIAN};
    tlv_format_t            format;
    uint8_t                 output[64], scratch[64];
    tlv_tree_writer_frame_t frames[2];
    tlv_tree_writer_t       writer;
    const uint8_t           value_a[] = {0xAA}, value_b[] = {0xBB};
    const tlv_element_t     a = {TLV_TAG(0x01), {value_a, sizeof(value_a)}};
    const tlv_element_t     b = {TLV_TAG(0x02), {value_b, sizeof(value_b)}};
    const uint8_t           expected[] = {0xE1, 8, 1, 1, 0xAA, 0xE2, 3, 2, 1, 0xBB};
    if (tlv_fixed_format_init(&format, &config) != TLV_OK) return 1;
    format.is_constructed = constructed;
    if (tlv_tree_writer_init(&writer, output, sizeof(output), &format, frames, 2, scratch,
                             sizeof(scratch), TLV_TREE_DEFAULT_DEPTH, SIZE_MAX) != TLV_OK)
        return 1;
    if (tlv_tree_writer_begin(&writer, TLV_TAG(0xE1)) != TLV_OK) return 1;
    if (tlv_tree_writer_write_element(&writer, &a) != TLV_OK) return 1;
    if (tlv_tree_writer_begin(&writer, TLV_TAG(0xE2)) != TLV_OK) return 1;
    if (tlv_tree_writer_write_element(&writer, &b) != TLV_OK) return 1;
    if (tlv_tree_writer_end(&writer) != TLV_OK) return 1;
    if (tlv_tree_writer_size(&writer) != 0) return 1; /* Outer root is still open. */
    if (tlv_tree_writer_end(&writer) != TLV_OK) return 1;
    if (tlv_tree_writer_finish(&writer) != TLV_OK) return 1;
    return tlv_tree_writer_size(&writer) == sizeof(expected) &&
                   memcmp(output, expected, sizeof(expected)) == 0
               ? 0
               : 1;
}
```
