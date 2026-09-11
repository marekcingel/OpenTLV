# C library formats

The directory layout follows the C library's `formats/default`, `formats/fixed`,
and `formats/asn1` implementation families. Each page includes a byte example.
Profile semantics are documented separately.

- [Default TLV](default/README.md)
- [Fixed 1-byte TLV](fixed/README.md)
- [BER-TLV](asn1/ber.md)
- [DER-TLV](asn1/der.md)
- [Application-defined formats](custom/README.md)
- Profiles: [DER validation](../profiles/der/README.md), [EMV](../profiles/emv/README.md)


## Choose a format

| Need | Start with | Boundary |
| --- | --- | --- |
| Small internal records with fixed header sizes | [Fixed 1-byte TLV](fixed/README.md) | Values up to 255 bytes |
| One-byte tags with larger payloads | [Default TLV](default/README.md) | Values up to 65,535 bytes |
| Multi-byte tags or constructed indefinite values | [BER-TLV](asn1/ber.md) | Payload semantics are separate |
| Canonical ASN.1 framing and nested checks | [DER](../profiles/der/README.md) | Structural validation, not full semantic DER |
| EMV Contact Book 3 data objects | [BER plus EMV profile](../profiles/emv/README.md) | Dictionary/codecs, not a transaction engine |
| Application-specific framing | [Custom callbacks](custom/README.md) | Application supplies wire rules |

All formats follow the [shared memory ownership rules](../memory.md).

For canonical ASN.1 framing, nested validation, limits and error offsets, see
[ASN.1 DER-TLV](../profiles/der/README.md). `tlv_reader_format_der` and `tlv_writer_format_der` also support the generic I/O below.

## Reading one element

Include `tlv/reader/reader.h` and call `tlv_read` to parse one element from the
beginning of a buffer:

```c
tlv_view_t view;
size_t consumed;
tlv_result_t result = tlv_read(data, size, &tlv_reader_format_fixed_1byte,
                               &view, &consumed);
if (result == TLV_OK) {
    /* view.value borrows data; consumed also includes any framing trailer. */
}
```

Trailing bytes are ignored. The input must remain alive while using the view.
The reader allocates no memory, copies no value bytes, and does not decode
value semantics or validate a schema. Formats may inspect nested framing to
resolve an element boundary. Empty input (including NULL with size zero)
returns `TLV_ERR_END_OF_BUFFER`; missing tag, length, or value bytes return
`TLV_ERR_BUFFER_TOO_SHORT` with the supplied formats. Invalid arguments return
`TLV_ERR_NULL_ARG`. Both outputs are required and remain unchanged on failure.
Custom format callback errors propagate unchanged. The stateful
`tlv_reader_next` uses the same parser and advances by the consumed size.

## Walking multiple elements

Include `tlv/reader/walker.h` to visit concatenated elements with the generic reader:

```c
static tlv_visit_result_t count_entry(const tlv_view_t* view, void* context) {
    size_t* count = (size_t*)context;
    (void)view;
    ++*count;
    return TLV_VISIT_CONTINUE;
}

/* Inside a function: */
size_t count = 0;
tlv_result_t result = tlv_walk(data, size, &tlv_reader_format_fixed_1byte,
                              count_entry, &count);
```

The visitor runs once per successfully parsed element, in buffer order.
Return `TLV_VISIT_CONTINUE` to advance, `TLV_VISIT_STOP` to finish successfully,
or `TLV_VISIT_ERROR` to return `TLV_ERR_VISITOR`. Unknown visitor results also
return `TLV_ERR_VISITOR`. Reader errors propagate unchanged. Stop and error
prevent parsing any further elements; earlier callback effects remain.

Empty input, including NULL with size zero, succeeds without calling the visitor.
The visitor and a format with both read callbacks are required even for empty
input; invalid arguments return `TLV_ERR_NULL_ARG`. The optional context may be
NULL. The view pointer lasts only for the callback; a copied view still borrows
the input value. Keep the input and format valid and unchanged during traversal.
The walker allocates no memory and never interprets or recurses into values,
even when they contain nested TLVs.

## Writing one element

Include `tlv/writer/writer.h`. Query the complete encoded size without providing value
bytes, then write into a caller-owned buffer:

```c
const tlv_tag_t tag = {{0x01}, 1};
const uint8_t value[] = {0xAA, 0xBB, 0xCC};
uint8_t buffer[5];
size_t required, written;
tlv_result_t result = tlv_encoded_size(tag, sizeof(value),
                                      &tlv_writer_format_fixed_1byte, &required);
if (result == TLV_OK && required <= sizeof(buffer)) {
    result = tlv_write(buffer, sizeof(buffer), &tlv_writer_format_fixed_1byte,
                       tag, value, sizeof(value), &written);
    /* On success: written == required; buffer contains 01 03 AA BB CC. */
}
```

Both APIs require `write_tag`, `write_length`, and `length_size`. The size query
validates the tag and length; a total that cannot fit in `size_t` returns
`TLV_ERR_INVALID_LENGTH`. Output size pointers are required and remain unchanged
on failure. Insufficient capacity returns `TLV_ERR_BUFFER_TOO_SHORT` before any
destination bytes are written. NULL output memory is valid only with zero
capacity, which reports insufficient capacity for an otherwise valid element.
An empty value may use NULL with length zero and still encodes tag and length.
Value bytes are copied verbatim without allocation or semantic interpretation.
The source value must not overlap the destination element. Callback errors
propagate and may leave partially encoded bytes. `tlv_writer_write` uses the
same encoder and advances its position only on success.

## Generic interface

Include `tlv/formats/format.h` for the allocation-free, type-distinct descriptors:

- `tlv_reader_format_t`: `context`, `read_tag`, `read_length`, optional `read_value_bounds`.
- `tlv_writer_format_t`: exactly `context`, `write_tag`, `write_length`, `length_size`.

Pass the matching descriptor to `tlv_reader_init` or `tlv_writer_init` as the
last argument after the buffer and its size. The descriptor and its optional
immutable `context` are borrowed and must remain valid and unchanged throughout use.
All callbacks except `read_value_bounds` are required; a custom reader needs no
write callbacks, and a custom writer needs no read callbacks.

`tlv_reader_format_init(format, context, read_tag, read_length)` and
`tlv_writer_format_init(format, context, write_tag, write_length, length_size)`
initialize caller-owned descriptors at runtime. They return `TLV_OK` on success
or `TLV_ERR_INVALID_ARG` for a NULL destination or required callback, leaving
the destination unchanged on failure. A NULL context is valid. Static C
initialization can use designated fields. The named callback typedefs are
`tlv_read_tag_fn`, `tlv_read_length_fn`, `tlv_read_value_bounds_fn`, `tlv_write_tag_fn`,
`tlv_write_length_fn`, and `tlv_length_size_fn`.

The two descriptor pointer types are incompatible. C++ rejects a direction
mismatch; C builds with `-std=c11 -Wall -Wextra -Werror` reject it as well.
Without warnings-as-errors, a C compiler may diagnose the mismatch and continue.
No combined format descriptor or compatibility alias is provided.

Callbacks receive the context and a bounded byte range; return a `tlv_result_t`
and report consumed or written bytes through their output pointer.

`write_tag(context, NULL, 0, tag, &size)` is a mandatory validation and sizing
query. `length_size` validates a value length and returns its encoded size.
The writer checks total capacity before invoking the actual encoding callbacks,
which must write exactly the queried sizes. No temporary heap buffer is needed.
Tags are copied into `tlv_tag_t`; decoded values borrow the input buffer.
A tag must consume at least one byte and contain 1 through `TLV_TAG_MAX_SIZE`
raw bytes. A format may use a zero-byte length field for an implicit length.

When non-NULL, `read_value_bounds(context, tag, data, size, &length_size,
&value_size, &trailer_size)` replaces `read_length` during element parsing.
Its bounded input begins immediately after the parsed tag. It reports three
consecutive ranges: the length field, the borrowed value, and trailing framing.
The core checks each size against the remaining input before publishing outputs.
The value view excludes the trailer, while `consumed` includes it. Format-specific
resolution, including BER EOC matching, stays in this callback.

This appended field changes the reader descriptor ABI: rebuild the library and
all consumers together. `tlv_reader_format_init` keeps its signature and clears
the optional callback; assign it afterwards when needed. Custom aggregate
initializers should explicitly append `NULL` (C) or `nullptr` (C++) to avoid
missing-field warnings. Descriptors assigned field by field must initialize the
new field too. The writer descriptor and `tlv_view_t` are unchanged.

On failure, reader position and output remain unchanged. Writer position also
remains unchanged, but an encoding callback failure may leave modified bytes
beyond that position. Callbacks must obey their buffer bounds; the core checks
reported sizes but cannot undo an out-of-bounds write by a custom callback.
Source values passed to the writer must not overlap the destination item.

`tlv_reader_init` and `tlv_writer_init` require an explicit format argument.
The C++ reader constructor requires `const tlv_reader_format_t&`; the writer
constructor requires `const tlv_writer_format_t&` as its last argument. There are no implicit-format overloads.
`tlv_reader_format_default` and `tlv_writer_format_default` are public const
descriptors for one raw tag byte and a
definite BER-style length of up to 65535; it does not implement full BER-TLV tags.
Reader and writer structs store a borrowed format pointer; rebuild consumers.

For a complete custom format, see `tests/integration/tlv/src/format_test.cpp`: it defines
a two-byte tag and a fixed two-byte little-endian length, then uses the same
generic reader and writer to round-trip multiple items. Adding a format only
requires a descriptor and callbacks in application code, without parser edits.

## Nested traversal

Concrete descriptors are declared in `tlv/formats/default/default.h`,
`tlv/formats/fixed/fixed_1byte.h`, `tlv/formats/asn1/ber.h`, and
`tlv/formats/asn1/der.h`. The generic `format.h` declares only the contract.

The separate optional `tlv_is_constructed_fn` traversal argument identifies
values containing child TLVs in the same format. It receives the reader
format context and a parsed tag. NULL means opaque values. Pass
`tlv_ber_is_constructed` or `tlv_der_is_constructed` to inspect the respective
constructed bit; pass NULL for opaque default and fixed-format values.
Custom protocols can supply a different rule. Traversal follows the value view
and resumes at the complete encoded end, so BER EOCs are skipped correctly.

Use `tlv_walk_tree(data, size, format, is_constructed, max_depth, max_elements, visitor, context,
error_offset)` for bounded preorder traversal or NULL visitor for validation.
Depth is zero at the top level and cannot exceed `TLV_WALK_MAX_DEPTH` (64).
Limits are inclusive; zero is a real limit. Offsets identify failing elements.
STOP succeeds immediately without validating the remaining input. The original
flat reader and walker retain their behavior. See [architecture](../architecture.md).
