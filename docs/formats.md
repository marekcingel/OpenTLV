# C format abstraction

For canonical ASN.1 framing, nested validation, limits and error offsets, see
[ASN.1 DER-TLV](der.md). `tlv_reader_format_der` and `tlv_writer_format_der` also support the generic I/O below.

## Reading one element

Include `tlv/reader/reader.h` and call `tlv_read` to parse one element from the
beginning of a buffer:

```c
tlv_view_t view;
size_t consumed;
tlv_result_t result = tlv_read(data, size, &tlv_reader_format_fixed_1byte,
                               &view, &consumed);
if (result == TLV_OK) {
    /* view.value borrows data; consumed includes tag, length, and value. */
}
```

Trailing bytes are ignored. The input must remain alive while using the view.
The reader allocates no memory, copies no value bytes, and does not interpret
the value or validate a schema. Empty input (including NULL with size zero)
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

## Fixed 1-byte TLV

Use `tlv_reader_format_fixed_1byte` and `tlv_writer_format_fixed_1byte` for a one-byte tag, a one-byte unsigned length,
and exactly that many value bytes. For example, `01 03 AA BB CC` encodes tag
`01` and the three-byte value `AA BB CC`. All tag bytes are valid, including
`00` and `FF`; lengths range from 0 to 255, with no BER-style prefixes.

```c
tlv_reader_t reader;
tlv_reader_init(&reader, data, size, &tlv_reader_format_fixed_1byte);
tlv_writer_t writer;
tlv_writer_init(&writer, buffer, capacity, &tlv_writer_format_fixed_1byte);
```

Writing a tag whose size is not 1 returns `TLV_ERR_INVALID_TAG`; a value
longer than 255 bytes returns `TLV_ERR_INVALID_LENGTH`. Missing length or
value bytes return `TLV_ERR_BUFFER_TOO_SHORT`. An empty input is the end of
the stream (`TLV_ERR_END_OF_BUFFER`). Multiple records may be concatenated.

## Generic interface

Include `tlv/formats/format.h` for the allocation-free, type-distinct descriptors:

- `tlv_reader_format_t`: exactly `context`, `read_tag`, `read_length`.
- `tlv_writer_format_t`: exactly `context`, `write_tag`, `write_length`, `length_size`.

Pass the matching descriptor to `tlv_reader_init` or `tlv_writer_init` as the
last argument after the buffer and its size. The descriptor and its optional
immutable `context` are borrowed and must remain valid and unchanged throughout use.
All callbacks in the chosen direction are required; a custom reader needs no
write callbacks, and a custom writer needs no read callbacks.

`tlv_reader_format_init(format, context, read_tag, read_length)` and
`tlv_writer_format_init(format, context, write_tag, write_length, length_size)`
initialize caller-owned descriptors at runtime. They return `TLV_OK` on success
or `TLV_ERR_INVALID_ARG` for a NULL destination or required callback, leaving
the destination unchanged on failure. A NULL context is valid. Static C
initialization can use designated fields. The named callback typedefs are
`tlv_read_tag_fn`, `tlv_read_length_fn`, `tlv_write_tag_fn`,
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

For a complete custom format, see `tests/tlv/src/format_test.cpp`: it defines
a two-byte tag and a fixed two-byte little-endian length, then uses the same
generic reader and writer to round-trip multiple items. Adding a format only
requires a descriptor and callbacks in application code, without parser edits.

## BER-TLV

Use `tlv_reader_format_ber` with the reader and `tlv_writer_format_ber` with
the writer for raw BER-TLV tags
such as `5A`, `5F 2A`, `9F 1C`, and `9F 81 01`. Tags retain their wire bytes,
including class and constructed bits. High-tag-number form ends at the first
subsequent byte with bit 7 clear; its first subsequent byte must have a nonzero
low seven-bit value. Tags must fit `TLV_TAG_MAX_SIZE`. The format accepts raw
identifiers such as `9F 1C` without enforcing ASN.1 tag-number minimality or
universal-tag semantics, and does not recurse into constructed values.

Definite lengths range from zero through `SIZE_MAX` (the complete element must
also fit `size_t`). The writer uses short form below 128 and the shortest
big-endian long form otherwise: 128 is `81 80`, 256 is `82 01 00`.
The reader also accepts nonminimal definite lengths, including leading zeros.
Indefinite length `80`, reserved length prefix `FF`, and lengths overflowing
`size_t` return `TLV_ERR_INVALID_LENGTH`.

Malformed tags, unterminated tags on write, and tags exceeding capacity return
`TLV_ERR_INVALID_TAG`. Missing tag continuation or length bytes return
`TLV_ERR_BUFFER_TOO_SHORT`; a continuation requiring bytes beyond tag capacity
returns `TLV_ERR_INVALID_TAG` even if those bytes are missing. Empty input to
the generic reader returns `TLV_ERR_END_OF_BUFFER`. All BER-specific encoding
and validation live in the format callbacks.

## Nested traversal

Concrete descriptors are declared in `tlv/formats/default/default.h`,
`tlv/formats/fixed/fixed_1byte.h`, `tlv/formats/asn1/ber.h`, and
`tlv/formats/asn1/der.h`. The generic `format.h` declares only the contract.

The separate optional `tlv_is_constructed_fn` traversal argument identifies
values containing child TLVs in the same format. It receives the reader
format context and a parsed tag. NULL means opaque values. Pass
`tlv_ber_is_constructed` or `tlv_der_is_constructed` to inspect the respective
constructed bit; pass NULL for opaque default and fixed-format values.
Custom protocols can supply a different rule. This supports definite-length
nesting; indefinite lengths and EOC are not supported by this contract.

Use `tlv_walk_tree(data, size, format, is_constructed, max_depth, max_elements, visitor, context,
error_offset)` for bounded preorder traversal or NULL visitor for validation.
Depth is zero at the top level and cannot exceed `TLV_WALK_MAX_DEPTH` (64).
Limits are inclusive; zero is a real limit. Offsets identify failing elements.
STOP succeeds immediately without validating the remaining input. The original
flat reader and walker retain their behavior. See [architecture](architecture.md).
