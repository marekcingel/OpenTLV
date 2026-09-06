# C format abstraction

Include `tlv/format.h` to define an allocation-free `tlv_format_t` descriptor.
Pass it to `tlv_reader_init` or `tlv_writer_init` as the
last argument after the buffer and its size. The descriptor and its optional
`context` are borrowed and must remain valid and unchanged throughout use.

The reader requires `read_tag` and `read_length`. The writer requires
`write_tag`, `write_length`, and `length_size`. Unused operations may be NULL.
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
The C++ reader and writer constructors likewise require a `const tlv_format_t&`
as their last argument. There are no implicit-format overloads.
`tlv_format_default` is an available encoding with one raw tag byte and a
definite BER-style length of up to 65535; it does not implement full BER-TLV tags.
Reader and writer structs store a borrowed format pointer; rebuild consumers.

For a complete custom format, see `tests/tlv/src/format_test.cpp`: it defines
a two-byte tag and a fixed two-byte little-endian length, then uses the same
generic reader and writer to round-trip multiple items. Adding a format only
requires a descriptor and callbacks in application code, without parser edits.
