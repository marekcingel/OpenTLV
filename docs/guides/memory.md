# Memory ownership and lifetime

[Back to documentation](../README.md)

| Object or operation | Ownership and lifetime |
| --- | --- |
| `tlv_value_t` | Borrows its bytes; does not allocate or free them. Its `tlv_size_t` length may exceed the current build's `size_t`; convert with `tlv_size_to_native()` before native-size use. |
| `tlv_tag_t` | Borrows its bytes (a pointer and a size); does not allocate, own or copy them, and has no length limit. Copying a tag copies only the pointer and the size. |
| `tlv_element_t` | Holds a borrowed `tlv_tag_t` and a borrowed `tlv_value_t`. Copying an element copies neither the tag bytes nor the payload. |
| Reader | Borrows the input, format descriptor, and descriptor context. Keep them valid and unchanged during use. |
| Writer | Borrows output storage, its format descriptor, and context. The caller provides capacity. |
| Visitor | Receives a temporary view; a copied view still borrows the input. |
| Value codecs | Representation-dependent; some results borrow input. Follow the selected codec contract. |
| `tlv_document_t` | Canonical owned mutable representation; owns copied Tags, Values and nodes and allocates; nodes and the tags and values read from them borrow from the document. See [mutable documents](document.md#ownership-and-lifetime). |

## Reading

Keep the input buffer alive and unchanged while using any view into it, including
nested child views. Reusing a receive buffer invalidates the previous values.
A successful read copies neither the tag nor the value and does not allocate a
tree: `element.value` points into the input. `element.tag` normally does too,
but `TLV_TAG_BINDING_FORMAT` permits immutable identifier storage supplied by
the format. Keep that storage alive and unchanged for all retained elements,
tags and shallow copies, even after the reader advances. Do not return a
borrowed view into a local array that goes out of scope.

## Tags

A `tlv_tag_t` is a pointer and a size. The bytes it refers to must stay valid,
and unchanged, for as long as the tag is used, and copying the tag never extends
that lifetime.

- A decoded tag references input or immutable format-supplied storage; see the
  [decoded identifier contract](../concepts/format-contract.md#decoded-identifier-consistency).
- `TLV_TAG(0x9F, 0x02)` refers to constant storage the compiler provides. In
  C++ that storage is static; in C it is a compound literal that lives until the
  end of the enclosing block.
- `tlv_tag(data, size)` refers to whatever `data` points to.
- `tlv_der_tag_make()` and `tlv_cer_tag_make()` write into caller-provided
  `storage`, which has to outlive the tag.
- APIs do not retain a tag beyond the call unless their documentation says so.
  Structures that hold tags, such as a `tlv_schema_entry_t`, a
  `tlv_dol_entry_t`, a `tlv_schema_diagnostic_t` path, or a reader's view, therefore
  borrow the bytes too: a schema table needs its tag bytes to have static (or
  otherwise long) storage, and a validation report's paths point into the input
  that was validated, immutable format-supplied identifier storage, or the schema
  for a missing tag.
- A `tlv_query_t` is the exception: it copies the tag bytes it parses, so it is
  a self-contained value, and `tlv_query_step()` returns tags that borrow it.
- An empty tag is `{ NULL, 0 }`. `{ NULL, size }` with a nonzero size is invalid.

To keep a tag after its input is gone, copy its bytes into your own storage and
build a new tag over the copy.

```c
uint8_t kept[8];
memcpy(kept, element.tag.data, element.tag.size);   /* the format bounded the size */
tlv_tag_t stable = tlv_tag(kept, element.tag.size);
```

To retain data independently, use the [copy helpers](copy.md) with caller-owned
storage. `tlv_copy_value` copies payload bytes; `tlv_copy_encoded` preserves a full
encoded range; `tlv_copy_element` re-encodes with a selected writer format.
For indefinite BER, preserve the consumed range when the original EOC and outer
encoding must be retained.

## Writing

The C writer copies value bytes into caller-provided output. The source value
must not overlap the destination element. Capacity is checked before writing;
custom callback failures can still leave partially modified bytes. Do not assume
that every error rolls back destination memory. See [I/O contracts](../formats/README.md).

Sizing is the allocation boundary: OpenTLV reports exact storage, the caller
chooses where to allocate it, and Writer fills that storage. Neither measuring
nor writing requires Document, output I/O, or hidden buffering.

- `tlv_element_encoded_size(element, format, &required)` measures Header +
  Value + Trailer using the complete semantic input. It checks that the total
  fits native `size_t` without allocating output memory.
- `tlv_encoded_size(tag, value_length, format, &required)` remains available
  when the Format can measure without reading Value content.
- `tlv_write_element()` writes one Element. `tlv_writer_write_element()`
  appends it to a caller-owned cursor; the tag/value/length helpers use the
  same path. `tlv_writer_copy_element()` also re-encodes with the target Format.
- `tlv_writer_preserve()` appends original Source bytes after verifying
  unchanged semantic content. Source storage must remain immutable. The
  cursor's Format does not convert the preserved representation.
- `tlv_writer_copy_encoded()` appends an arbitrary byte range without framing
  validation. Raw copying and preservation support overlapping byte ranges;
  semantic encoding does not. Source descriptors must not overlap output.

Every cursor operation advances `pos` only on success, with `pos <= capacity`.
`tlv_writer_remaining()` reports remaining capacity. A cursor with no storage
is a real destination, never an implicit sizing mode. A zero-byte raw copy can
succeed; an Element cannot fit in zero capacity.

`tlv_write()` and `tlv_write_element()` set `written` to the required size on a
preflight capacity failure, leaving destination bytes unchanged. Other failures
leave `written` unchanged. Standalone copy helpers retain their separate contract:
`NULL, 0` queries size, and failure leaves `written` unchanged. For original
representation sizing, use `tlv_source_preserve(source, element, NULL, 0, &required)`.

Diagnostic variants preserve diagnostics on success. On failure they identify
the operation, applicable semantic input, and known required/available sizes.
Sizing has no destination capacity. Field offsets are relative to the Element
for standalone operations and absolute within the buffer for cursor operations;
errors without a field offset point to the Element start. An absolute offset
that cannot be represented is unset.

In C++, `tlv::encoded_size(element, format)` and `tlv::writer<>::write(element)`
provide the same two-stage model; error objects may allocate. Rust exposes
`element_encoded_size` (and its fixed-format variant) and a Writer borrowing
`&mut [u8]`. Python exposes `element_encoded_size` and
`Writer(format, buffer=storage)`: caller-supplied writable contiguous storage
never grows. `Writer.view()` borrows written bytes; `Writer.bytes()` copies.
Python wrapper objects may allocate; borrowed mode does not allocate output
storage. Omitting `buffer` retains the optional growable convenience wrapper.

## Format context ownership and lifetime

`tlv_format_t::context` is a borrowed, non-owning `const void*`: whoever
constructs the state it points to (for example a `tlv_fixed_format_t`) owns
it, and must keep it valid and unchanged for as long as any `tlv_format_t` —
and any reader, writer, document or structure codec built from it — is in
use. Passing `NULL` is always valid; not every format needs runtime state.

`tlv_format_t` itself is a plain, trivially copyable value: copying it
shallow-copies the callback pointers and the `context` pointer, but does not
copy or extend the lifetime of whatever `context` points to. State types such
as `tlv_fixed_format_t` are themselves ordinary movable/copyable values with
no special member functions of their own — but relocating one (a move, a
copy, a `realloc`, a growing `Vec`/`std::vector`) changes its address, which
invalidates any `tlv_format_t` that already stored the *old* address as its
context. Re-run the format's `_init` function (or the language binding's
equivalent) against the new address if you need a `tlv_format_t` for it.

**Avoid self-referential containers.** Do not define a struct that holds both
a format's state and a `tlv_format_t` pointing at that state as a sibling
member of the same struct: copying or moving such a struct relocates the
state but leaves the embedded `tlv_format_t::context` pointing at the old,
now-stale address. If you need a movable or copyable wrapper type around a
format, keep its state behind a stable, heap-owned pointer instead, the way
`tlv::document`'s private implementation struct does (heap-allocated via
`std::unique_ptr`), precisely so the C document's internal pointers survive a
move of the `tlv::document` value.

OpenTLV itself never mutates a format descriptor or its context after
initialization, so multiple readers, writers and documents may safely share
one immutable format concurrently, including across threads. This does not
by itself make a *custom* format thread-safe: the callbacks and context of a
custom format are supplied by its author, and whether they tolerate
concurrent calls is the author's responsibility, not a guarantee OpenTLV
makes on their behalf. The built-in formats (including the configurable
Fixed format) always are, since their context, when present, is read-only
scalar state.

This model scales unchanged to arbitrarily large runtime-defined format
state: the caller picks whatever storage duration suits it (stack, static,
heap, arena), and OpenTLV never requires an inline buffer or a forced heap
allocation just to keep a context pointer stable.

## Custom descriptors and C++

Descriptors and their optional context are borrowed, not owned (see
[above](#format-context-ownership-and-lifetime)). Avoid returning a reader or
writer referring to a descriptor or context local to a completed function.
Borrowed C processing does not allocate dynamically; Document owns storage and
allocates. C++ convenience types, error strings and dynamic containers may also
allocate. Select operations with explicit caller storage for a strict no-heap
path; enabling Document does not impose runtime allocations on unused paths.

See also the [C API reference](../reference/c-api.md#core-types-and-utilities) and the [C++ API reference](../reference/cxx-api.md).
