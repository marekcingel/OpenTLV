# Memory ownership and lifetime

[Back to documentation](../README.md)

| Object or operation | Ownership and lifetime |
| --- | --- |
| `tlv_value_t` | Borrows its bytes; does not allocate or free them. Its `tlv_length_t` length may exceed the current build's `size_t`; convert with `tlv_length_to_size()` before native-size use. |
| `tlv_tag_t` | Borrows its bytes (a pointer and a size); does not allocate, own or copy them, and has no length limit. Copying a tag copies only the pointer and the size. |
| `tlv_view_t` | Holds a borrowed `tlv_tag_t` and a borrowed `tlv_value_t`. Copying a view copies neither the tag bytes nor the payload. |
| Reader | Borrows the input, format descriptor, and descriptor context. Keep them valid and unchanged during use. |
| Writer | Borrows output storage, its format descriptor, and context. The caller provides capacity. |
| Visitor | Receives a temporary view; a copied view still borrows the input. |
| Value codecs | Representation-dependent; some results borrow input. Follow the selected codec contract. |
| `tlv_document_t` (optional) | Owns a copy of everything in it and allocates; nodes and the tags and values read from them borrow from the document. See [mutable documents](document.md#ownership-and-lifetime). |

## Reading

Keep the input buffer alive and unchanged while using any view into it, including
nested child views. Reusing a receive buffer invalidates the previous values.
A successful read copies neither the tag nor the value and does not allocate a
tree: `view.tag` and `view.value` both point into the input. Do not return a
borrowed view into a local array that goes out of scope.

## Tags

A `tlv_tag_t` is a pointer and a size. The bytes it refers to must stay valid,
and unchanged, for as long as the tag is used, and copying the tag never extends
that lifetime.

- A tag read from input references the input buffer.
- `TLV_TAG(0x9F, 0x02)` refers to constant storage the compiler provides. In
  C++ that storage is static; in C it is a compound literal that lives until the
  end of the enclosing block.
- `tlv_tag(data, size)` refers to whatever `data` points to.
- `tlv_der_tag_make()` and `tlv_cer_tag_make()` write into caller-provided
  `storage`, which has to outlive the tag.
- APIs do not retain a tag beyond the call unless their documentation says so.
  Structures that hold tags, such as a `tlv_schema_entry_t`, a
  `tlv_dol_entry_t`, a `tlv_schema_issue_t` path, or a reader's view, therefore
  borrow the bytes too: a schema table needs its tag bytes to have static (or
  otherwise long) storage, and a validation report's paths point into the input
  that was validated, or into the schema for a missing tag.
- A `tlv_query_t` is the exception: it copies the tag bytes it parses, so it is
  a self-contained value, and `tlv_query_step()` returns tags that borrow it.
- An empty tag is `{ NULL, 0 }`. `{ NULL, size }` with a nonzero size is invalid.

To keep a tag after its input is gone, copy its bytes into your own storage and
build a new tag over the copy.

```c
uint8_t kept[8];
memcpy(kept, view.tag.data, view.tag.size);   /* the format bounded the size */
tlv_tag_t stable = tlv_tag(kept, view.tag.size);
```

To retain data independently, use the [copy helpers](copy.md) with caller-owned
storage. `tlv_copy_value` copies payload bytes; `tlv_copy_encoded` preserves a full
encoded range; `tlv_copy_view` re-encodes with a selected writer format.
For indefinite BER, preserve the consumed range when the original EOC and outer
encoding must be retained.

## Writing

The C writer copies value bytes into caller-provided output. The source value
must not overlap the destination element. Capacity is checked before writing;
custom callback failures can still leave partially modified bytes. Do not assume
that every error rolls back destination memory. See [I/O contracts](../formats/README.md).

## Custom descriptors and C++

Descriptors and their optional context are borrowed, not owned. Avoid returning a
reader or writer referring to a descriptor or context local to a completed function.
The C core does not allocate dynamically. C++ convenience types, error strings,
and dynamic containers may allocate; choose the C API for a strict no-heap path.

See also the [C API reference](../reference/c-api.md#core-types-and-utilities) and the [C++ API reference](../reference/cxx-api.md).
