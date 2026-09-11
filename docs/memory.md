# Memory ownership and lifetime

[Back to documentation](README.md)

| Object or operation | Ownership and lifetime |
| --- | --- |
| `tlv_buffer_t` | Borrows its bytes; does not allocate or free them. |
| `tlv_tag_t` | Stores tag bytes inline; copying it copies the tag. |
| `tlv_view_t` | Stores a tag inline and borrows value bytes. Copying a view does not copy its payload. |
| Reader | Borrows the input, format descriptor, and descriptor context. Keep them valid and unchanged during use. |
| Writer | Borrows output storage, its format descriptor, and context. The caller provides capacity. |
| Visitor | Receives a temporary view; a copied view still borrows the input. |
| Value codecs | Representation-dependent; some results borrow input. Follow the selected codec contract. |

## Reading

Keep the input buffer alive and unchanged while using any view into it, including
nested child views. Reusing a receive buffer invalidates the previous values.
A successful read copies tag bytes but does not copy the value or allocate a tree.
Do not return a borrowed view into a local array that goes out of scope.

To retain data independently, use the [copy helpers](copy.md) with caller-owned
storage. `tlv_copy_value` copies payload bytes; `tlv_copy_encoded` preserves a full
encoded range; `tlv_copy_view` re-encodes with a selected writer format.
For indefinite BER, preserve the consumed range when the original EOC and outer
encoding must be retained.

## Writing

The C writer copies value bytes into caller-provided output. The source value
must not overlap the destination element. Capacity is checked before writing;
custom callback failures can still leave partially modified bytes. Do not assume
that every error rolls back destination memory. See [I/O contracts](formats/README.md).

## Custom descriptors and C++

Descriptors and their optional context are borrowed, not owned. Avoid returning a
reader or writer referring to a descriptor or context local to a completed function.
The C core does not allocate dynamically. C++ convenience types, error strings,
and dynamic containers may allocate; choose the C API for a strict no-heap path.
