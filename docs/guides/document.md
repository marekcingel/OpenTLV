# Mutable documents

The reader, writer and walker are zero-copy: they look at the input buffer and
never allocate. That is the right tool for parsing and for embedded targets, but
it cannot change a message that already exists. When an application has to
read a TLV message, change a field, add or drop an element and send it on, use
the optional **document** API. It copies the data into an owned tree that can be
modified, and encodes it again.

```text
Low level, zero-copy:   bytes -> reader -> view -> traversal / schema / codec
High level, mutable:    bytes -> document -> inspect / modify -> encode
```

The document is a separate layer on top of the public reader, writer and
[path query](queries.md) APIs. It changes nothing about how they work, and they
do not depend on it. It is the only OpenTLV component that allocates memory, and
it can be left out of a build with `-DOPENTLV_DOCUMENT=OFF`; see
[building only the components you need](select-components.md).

## Formats

A document works with every format. You give it the same pieces that
`tlv_walk_tree()` takes: a reader format, a writer format and an optional
`is_constructed` predicate that says which tags hold nested elements. Values of
those tags are parsed into child nodes; every other value stays an opaque byte
string. Without a predicate the document is a flat list.

```c
#include "tlv/document/document.h"
#include "tlv/formats/asn1/ber.h"

tlv_document_options_t options;
tlv_document_options_init(&options, &tlv_reader_format_ber,
                          &tlv_writer_format_ber, tlv_ber_is_constructed);

tlv_document_t* document;
size_t error_offset;
tlv_result_t rc = tlv_document_parse(data, size, &options, &document, &error_offset);
if (rc != TLV_OK) { /* error_offset is the offset of the offending element */ }
```

`tlv_document_options_init()` also sets the limits, which you can change before
use: `max_depth` (default `TLV_WALK_MAX_DEPTH`) and `max_elements` (default
`TLV_DOCUMENT_DEFAULT_MAX_ELEMENTS`, 65536). Parsing and every later
modification are refused with `TLV_ERR_LIMIT` when they would exceed a limit, so
untrusted input cannot make a document grow without bound.

## Inspecting

Nodes form a tree. Use the navigation functions or a [path query](queries.md):

```c
tlv_node_t* fci = tlv_document_find(document, NULL, TLV_TAG(0x6F));
for (tlv_node_t* child = tlv_node_first_child(fci); child; child = tlv_node_next(child)) {
    tlv_tag_t tag = tlv_node_tag(child);
    /* ... */
}

tlv_query_t query;
tlv_query_parse("6F/A5/50", &query, NULL);
tlv_node_t* label = tlv_document_find_path(document, &query);
const uint8_t* value = tlv_node_value_data(label);
size_t length = tlv_node_value_size(label);
```

`tlv_document_find_path()` returns the first element the query addresses in
document order. A constructed node has no value bytes of its own; read its
children.

## Modifying

```c
/* Replace a value. */
tlv_node_set_value(label, (const uint8_t*)"NEW", 3);

/* Insert: parent NULL is the top level, before NULL appends. */
tlv_node_t* created;
tlv_document_insert(document, fci, NULL, TLV_TAG(0x5F, 0x2D), lang, 2, &created);

/* Erase a node with everything below it. */
tlv_node_erase(label);
```

For a constructed tag the value given to `tlv_node_set_value()` and
`tlv_document_insert()` is *encoded child elements*, parsed with the document's
reader format, exactly as if it had been in the input. Enclosing lengths are
never stored, so they cannot go stale: changing a value anywhere in the tree
changes the encoded lengths of all its ancestors automatically.

Every modification either succeeds completely or leaves the document unchanged,
including when memory runs out (`TLV_ERR_OUT_OF_MEMORY`) or a nested value is
malformed.

## Encoding

```c
size_t size;
tlv_document_encoded_size(document, &size);
uint8_t* out = malloc(size);
tlv_document_encode(document, out, size, &size);
```

Encoding uses the writer format, through `tlv_writer_write()`. It fails with the
writer's error, for example `TLV_ERR_INVALID_LENGTH` when a value became longer
than the format can express, and the document stays as it was so you can repair
it. `tlv_node_encode()` and `tlv_node_encoded_size()` do the same for a single
element with its descendants.

The document stores decoded elements, not the original bytes, so it encodes with
the writer's spelling. Input the writer would spell differently, such as a
non-minimal BER length or an indefinite-length container, is normalised; input
that already uses the writer's spelling encodes back to identical bytes.

## Ownership and lifetime

| Object | Rule |
| --- | --- |
| Input buffer | Copied by `tlv_document_parse()`; it can be released or reused as soon as the call returns. |
| `tlv_document_t` | Owns every node, tag and value. Free it with `tlv_document_free()`. |
| `tlv_node_t*` | Borrows from the document. Valid until the node is erased or the document is freed. Erasing a node also invalidates every node below it. |
| Tag and value pointers read from a node | Borrow the node's storage. A value pointer is invalidated when that node's value is replaced. |
| Formats and their contexts | Borrowed; keep them valid until the document is freed. |
| Allocator | Optional `tlv_allocator_t` in the options, copied into the document; `malloc()` and `free()` by default. |

A document is not synchronised: concurrent reads are fine, any modification
needs exclusive access.

## C++

`tlv++/document.hpp` wraps the same API. `tlv::document` owns the tree and is
move-only; `tlv::node` is a cheap non-owning handle.

```cpp
#include <tlv++/document.hpp>

tlv::document_format format(tlv_reader_format_ber, tlv_writer_format_ber,
                            tlv_ber_is_constructed);

auto parsed = tlv::document::parse(buffer, format);
if (!parsed) { /* parsed.error().code */ }
tlv::document document = std::move(*parsed);

tlv::node entry = document.find(TLV_TAG(0x50));
if (entry) (void)entry.set(new_value);

(void)document.insert(new_tag, new_value);
document.erase(old_tag);

auto encoded = document.encode();   // expected<std::vector<byte>, error>
```

Handles stay valid when the document is moved. Children can be visited with
`for (tlv::node child : tlv::node_range(parent.first_child()))`, and a path
query works as `document.find(query)`.

## Limits and scope

- The tree keeps decoded elements; it is not an editor for raw bytes. To patch
  bytes of a message in place without allocating, use the writer and
  [copy helpers](copy.md).
- Which tags are constructed is decided when a node is created and stays with
  the node; there is no operation that changes a node's tag.
