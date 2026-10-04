# Mutable documents

Prerequisite: Understand the owned/borrowed choice in [the basic model](../concepts/learning-model.md).

```text
wire bytes --parse--> owned tree --edit/encode--> wire bytes
```

Document is the canonical owned mutable representation of TLV data. It copies
Tags and Values into an editable tree, complementing borrowed Reader and Tree
Reader processing. Use it to retain data independently of input, query Nodes,
replace Values, insert or erase elements, and encode the edited result.
For choosing between borrowed traversal and owned editing, see
[Choose a processing API](processing.md).

```text
Low level, zero-copy:   bytes -> reader -> element -> traversal / schema / codec
High level, mutable:    Tree Reader -> Document Builder -> document -> modify -> encode
```

Document builds on Element, Format and the public Reader/Tree Reader,
Writer/Tree Writer and [Query](queries.md) contracts. It owns data and allocates;
the C borrowed processing APIs retain their allocation-free buffer/workspace
contracts and do not require a Document. Bindings can add their own allocating
conveniences. Architectural role and build inclusion are separate: Document
can be omitted with `-DOPENTLV_DOCUMENT=OFF`, and static linking/dead-code
elimination can omit unused implementation where supported. Merely enabling
Document does not allocate a tree. See
[building only the components you need](select-components.md).

## Formats

A document works with every format that can both read and write. Its
`format->is_constructed` predicate says which tags hold nested elements.
Values of those tags are parsed into child nodes; every other value stays an
opaque byte string. Without a predicate (BER's own descriptor already sets
one) the document is a flat list.

```c
#include "tlv/document/document.h"
#include "tlv/builtins/asn1/ber.h"

tlv_document_options_t options;
tlv_document_options_init(&options, &tlv_format_ber);

tlv_document_t* document;
size_t error_offset;
tlv_result_t rc = tlv_document_parse(data, size, &options, &document, &error_offset);
if (rc != TLV_OK) { /* error_offset is the offset of the offending element */ }
```

`tlv_document_options_init()` also sets the limits, which you can change before
use: `max_depth` (default `TLV_TREE_DEFAULT_DEPTH`) and `max_elements` (default
`TLV_DOCUMENT_DEFAULT_MAX_ELEMENTS`, 65536). Parsing and every later
modification are refused with `TLV_ERR_LIMIT` when they would exceed a limit, so
untrusted input cannot make a document grow without bound.

## Building from a Tree Reader

`tlv_document_parse()` and constructed-value mutations use the same internal
Tree Reader consumer as the resumable `tlv_document_builder_t`. The consumer
copies canonical tags and primitive values into owned nodes and uses the
Tree Reader's constructed classification. It does not decode TLV framing.

For incremental input, initialize a `tlv_tree_reader_t`, then create a builder:

```c
tlv_document_builder_t* builder = NULL;
tlv_document_t* document = NULL;
tlv_result_t rc = tlv_document_builder_create(&options, &reader, NULL, &builder);
if (rc == TLV_OK) {
    rc = tlv_document_builder_consume(builder, &document, &error_offset, NULL);
    /* On TLV_NEED_MORE_DATA, retain builder, replace/extend reader input with
       tlv_tree_reader_set_input(), and call consume again. */
}
/* At completion, or to cancel: */
tlv_document_builder_free(builder);
/* Only TLV_OK from consume publishes a document; free it when finished. */
tlv_document_free(document);
```

Use the same Format descriptor for the reader and document options. The
reader and its frames remain caller-owned. Do not interleave pulls or skips
while the builder is active. Input replacement follows the normal Reader
window rules; copied nodes no longer borrow the old input. Format and allocator
contexts remain borrowed and must outlive both the builder and document.

`TLV_NEED_MORE_DATA` preserves private construction state and returns a NULL
document. A whole-stream builder publishes only at final end. A terminal error
discards the unfinished nodes; the reader is not rolled back. The optional
`tlv_reader_diagnostic_t` output forwards Reader diagnostics with absolute
offsets and their original borrowed lifetime. Allocation failures and document
limits report the current item's absolute offset through `error_offset`.

### Materializing a selected subtree

Pull items and feed their tags and depths to a Query matcher. When the desired
root matches, pass that **last published item** as the `root` argument to
`tlv_document_builder_create()`. The builder copies the root immediately and
consumes its descendants without decoding the following sibling. It can
complete before the overall input is final. Continue pulling from the same
reader after completion.

The selected root has document depth zero. Document depth and element limits
apply to the selected tree, while Reader limits still apply to the entire
traversal. No Query logic is built into either Reader or Builder. Selection
materializes a complete subtree, not an arbitrary sequence with missing parents.
Malformed input outside that subtree is left for the caller's later traversal.

This reduces **owned Document memory**, but does not change Reader's input
contract: a constructed element is published only when its complete encoded
extent is contiguous. A single 500 MB constructed root therefore still needs
that extent available before its descendants can be selected. Multiple complete
roots can be consumed through successive input windows.

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

## Compare the public APIs

Each tab parses the same BER bytes `50 01 41`, finds the first top-level tag `50`,
changes its Value from `A` to `NEW`, then encodes `50 03 4E 45 57`. BER and
Document must be enabled. These are fragments inside a function with the shown
language's error handling; the detailed C operations above apply to all bindings.

/// tab | C

```c
#include "tlv/document/document.h"
#include "tlv/builtins/asn1/ber.h"

const uint8_t data[] = {0x50, 1, 'A'};
const uint8_t value[] = {'N', 'E', 'W'};
tlv_document_options_t options;
if (tlv_document_options_init(&options, &tlv_format_ber) != TLV_OK) return 1;
tlv_document_t* document = NULL;
size_t offset;
if (tlv_document_parse(data, sizeof(data), &options, &document, &offset) != TLV_OK)
    return 1;
tlv_node_t* entry = tlv_document_find(document, NULL, TLV_TAG(0x50));
uint8_t encoded[5];
size_t written;
tlv_result_t rc = entry ? tlv_node_set_value(entry, value, sizeof(value)) : TLV_ERR_INVALID_ARG;
if (rc == TLV_OK) rc = tlv_document_encode(document, encoded, sizeof(encoded), &written);
tlv_document_free(document);
if (rc != TLV_OK) return 1;
```

C returns status codes and writes into caller-owned output. Free the Document on every exit after successful parsing.

///

/// tab | C++

`tlv++/document/document.hpp` wraps the same API. `tlv::document` owns the tree and is
move-only; `tlv::node` is a cheap non-owning handle.

```cpp
#include <tlv++/tlv.hpp>

const tlv::byte data[] = {tlv::byte(0x50), tlv::byte(1), tlv::byte('A')};
tlv::document_format format(tlv_format_ber);
auto parsed = tlv::document::parse({data, sizeof(data)}, format);
if (!parsed) return 1;
tlv::document document = std::move(*parsed);
auto entry = document.find(tlv::tag_bytes<0x50>());
const tlv::byte value[] = {tlv::byte('N'), tlv::byte('E'), tlv::byte('W')};
if (!entry || !entry.set({value, sizeof(value)})) return 1;
auto encoded = document.encode();
if (!encoded) return 1;
```

Iterate top-level elements with `for (auto node : document)` and direct children
with `for (auto child : node.children())`. `node.insert(tag, value, before)`
inserts a direct child; omit `before` to append. Tag lookup selects the first
direct child or top-level element; a path query works as `document.find(query)`.
`document.size()` counts all elements, including descendants.

Document alone owns the canonical C tree. Node copies share validity metadata,
not tree ownership. Handles remain valid across Document moves and insertion.
Erasure invalidates every handle to the erased subtree. Successful replacement
of a constructed Value invalidates its descendants, preserving the parent and
unrelated handles; failed edits preserve all handles. Destruction or move
assignment over a Document invalidates handles to its previous tree.

Invalid handles test false, navigation returns empty handles, and tag/value
access returns empty views. Fallible Node operations return `TLV_ERR_INVALID_ARG`;
erasing an invalid handle does nothing. An iterator whose current node is
invalidated compares equal to the end iterator. Capture the next sibling before
erasing the current node if iteration must continue. Ranges borrow their first
node and follow the current sibling links; they are not snapshots.

Tag and Value views already returned by accessors remain borrowed: validity
tracking does not extend their storage lifetime. Do not retain them across
invalidating edits or Document destruction. Format contexts also remain borrowed.
The C++ facade allocates handle metadata and is not thread-safe. Native handle
access is an explicit interoperability escape hatch; native mutation bypasses
C++ validity tracking. Construct Nodes through Document or Node accessors rather
than from raw C pointers.

`tlv::ber::parse()` remains the borrowed Reader range API. Owning parsing uses
`tlv::document::parse(data, tlv::document_format(tlv::ber::format{}))` and returns
`expected<document, error>`. A runnable traversal and mutation example is
[`document.cpp`](https://github.com/marekcingel/OpenTLV/blob/main/examples/tlv++/src/document.cpp).

///

/// tab | Rust

```rust
use opentlv::{Document, Format, Tag};

let mut document = Document::parse(b"\x50\x01A", Format::Ber, 16, 1000)?;
let tag = Tag::from_bytes(&[0x50]);
document.find_mut(&tag).expect("tag 50").set_value(b"NEW")?;
let encoded = document.encode()?;
```

Use a function returning `Result<_, Box<dyn std::error::Error>>` to propagate both parse and mutation errors. Document drops its native tree automatically; Node borrows prevent overlapping mutation.

///

/// tab | Python

`opentlv.Document` wraps the same API as a context manager; `Node` is a cheap
non-owning handle.

```python
import opentlv

with opentlv.Document(b"\x50\x01A", opentlv.Format.BER) as document:
    entry = document.find(opentlv.Tag(b"\x50"))
    if entry is None:
        raise ValueError("tag 50 is missing")
    entry.value = b"NEW"
    encoded = document.encode()
```

Navigate with `document.first`/`for node in document`, `node.first_child`/
`for child in node`, `node.next`/`node.parent`, or search with
`document.find(tag, parent=...)`, `node.find(tag)` or a
[path query](queries.md), `document.find_path("6F/A5/50")`. Close the document
deterministically with `close()` or a `with` block, since it is the only part
of OpenTLV that allocates beyond a Python object's own memory. Runnable
version, replacing a value and appending an element in an existing message:
[document.py](https://github.com/marekcingel/OpenTLV/blob/main/bindings/python/opentlv/examples/document.py)
(`python examples/document.py`). See [Using OpenTLV from
Python](python.md#documents) for the full API, including error handling.

///

/// tab | Lua

```lua
local opentlv = require("opentlv")
local document = opentlv.document(string.char(0x50, 1) .. "A", opentlv.formats.ber)
local entry = assert(document:find("50"))
entry:set("NEW")
local encoded = document:serialize()
```

Native failures raise errors. Document and its Node handles retain native storage until garbage collection; strings returned by accessors are owned snapshots.

///

/// tab | Go

```go
format, err := opentlv.Builtin(opentlv.BER)
if err != nil {
 return err
}
document, err := opentlv.Parse([]byte{0x50, 1, 'A'}, format)
if err != nil {
 return err
}
defer document.Close()
matches, err := document.Query("50")
if err != nil {
 return err
}
if len(matches) == 0 {
 return fmt.Errorf("tag 50 is missing")
}
if err := matches[0].SetValue([]byte("NEW")); err != nil {
 return err
}
encoded, err := document.Encode()
if err != nil {
 return err
}

```

Import the public `opentlv` package and use a function returning `error`. `Close` provides deterministic cleanup. A successful edit invalidates existing Node handles; `Value()` and encoded bytes are owned Go snapshots. See the [Go binding README](../../bindings/go/README.md#document).

///

## Limits and scope

- The tree keeps decoded elements; it is not an editor for raw bytes. To patch
  bytes of a message in place without allocating, use the writer and
  [copy helpers](copy.md).
- Which tags are constructed is decided when a node is created and stays with
  the node; there is no operation that changes a node's tag.

Document uses the canonical Tree Reader to parse nested input. Its runtime depth
limit is not capped at `TLV_TREE_DEFAULT_DEPTH`; temporary structural storage uses
the Document allocator. Parsing, subtree cleanup, path search, encoded-size
measurement and encoding are iterative. Document supplies canonical BEGIN/ELEMENT/END
events to Tree Writer; it does not size or encode nested
TLVs itself. Tree Writer uses Format callbacks for every element.

Exact measurement may call both the Format's measure and encode callbacks: a
parent whose framing depends on its Value needs the actual encoded children.
Document owns the temporary frame stack, a staged output buffer, and one shared
scratch buffer. There are no per-constructed-node byte buffers. Workspace grows
through the Document allocator; allocation failures release all temporary storage.
Format callbacks must be deterministic because workspace growth can replay a
traversal. Encoder errors can therefore be returned by `encoded_size()` too.
The staged output is reused by `encode()` through the Writer copy API after the
caller buffer has passed the exact capacity check. No second encoding pass is
needed within that call. Staging requires O(encoded bytes) memory in addition to
the O(depth) stack; closing ancestors retains Tree Writer's O(bytes * depth)
worst-case copying cost.

### Choosing a destination Format

The existing C functions use the document's original Format. To encode the same
owned tree with another runtime or native Format, use
`tlv_document_encoded_size_as(document, format, &size)` and
`tlv_document_encode_as(document, format, output, capacity, &written)`.
`tlv_node_encoded_size_as()` and `tlv_node_encode_as()` select a single subtree,
excluding its siblings. The destination only needs write capability and remains
borrowed for the duration of the call. The tree and original Format are unchanged.

Destination Formats must preserve the nodes' constructed classification and
support their identifiers and Values. Identifiers are not remapped. Incompatible
classification returns `TLV_ERR_INVALID_TAG`; other Format errors propagate
unchanged. All destinations follow the same Tree Writer path.

In C++, `document.encoded_size(format)` / `document.encode(format)` and the
corresponding `node` overloads accept a borrowed `const tlv_format_t&`. The
no-argument methods retain their original behavior.

## Next step

Next: [Query](queries.md) to select nodes and [memory ownership](memory.md) for handle rules.
