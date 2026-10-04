# Path queries

Prerequisite: Use Reader/tree traversal or Document; see [the basic model](../concepts/learning-model.md).

```text
nested elements + path --> selected elements
```

See [Choose a processing API](processing.md) for ownership, nesting, resumable
input, construction and editing choices.

A query addresses TLV elements by the tags on the way to them, so code can read
one value out of nested data without traversing the whole structure itself. The
same text works in the C API, the C++ API and the [`otlv query`](../cli/README.md#path-queries)
command.

## Syntax

A query is a list of hexadecimal tags separated by `/`:

```text
6F/A5/50
```

The first tag names a top-level element, each following tag one of its direct
children. For the structure

```text
6F
├── 84
└── A5
    ├── 50
    └── 9F38
```

`6F/A5/50` addresses the `50` inside `A5` inside `6F`. It does not address a
`50` anywhere else, and when a tag repeats it addresses every element the path
reaches, in document order.

Tags are read in either case, must have an even number of digits and are of
any length, within `TLV_QUERY_MAX_BYTES` (512) tag bytes in total. Whitespace, empty steps and a leading or trailing
`/` are errors. The tag bytes are compared as they are, so the query does not
depend on a format or standard. A path of more than one tag needs a reader
format whose `is_constructed` says which values can be constructed, such as
BER or DER; without one only one-tag queries match.

This is a deliberately small language. Wildcards, indexes, recursive search and
predicates are not part of it.

## Borrowed traversal

The C and C++ examples below apply `6F/A5/50` to the same borrowed BER input.
`data` contains `6F 0A 84 03 41 42 43 A5 03 50 01 01`. Both visit every match;
their cursor/storage choices and error handling differ.

/// tab | C

```c
#include "tlv/query/query.h"
#include "tlv/builtins/asn1/ber.h"
#include <stdio.h>

static tlv_visit_result_t print_match(const tlv_element_t* element, size_t depth,
                                      size_t offset, void* context) {
    /* element->value borrows the input and is valid only during this call. */
    (void)depth;
    (void)context;
    printf("match at offset %zu, %llu bytes\n", offset,
           (unsigned long long)element->value.size);
    return TLV_VISIT_CONTINUE;
}

tlv_query_t query;
size_t text_offset;
tlv_result_t rc = tlv_query_parse("6F/A5/50", &query, &text_offset);
/* On TLV_ERR_INVALID_ARG, text_offset is the index of the offending character. */
if (rc != TLV_OK) return 1;

size_t error_offset;
rc = tlv_query_visit_buffer(data, size, &tlv_format_ber, &query, TLV_TREE_DEFAULT_DEPTH, 100000, print_match,
                    NULL, &error_offset);
if (rc != TLV_OK) return 1;
```

`tlv_query_visit_buffer()` builds on `tlv_tree_reader_visit()`: it neither allocates nor
converts the data into another structure, and the element given to the visitor
borrows the input. No match is not an error; the visitor is just never called.
The whole input is traversed unless the visitor returns `TLV_VISIT_STOP`, so
malformed data after the last match is reported, and `max_depth` and
`max_elements` apply to every traversed element, not only to matches.

For incremental input or caller-selected traversal storage, initialize a
`tlv_tree_reader_t` and a `tlv_query_matcher_t`, then call
`tlv_query_visit(&reader, &matcher, print_match, NULL, &error_offset)`.
Retain both states across STOP or `TLV_NEED_MORE_DATA`; replace input using
`tlv_tree_reader_set_input()` before resuming. The buffer convenience function
owns `TLV_QUERY_MAX_STEPS` frames, while the cursor API uses caller-owned frames.

To run a query on a traversal you already have, such as the DER validation traversal, feed each
element to a matcher instead:

```c
tlv_query_matcher_t matcher;
tlv_query_matcher_init(&matcher, &query);
/* In a preorder visitor, with the element's tag and depth: */
if (tlv_query_matcher_visit(&matcher, &element->tag, depth)) {
    /* the element is addressed by the query */
}
```

///

/// tab | C++

```cpp
#include "tlv++/query/query.hpp"
#include <iostream>

size_t text_offset;
auto query = tlv::query::parse("6F/A5/50", &text_offset);
if (!query) return 1; // query.error().code; text_offset is the offending character

auto visited = query->visit_buffer(
    tlv::bytes(data, size), tlv_format_ber,
    TLV_TREE_DEFAULT_DEPTH, 100000,
    [](const tlv::element_view& item, size_t depth, size_t offset) {
        // item.value() borrows the input
        (void)depth;
        std::cout << "match at offset " << offset << ", " << item.value().size() << " bytes\n";
        return TLV_VISIT_CONTINUE;
    });
if (!visited) return 1;
```

`tlv::query` holds the parsed query by value and never allocates.
`tlv::query::visit_buffer()` wraps `tlv_query_visit_buffer()` with the visitor conventions of
`tlv::tree_reader::visit()`.

Compile a reusable Query with `tlv::query::parse()` for explicit error handling,
or `tlv::query::compile()` to throw `tlv::query_error`. The exception retains
the original C result and the zero-based text error offset.

An owning Document supports all-result lookup through normal Node handles:

```cpp
auto matches = document.select("6F/A5/50");
for (auto node : matches) {
    // Use node.value(), node.children(), or node.decode<Field>().
}
```

`document.select(query)` also accepts a compiled Query. Results are a
`std::vector<tlv::node>` snapshot in Document order; selection allocates result
storage and Node validity metadata. Later insertions are absent from the snapshot.
Erased Nodes, descendants of replaced constructed Values, and handles whose
Document was destroyed become invalid according to the normal Node contract.
The result does not own the Document. `document.find(query)` still returns
only the first match.

For borrowed traversal, include `tlv++/query/query.hpp` and use:

```cpp
auto matches = reader.select("6F/A5/50"); // reader is a tlv::tree_reader
for (const auto& item : matches) {
    // item.element, item.depth and item.offset are normal Tree Reader results.
}
```

The selection owns its compiled Query and borrows the Tree Reader. It is a
single-pass range; advancing invalidates other iterator copies. Moving the range
invalidates its iterators. Successful pulls allocate nothing. Input, Format and
frames retain their normal borrowed lifetime rules. Start at the beginning of
a tree and do not interleave other cursor operations.

Only final EOF ends iteration. Malformed input, resource limits and
`NEED_MORE_DATA` throw `tlv::parse_error` with the original result and offset.
For incremental input, use `matches.next()`, which returns
`expected<tree_item, error>`; retain the selection across `NEED_MORE_DATA`,
replace the Reader input with `set_input()`, and retry. Matching state survives.
All traversed items count towards limits, including nonmatches. A constructed
parent still requires its complete encoded extent before publication.

Both surfaces reuse C Query matching. Document selection uses
`tlv_document_query_visit()`, an allocation-free callback API for all matching
Nodes. Its callbacks may stop early, but must not mutate the Document.
Tree selection uses the canonical C Tree Reader and Query matcher; it does not
materialize a Document or evaluate a separate C++ query language.

///

Rust also exposes resumable Query matching over its Tree Reader; Lua exposes
`query:evaluate(data, format)` over borrowed traversal with owned result tables.
Go currently exposes Query through Document. See the
[binding capability contract](../concepts/bindings.md) for the distinction.

## Owned-document lookup

Given a Document parsed from the same BER input, each fragment retrieves the
first `6F/A5/50` match and its Value `01`. `document` is already owned and alive
as described in [Mutable documents](document.md#compare-the-public-apis).
The public APIs differ in whether they return one match or a collection:

/// tab | C

```c
tlv_query_t query;
size_t text_offset;
if (tlv_query_parse("6F/A5/50", &query, &text_offset) != TLV_OK) return 1;
const tlv_node_t* label = tlv_document_find_path(document, &query);
if (label) {
    const uint8_t* value = tlv_node_value_data(label);
    size_t size = tlv_node_value_size(label);
    /* value borrows Document storage */
}
```

No match is `NULL`. C also offers `tlv_document_query_visit()` for all matches.

///

/// tab | C++

```cpp
auto query = tlv::query::parse("6F/A5/50");
if (!query) return 1;
auto label = document.find(*query);
if (label) {
    auto value = label.value(); // borrows Document storage
}
```

`find` returns the first match; `select` returns all matches as checked Node handles.

///

/// tab | Rust

```rust
let query = opentlv::Query::parse("6F/A5/50")?;
if let Some(label) = document.find_path(&query) {
    let value = label.value(); // borrows Document storage
}
```

No match is `None`. Query parse errors retain the byte offset; `?` propagates them.

///

/// tab | Python

```python
label = document.find_path("6F/A5/50")
if label is not None:
    value = bytes(label.value)  # owned snapshot
```

No match is `None`; malformed query text raises `opentlv.InvalidArgError`. [Runnable query example](../../bindings/python/opentlv/examples/query.py).

///

/// tab | Lua

```lua
local label = document:find("6F/A5/50")
if label then
    local value = label:value() -- owned string
end
```

No match is `nil`; malformed query text raises an error. `document:query()` returns all matching Node handles.

///

/// tab | Go

```go
matches, err := document.Query("6F/A5/50")
if err != nil {
 return err
}
if len(matches) > 0 {
 value := matches[0].Value() // owned snapshot
 fmt.Printf("%X\n", value)
}

```

`Query` returns all matches in document order, or an empty slice. Malformed text returns `*opentlv.QueryError` with its native text offset. [Runnable query example](../../bindings/go/examples/query/main.go).

///

## Next step

Next: [codecs](codecs.md) to interpret selected Values.
