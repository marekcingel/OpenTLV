# Path queries

A query addresses TLV elements by the tags on the way to them, so code can read
one value out of nested data without walking the whole structure itself. The
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
depend on a format or profile. A path of more than one tag needs a reader
format whose values can be constructed and a matching `is_constructed`
predicate, such as BER or DER; without a predicate only one-tag queries match.

This is a deliberately small language. Wildcards, indexes, recursive search and
predicates are not part of it.

/// tab | C

```c
#include "tlv/query/query.h"
#include "tlv/builtins/asn1/ber.h"

static tlv_visit_result_t print_match(const tlv_view_t* view, size_t depth,
                                      size_t offset, void* context) {
    /* view->value borrows the input and is valid only during this call. */
    (void)depth;
    (void)context;
    printf("match at offset %zu, %llu bytes\n", offset,
           (unsigned long long)view->value.length);
    return TLV_VISIT_CONTINUE;
}

tlv_query_t query;
size_t text_offset;
tlv_result_t rc = tlv_query_parse("6F/A5/50", &query, &text_offset);
/* On TLV_ERR_INVALID_ARG, text_offset is the index of the offending character. */

size_t error_offset;
rc = tlv_query_walk(data, size, &tlv_reader_format_ber, tlv_ber_is_constructed,
                    &query, TLV_WALK_MAX_DEPTH, 100000, print_match, NULL,
                    &error_offset);
```

`tlv_query_walk()` builds on `tlv_walk_tree()`: it neither allocates nor
converts the data into another structure, and the view given to the visitor
borrows the input. No match is not an error; the visitor is just never called.
The whole input is traversed unless the visitor returns `TLV_VISIT_STOP`, so
malformed data after the last match is reported, and `max_depth` and
`max_elements` apply to every traversed element, not only to matches.

To run a query on a traversal you already have, such as the DER walker, feed each
element to a matcher instead:

```c
tlv_query_matcher_t matcher;
tlv_query_matcher_init(&matcher, &query);
/* In a preorder visitor, with the element's tag and depth: */
if (tlv_query_matcher_visit(&matcher, &view->tag, depth)) {
    /* the element is addressed by the query */
}
```

///

/// tab | C++

```cpp
#include "tlv++/query/query.hpp"

size_t text_offset;
auto query = tlv::query::parse("6F/A5/50", &text_offset);
if (!query) return;  // query.error().code; text_offset is the offending character

auto walked = query->walk(
    tlv::bytes(data, size), tlv_reader_format_ber, tlv_ber_is_constructed,
    TLV_WALK_MAX_DEPTH, 100000,
    [](const tlv::entry& item, size_t depth, size_t offset) {
        // item.value borrows the input
        return TLV_VISIT_CONTINUE;
    });
```

`tlv::query` holds the parsed query by value and never allocates.
`tlv::query::walk()` wraps `tlv_query_walk()` with the visitor conventions of
`tlv::walk_tree()`.

///

/// tab | Python

`opentlv` does not bind the zero-copy walk directly; a query addresses
elements of a [`Document`](document.md) instead, through `find_path()`:

```python
with opentlv.Document(data, opentlv.Format.BER) as document:
    label = document.find_path("6F/A5/50")
    if label is not None:
        print(bytes(label.value))
```

A malformed query raises `opentlv.InvalidArgError`; no match is simply
`None`, the same as `document.find()`. Runnable version, including both
cases:
[query.py](https://github.com/marekcingel/OpenTLV/blob/main/bindings/python/opentlv/examples/query.py)
(`python examples/query.py`).

///

Rust does not bind path queries yet; see the [language bindings conceptual
model](../concepts/bindings.md) for the binding coverage of each language.
