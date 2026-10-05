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

The V1 helpers below retain exact-path syntax. The separately selected compiled
language uses caller-owned program and execution storage; see the
[Query language and execution contract](../concepts/query-language.md).
Compiled execution supports S0/S1 streaming, explicitly retained S2 and Document D,
typed variables and scalar results. The full language is selected explicitly by
the compiled program APIs; the V1 helpers retain their smaller grammar.

## Full programs and integration

C++ applications include `tlv++/query/program.hpp` for `tlv::query_program` and
`tlv::query_execution`. `query_program::compile(std::string, options)` preserves
the text byte length, including embedded NUL diagnostics, and owns immutable
program storage shared by copies. `compile_into` borrows explicit aligned caller
scratch/program storage. Native sizing APIs report their exact requirements.

`query_execution::create` allocates retained workspace with explicit depth,
node and work bounds. `external(..., retained=false)` uses depth-bounded S0/S1
storage from `tlv_query_exec_size`; retained executions use `tlv_query_eval_size`.
The `environment` and all binding byte spans remain borrowed. Bind integers with
`bind(name, int64_t)` and bytes/string spans with `bind(name, bytes, string)` before
execution. No variable text is interpolated. Providers and symbolic resolvers
are the same native descriptors used by C compilation, with their native lifetime
and capability-ID requirements.

Tree execution uses `visit(reader, visitor)`. STOP returns success and resumes
after the delivered match. NEED_MORE_DATA preserves the native continuation and
is returned as a distinct status in `query_failure.code`. Retained input windows
must stay alive and immutable until execution destruction/reset. `result()` reads
a finalized typed scalar; byte/string spans borrow input, program or workspace.
`next()` pulls finalized retained node events and reports END_OF_BUFFER only at
final exhaustion. Each independent execution retains the program owner.
`next(reader)` is the single-pass resumable alternative: it stops after one
publication and reports NEED_MORE_DATA independently of final exhaustion. Scalar
programs are rejected before reading input. Copy borrowed payloads explicitly
when they must outlive the input or workspace.

`tlv++/query/builder.hpp` provides typed `query_nodes`, `query_boolean`,
`query_integer`, `query_bytes` and `query_string` expressions. Compose `where`,
`count`, `exists`, boolean operations and numeric comparisons, then call
`compile(options)`. The helper builds text and delegates all validation and
execution to C; it neither parses the language nor bypasses compiler limits.
`integer(value)` supplies a decimal comparison operand: bare digit text outside
a comparison retains the language's raw-tag meaning. Typed `variable<Kind>(name)`
references still require matching native declarations and runtime bindings.

Document `select(program)` returns an allocated vector of checked Node handles.
Evaluation completes before returning; later insertions do not appear in that
snapshot. Erasing a subtree invalidates its handles, constructed Value replacement
invalidates descendants, and unaffected handles remain valid. Native C edits are
detected using Document revisions and identities, including reused allocator
addresses. Ownership destruction makes C++ handles and associated execution
results fail safely. Borrowed Value/tag views still require callers to obey edit
lifetimes; an already returned raw span cannot be checked retroactively.

For allocation-free Document execution, initialize caller workspace, bind values,
and use `document.evaluate(execution, values, capacity, staging, context)` followed
by `document.next(execution)` or `execution.result()`. Programs that inspect
constructed Values need explicit canonical encoded snapshot storage and Writer
staging. Source metadata is unavailable on Document nodes, including edited and
inserted nodes: `@offset` and `@hlen` fail with SOURCE diagnostics. Source locations
are not invented from the canonical Value snapshot.

`tlv_document_query_edit` consumes a completed native node selection into a
caller-owned target array before editing. Capacity failure makes no tree changes.
Selected ancestors dominate descendants for remove/replace; insertion processes
every initial target once, immediately after it, in preorder. Replace means Value
replacement using the existing Format and constructed-Value parser. Replacement
bytes are copied through the Document allocator before mutation, so a Value taken
from a selected node can be used safely by that operation. Native remove cannot
fail after collection; replace/insert stop at the first failure and report the
number already applied. They provide no transaction or rollback. C++ convenience
methods are `query_remove`, `query_replace` and `query_insert_after`.

Native compiled result cursors use whole-Document revision invalidation: any
successful edit rejects subsequent pulls/scalar access before exposing stale
storage. Keep the native C Document alive until result consumption; its revision
is not a destruction token. C++ snapshots retain granular checked Node semantics.
During Query callbacks, fallible edits return INVALID_ARG and erase/free are
no-ops. Do not destroy or mutate a Document owner in a callback.

Contextual Schema assertions are defined in `tlv/schema/query.h`. Each rule
contains a compiled node context selector, a compiled boolean assertion and an
optional borrowed environment. `assert(...)` describes the Schema wrapper and
is not a new Query function. Empty context selection succeeds. `query_size`
reports the maximum selector and assertion workspaces reused across all rules;
context capacity and Reader frames are additional caller storage. Complete-buffer
validation rejects D programs before traversal; Document validation supports D.
Reader/codec errors preserve their original codes and diagnostics; false
assertions report SCHEMA with rule, selected tag and expected boolean context.
No rules explicitly skips assertion validation. Existing structural rules and
protocol/domain policies remain independent and optional.

Semantic diff is available from `tlv++/document/diff.hpp`. Correspondence is the
sequence of ancestor raw tags and one-based same-tag sibling occurrences.
Repeated-tag insertions can shift correspondence; there is no alignment heuristic.
The optional compiled selector runs once on each original complete Document.
A node selected on either side includes its original counterpart. Selected
constructed ancestors compare their own classification, with descendants compared
only when independently selected. Offsets and historical wire spelling do not
define identity. Index/result storage allocates; typed variables and provider
environments are not exposed by this minimal diff convenience surface.

The other binding Query facades still expose their existing V1 APIs. Full compiled
Rust, Python, Go, Lua and JS/WASM parity remains required before F4 (#522) closes;
these C/C++ integrations alone do not complete that phase.

## V1 exact paths

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

## Compiled deferred and Document queries

The full language uses `tlv_query_compile` and an immutable caller-stored program.
Inspect its whole-expression level and decision timing before selecting execution.
S0/S1 use `tlv_query_exec_size/init`; S2 uses `tlv_query_eval_size/init` with an
explicit capacity for every published node, including nonmatches. Deferred spans
require stable input storage across Reader windows. Reader callbacks resume after
STOP; NEED_MORE_DATA preserves execution without exposing a partial event.
The levels describe resource needs: immediate decisions (S0), decisions when a
scope closes (S1), retained input descriptors (S2), or Document navigation (D).
When `stable_input_required` is nonzero, replacing a Reader window does not release
old borrowed bytes: keep all published spans alive and immutable until execution reset.

For a compiled query on an existing Document, initialize retained execution even
when the program can also stream. First inspect `constructed_values_required` in
program info. If zero, pass NULL/zero for Value storage and NULL for Writer staging;
navigation and counting do not encode the Document.

Otherwise supply `tlv_tree_writer_workspace_t` with caller-owned frames, output
and closing scratch. `tlv_document_query_value_size` discovers the complete encoded
Document size. Resize explicitly from reported Writer requirements and repeat if
needed. Reuse its output as the final Value snapshot: evaluation encodes directly
into the supplied Value buffer and all Values borrow ranges within it. Staging
frames/scratch remain required, but staging output is ignored during evaluation.
Both discovery and execution use no Document allocation.

Then call `tlv_document_query_evaluate` with the execution, optional relative
context handle, Value buffer and Writer workspace. Pull first/all matches with
`tlv_document_query_next`, or use `tlv_document_query_program_visit` for resumable
callbacks. Scalars use `tlv_query_exec_result`. Keep the Document and Value storage
alive and unchanged through consumption. Reinitialize execution after edits or a
terminal error. Global `following`/`preceding` plans require this backend and are
rejected by Reader execution before input is consumed. Source offsets are unavailable.

The [language contract](../concepts/query-language.md#storage-and-execution)
defines ordered emission, deduplication, capacity errors and backend costs.
These compiled APIs currently have a C facade; the path APIs above retain their
existing language and binding behavior.

## Next step

Next: [codecs](codecs.md) to interpret selected Values.
