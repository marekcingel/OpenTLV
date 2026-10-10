# Diagnostics

Prerequisite: Complete a [first program](../getting-started/README.md#quick-start) and check operation results.

```text
operation failure --> error code + optional source context
```

A result code such as `TLV_ERR_TRUNCATED` says an operation failed, but
not where, on what, or why. The **diagnostic** model adds that detail as a
single, allocation-free structure that every OpenTLV layer can share instead
of inventing its own error-reporting shape.

```c
#include "tlv/diagnostic.h"

tlv_diagnostic_t diagnostic;
tlv_diagnostic_init(&diagnostic, TLV_ERR_TRUNCATED, TLV_DIAGNOSTIC_SEVERITY_ERROR);
tlv_diagnostic_set_location(&diagnostic, TLV_LOCATION_INPUT, TLV_LOCATION_POINT, 42, 42);
```

`tlv_diagnostic_t` holds a stable `code` (a `tlv_result_t`), a `severity`, a
primary `location`, an optional inline enclosing path, and borrowed `expected`/`actual` descriptions. Every
field is a fixed-size value or a borrowed pointer, so building or passing a
diagnostic never allocates.

## Evidence locations

`location.kind == TLV_LOCATION_UNKNOWN` means there is no known position. A
POINT at zero is known evidence; never use zero or `SIZE_MAX` as an absence
sentinel. SPAN is half-open `[begin, end)` and may be empty at EOF. SCOPE_END
and INSERTION describe missing content without claiming an element exists there.

The domain is INPUT, OUTPUT, EXPRESSION, DEFINITION or VALUE. Each operation
defines the source and origin: Reader input coordinates include discarded windows;
Writer and DER write coordinates describe would-be output; Query parse spans
index expression bytes. Query runtime errors may carry primary INPUT evidence
and retain a separate related expression span in `begin`/`end`. VALUE is local
evidence whose enclosing wire origin is unavailable. Native Schema definitions
use `definition.kind`, `definition.owner` and `definition.index`, not invented
wire offsets. The owner borrows the supplied table/type.

`tlv_location_translate()` checks both bounds. Overflow clears only the optional
location and preserves the original result and detail. Diagnostics remain optional;
requesting them does not add a second parse or callback invocation.

The offset-only failure outputs and Schema-specific anchor enum were removed.
Use the structured diagnostic parameters on Query paths, Tree visitors, Document,
DER/CER, Bluetooth AD and DOL APIs. Rebuild native clients and every binding after
this source and ABI change; there are no compatibility wrappers.

## Layering context

A lower layer produces a diagnostic; higher layers add detail without
changing what it already says, by chaining caller-owned
`tlv_diagnostic_context_t` entries onto it:

```c
tlv_diagnostic_context_t ber_context;
tlv_diagnostic_add_context(&diagnostic, &ber_context, "ber", "declared_length", "6");

tlv_diagnostic_context_t schema_context;
tlv_diagnostic_add_context(&diagnostic, &schema_context, "schema", "field", "AmountAuthorised");
```

This chaining is available to any layer, but schema validation itself reports
its own violations directly as a `tlv_schema_diagnostic_t` with typed fields
rather than chained context strings; see [Schema diagnostics](#schema-diagnostics).

`tlv_diagnostic_add_context()` links `context` onto the front of
`diagnostic->contexts`, so the most recently added context is innermost and
`contexts` can be traversed from innermost to outermost. Nothing is copied: the
caller supplies storage for each context node and its `layer`, `key` and
`value` strings, and that storage must outlive the diagnostic.

## Reader diagnostics

The reader is the first layer to enrich a diagnostic: `tlv_read_diag()` and
`tlv_reader_next_diag()` behave exactly like `tlv_read()` and
`tlv_reader_next()`, and additionally fill an optional
`tlv_reader_diagnostic_t` when parsing fails, so the existing lightweight
functions remain usable without paying for diagnostics.

```c
#include "tlv/reader/reader.h"

tlv_element_t element;
size_t     consumed;
tlv_reader_diagnostic_t diagnostic;

tlv_result_t rc = tlv_read_diag(data, size, &format, &element, &consumed, &diagnostic);
if (rc != TLV_OK) {
    /* diagnostic.diagnostic.code   == rc
     * diagnostic.diagnostic.location.begin == the offset of the field that failed
     * diagnostic.detail.operation         == which step failed (tag, length, value or trailer)
     * diagnostic.detail.declared_length / diagnostic.detail.available, when set, describe
     * a value or trailer that didn't fit the input */
}
```

For a tag whose declared value length exceeds the bytes left in the input,
`diagnostic.detail.operation` is `TLV_READER_OP_VALUE`, `diagnostic.detail.has_tag` is set,
and `declared_length`/`available` report the mismatch directly, without
having to re-parse the input to find it. Every field is a fixed-size value or
a borrowed pointer, so filling a `tlv_reader_diagnostic_t` never allocates,
and `tag` borrows the input like any tag a reader produces.

`tlv_reader_next_diag()` reports the same fields with offsets absolute within
the reader's buffer, not relative to the element being read.

Reader-specific evidence lives in `tlv_reader_detail_t`. A standalone Reader
failure pairs it with one common diagnostic as `diagnostic` and `detail`.
Query embeds the same detail as `reader`, guarded by `has_reader`, while
`query.diagnostic` is the sole result, location and path for the failure.
Reader causes remain present under Query `STATE`; pure Query failures leave
`has_reader` unset. Neither representation contains self-referential pointers.

## Writer diagnostics

The writer enriches a diagnostic the same way: `tlv_write_diag()` and
`tlv_writer_write_diag()` behave exactly like `tlv_write()` and
`tlv_writer_write()`, and additionally fill an optional
`tlv_writer_diagnostic_t` when encoding fails.

```c
#include "tlv/writer/writer.h"

size_t written;
tlv_writer_diagnostic_t diagnostic;

tlv_result_t rc = tlv_write_diag(data, capacity, &format, tag, value, length, &written,
                                 &diagnostic);
if (rc != TLV_OK) {
    /* diagnostic.diagnostic.code   == rc
     * diagnostic.diagnostic.location.begin == the output offset the element would have started at
     * diagnostic.operation         == which step failed (tag, length or value)
     * diagnostic.length            == the value length that was requested
     * diagnostic.required / diagnostic.available, when set, describe an
     * element that didn't fit the destination */
}
```

For a tag that requires more bytes than remain in the destination,
`diagnostic.operation` is `TLV_WRITER_OP_VALUE`, `diagnostic.has_tag` is set,
and `required`/`available` report the mismatch directly: writing tag `5F2A`
that needs 5 bytes with only 3 remaining fills `diagnostic.required` with `5`
and `diagnostic.available` with `3`. Every field is a fixed-size value or a
borrowed pointer, so filling a `tlv_writer_diagnostic_t` never allocates, and
`tag` borrows the tag passed to the failing call.

`tlv_writer_write_diag()` reports the same fields with the offset absolute
within the writer's buffer, not relative to the element being written.

## Schema diagnostics

Schema validation records every violation through `tlv_schema_validate_all_diag()`
as a `tlv_schema_diagnostic_t`; see
[Reporting every violation](schemas.md#reporting-every-violation).

```c
#include "tlv/schema/schema.h"

tlv_schema_diagnostic_t        diagnostics[16], failure;
tlv_schema_diagnostic_report_t report = {diagnostics, 16, 0};

tlv_result_t rc = tlv_schema_validate_all_diag(data, size, &tlv_format_ber, &template_schema, 16,
                                               1000, TLV_SCHEMA_UNKNOWN_BY_SCHEMA, &report,
                                               &failure);
if (rc == TLV_ERR_SCHEMA) {
    for (size_t i = 0; i < report.count && i < report.capacity; ++i) {
        const tlv_schema_diagnostic_t* d = &diagnostics[i];
        char path[64];
        tlv_diagnostic_path_string(&d->diagnostic.path, path, sizeof(path), NULL);
        /* d->diagnostic.code   == TLV_ERR_SCHEMA; kind distinguishes missing, length and other findings
         * d->diagnostic.location.begin == the offset of the affected element, when d->diagnostic.location.kind != TLV_LOCATION_UNKNOWN
         * path                == the scopes enclosing d->tag, for example "6F > A5 > BF0C > 61"
         * d->field             == the rule's schema name for d->tag, or NULL if it has none */
    }
}
```

For a value whose length is outside its rule's bounds, `d->kind` is
`TLV_SCHEMA_ISSUE_LENGTH`, `d->diagnostic.code` is `TLV_ERR_SCHEMA`,
and `d->has_length` is set, with `min_length`/`max_length` from the rule and
`actual_length` from the value that violated it: validating a 4F (ADF Name)
with only 3 bytes against a rule requiring 5 to 16 fills `min_length` with
`5`, `max_length` with `16`, and `actual_length` with `3`. A missing or
duplicate tag instead sets `has_occurs`, with `min_occurs`/`max_occurs` from
the rule and `occurs` the number found; a primitive/constructed mismatch sets
`has_form`, with `expected_form` from the rule and `actual_constructed`
reporting what the value actually was. Only the fields for `kind` are set; the
others are left zero. `field` and the fields for other kinds are `NULL` or
unset for `TLV_SCHEMA_ISSUE_UNEXPECTED`, which matches no rule.

The common base stores `path` by value, with `has_path` distinguishing an
untracked path from a known empty path. Copying a diagnostic needs no rebasing.
Tag spans still borrow their bytes; bindings copy those bytes before releasing
the source. A nonzero `path.omitted` records truncated inner ancestry.

## Hierarchical paths

An offset alone does not say which branch of a nested document a diagnostic
came from: the same tag can appear at several depths. `tlv_diagnostic_path_t`
is a bounded, allocation-free stack of the tags enclosing a diagnostic,
outermost first, that a caller builds while descending into nested
constructed elements, for example with `tlv_tree_reader_visit()`:

```c
#include "tlv/diagnostic.h"
#include "tlv/reader/visitor.h"

tlv_diagnostic_path_t path;
tlv_diagnostic_path_init(&path);

tlv_visit_result_t on_element(const tlv_element_t* element, size_t depth, size_t offset, void* context) {
    while (path.length > depth || path.omitted > depth - path.length)
        tlv_diagnostic_path_pop(&path);
    if (format.is_constructed(format.context, &element->tag)) {
        tlv_result_t rc = tlv_diagnostic_path_push(&path, element->tag);
        /* BUFFER_TOO_SHORT records an omitted tag; traversal can still continue. */
        if (rc != TLV_OK && rc != TLV_ERR_BUFFER_TOO_SHORT) return TLV_VISIT_STOP;
    }
    /* ... validate element, using `path` as the location of the current element's parent ... */
    return TLV_VISIT_CONTINUE;
}

tlv_tree_frame_t frames[TLV_TREE_DEFAULT_DEPTH];
tlv_tree_reader_t reader;
if (tlv_tree_reader_init(&reader, data, size, &format, frames, TLV_TREE_DEFAULT_DEPTH,
                         TLV_TREE_DEFAULT_DEPTH, SIZE_MAX) == TLV_OK)
    tlv_tree_reader_visit(&reader, on_element, NULL, NULL);
```

Popping back to `depth` before pushing keeps `path` in sync with preorder
traversal: a sibling at the same depth replaces the previous element's tag,
and returning to an ancestor drops everything below it. When a diagnostic is
produced, attach the path with `tlv_diagnostic_set_path()`:

```c
tlv_diagnostic_t diagnostic;
tlv_diagnostic_init(&diagnostic, TLV_ERR_INVALID_LENGTH, TLV_DIAGNOSTIC_SEVERITY_ERROR);
tlv_diagnostic_set_location(&diagnostic, TLV_LOCATION_INPUT, TLV_LOCATION_POINT, offset, offset);
tlv_diagnostic_set_path(&diagnostic, &path);

char text[128];
tlv_diagnostic_path_string(&diagnostic.path, text, sizeof(text), NULL);
/* text == "6F > A5 > BF0C > 61" for the element enclosing the failing 4F */
```

Every path producer retains the outermost `TLV_DIAGNOSTIC_PATH_MAX` tags (32).
Pushing beyond that capacity returns `TLV_ERR_BUFFER_TOO_SHORT`, preserves the retained
tags and increments `path.omitted`, the number of omitted innermost tags
(saturating at `SIZE_MAX`). A pop consumes an omitted tag before removing a
retained tag, so returning from a deep subtree restores the correct parent.
Initialization clears both counts. Formatted truncated paths end in `> ...`;
CLI JSON diagnostics also include `path_omitted` when nonzero. The full logical
depth is `length + omitted` when that sum is representable.

Structural Schema reports and buffer/Document Schema Query assertions use the
same root-prefix policy. Their affected tag remains separate from the enclosing
path. Diagnostic capacity does not reduce Schema's structural depth limit.
Adding `omitted` changes the public path and embedding Schema diagnostic ABI;
rebuild native clients and bindings against the updated headers/library.

Attaching a path copies its bounded value. The original path object can be
changed or destroyed after attachment, while the Tag bytes must remain alive.
Path collection is opt-in, but inline path capacity contributes to every common
diagnostic's size. No diagnostic allocates memory.

## Scope

The core `tlv_diagnostic_t` type is independent of any wire format, schema or
protocol, so it carries no BER-, EMV- or CLI-specific fields; those layers
attach their own detail through `contexts` instead. Rendering a diagnostic
for humans is a separate concern and is not part of this type.

## Other languages

Python and Rust do not expose a shared `tlv_diagnostic_t`-shaped type; each
reports failures in its own idiomatic error model instead. Python raises an
`OpenTLVError` subclass per `TLV_ERR_*` code, with `offset`, `expected`,
`actual`, `operation` and `tag` fields carrying the same detail a reader or
writer diagnostic would (see [Using OpenTLV from Python: Error
handling](python.md#error-handling)). Rust returns a `Result<T, Error>` with
one `Error` variant per code, plus separate `SchemaError`, `ValidationError` and
`CodecError` types for layers that add context, rather than a single chained
diagnostic (see [Using OpenTLV from Rust: Error
handling](rust.md#error-handling)). Schema reports own copied paths in both bindings; Rust Reader detail also copies
tracked common paths. Location domain, kind and bounds are available directly.

Reader diagnostics preserve `declared_length` as a 64-bit `tlv_size_t`, even
when the value does not fit the supplied buffer or native address space.
When `has_raw_length` is set, `raw_length` borrows the original length-field
bytes (the available prefix if truncated). This also works for malformed,
nonminimal and logically overflowing length encodings. Keep the input alive
and unchanged while using this diagnostic. CLI diagnostics expose these bytes
as `raw_length` in hexadecimal.

## Next step

Next: [error reference](../reference/errors.md) for exact codes.
