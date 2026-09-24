# Diagnostics

A result code such as `TLV_ERR_END_OF_BUFFER` says an operation failed, but
not where, on what, or why. The **diagnostic** model adds that detail as a
single, allocation-free structure that every OpenTLV layer can share instead
of inventing its own error-reporting shape.

```c
#include "tlv/diagnostic.h"

tlv_diagnostic_t diagnostic;
tlv_diagnostic_init(&diagnostic, TLV_ERR_END_OF_BUFFER, TLV_DIAGNOSTIC_SEVERITY_ERROR);
tlv_diagnostic_set_offset(&diagnostic, 42);
```

`tlv_diagnostic_t` holds a stable `code` (a `tlv_result_t`), a `severity`, an
optional byte `offset`, and borrowed `expected`/`actual` descriptions. Every
field is a fixed-size value or a borrowed pointer, so building or passing a
diagnostic never allocates.

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
`contexts` can be walked from innermost to outermost. Nothing is copied: the
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

tlv_view_t entry;
size_t     consumed;
tlv_reader_diagnostic_t diagnostic;

tlv_result_t rc = tlv_read_diag(data, size, &format, &entry, &consumed, &diagnostic);
if (rc != TLV_OK) {
    /* diagnostic.diagnostic.code   == rc
     * diagnostic.diagnostic.offset == the offset of the field that failed
     * diagnostic.operation         == which step failed (tag, length, value or trailer)
     * diagnostic.declared_length / diagnostic.available, when set, describe
     * a value or trailer that didn't fit the input */
}
```

For a tag whose declared value length exceeds the bytes left in the input,
`diagnostic.operation` is `TLV_READER_OP_VALUE`, `diagnostic.has_tag` is set,
and `declared_length`/`available` report the mismatch directly, without
having to re-parse the input to find it. Every field is a fixed-size value or
a borrowed pointer, so filling a `tlv_reader_diagnostic_t` never allocates,
and `tag` borrows the input like any tag a reader produces.

`tlv_reader_next_diag()` reports the same fields with offsets absolute within
the reader's buffer, not relative to the element being read.

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
     * diagnostic.diagnostic.offset == the output offset the element would have started at
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

Schema validation enriches a diagnostic the same way, but for every violation
it finds, not just the first: `tlv_schema_validate_all_diag()` behaves
exactly like `tlv_schema_validate_all()` (see
[Reporting every violation](schemas.md#reporting-every-violation)), and
additionally fills each recorded violation as a `tlv_schema_diagnostic_t`.

```c
#include "tlv/schema/schema.h"

tlv_schema_diagnostic_t        diagnostics[16];
tlv_schema_diagnostic_report_t report = {diagnostics, 16, 0};

tlv_result_t rc = tlv_schema_validate_all_diag(data, size, &tlv_reader_format_ber,
                                               tlv_ber_is_constructed, &template_schema, 16, 1000,
                                               TLV_SCHEMA_UNKNOWN_BY_SCHEMA, &report, &offset);
if (rc == TLV_ERR_SCHEMA) {
    for (size_t i = 0; i < report.count && i < report.capacity; ++i) {
        const tlv_schema_diagnostic_t* d = &diagnostics[i];
        char path[64];
        tlv_diagnostic_path_string(&d->path, path, sizeof(path), NULL);
        /* d->diagnostic.code   == TLV_ERR_SCHEMA_MISSING, TLV_ERR_INVALID_LENGTH or TLV_ERR_SCHEMA
         * d->diagnostic.offset == the offset of the affected element, when d->diagnostic.has_offset
         * path                == the scopes enclosing d->tag, for example "6F > A5 > BF0C > 61"
         * d->field             == the rule's schema name for d->tag, or NULL if it has none */
    }
}
```

For a value whose length is outside its rule's bounds, `d->kind` is
`TLV_SCHEMA_ISSUE_LENGTH`, `d->diagnostic.code` is `TLV_ERR_INVALID_LENGTH`,
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

`d->path` is a plain `tlv_diagnostic_path_t` value, not reachable through
`d->diagnostic.path` (which stays `NULL`): each `tlv_schema_diagnostic_t` in a
report needs its own path, and wiring it through a pointer field would leave
a dangling self-reference the moment the struct is copied out of the report
array. Attach it explicitly with `tlv_diagnostic_set_path(&d->diagnostic,
&d->path)` if code elsewhere expects to find a path on `d->diagnostic`.
`tlv_schema_validate_all()` is unchanged and still reports `tlv_schema_issue_t`
for callers that only need the tag, kind and path.

## Hierarchical paths

An offset alone does not say which branch of a nested document a diagnostic
came from: the same tag can appear at several depths. `tlv_diagnostic_path_t`
is a bounded, allocation-free stack of the tags enclosing a diagnostic,
outermost first, that a caller builds while descending into nested
constructed elements, for example with `tlv_walk_tree()`:

```c
#include "tlv/diagnostic.h"
#include "tlv/reader/walker.h"

tlv_diagnostic_path_t path;
tlv_diagnostic_path_init(&path);

tlv_visit_result_t on_element(const tlv_view_t* view, size_t depth, size_t offset, void* context) {
    while (path.length > depth) tlv_diagnostic_path_pop(&path);
    if (is_constructed(NULL, &view->tag)) tlv_diagnostic_path_push(&path, view->tag);
    /* ... validate view, using `path` as the location of the current element's parent ... */
    return TLV_VISIT_CONTINUE;
}

tlv_walk_tree(data, size, &format, is_constructed, TLV_WALK_MAX_DEPTH, SIZE_MAX, on_element, NULL,
             NULL);
```

Popping back to `depth` before pushing keeps `path` in sync with preorder
traversal: a sibling at the same depth replaces the previous element's tag,
and returning to an ancestor drops everything below it. When a diagnostic is
produced, attach the path with `tlv_diagnostic_set_path()`:

```c
tlv_diagnostic_t diagnostic;
tlv_diagnostic_init(&diagnostic, TLV_ERR_INVALID_LENGTH, TLV_DIAGNOSTIC_SEVERITY_ERROR);
tlv_diagnostic_set_offset(&diagnostic, offset);
tlv_diagnostic_set_path(&diagnostic, &path);

char text[128];
tlv_diagnostic_path_string(diagnostic.path, text, sizeof(text), NULL);
/* text == "6F > A5 > BF0C > 61" for the element enclosing the failing 4F */
```

Pushing beyond `TLV_DIAGNOSTIC_PATH_MAX` tags returns `TLV_ERR_LIMIT` and
leaves the path unchanged. Nothing is copied or allocated: a pushed tag
borrows the input like any tag a reader produces, and `path` itself must stay
valid, and unchanged, for as long as the diagnostic is used. Tracking a path
is entirely opt-in: a diagnostic that is never given one, and code that never
builds a `tlv_diagnostic_path_t`, pay nothing beyond the one `NULL` pointer in
`tlv_diagnostic_t::path`.

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
one `Error` variant per code, plus separate `SchemaError`, `ProfileError` and
`CodecError` types for layers that add context, rather than a single chained
diagnostic (see [Using OpenTLV from Rust: Error
handling](rust.md#error-handling)). Neither binds hierarchical paths or
context chaining yet.
