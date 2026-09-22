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

## Scope

The core `tlv_diagnostic_t` type is independent of any wire format, schema or
protocol, so it carries no BER-, EMV- or CLI-specific fields; those layers
attach their own detail through `contexts` instead. Rendering a diagnostic
for humans is a separate concern and is not part of this type.
