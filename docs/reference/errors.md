# Error codes

Every C function that can fail returns a `tlv_result_t` from `tlv/error.h`. Zero is
success and every other value is an error. `tlv_strerror` returns a static, readable
description of any code and `"unknown error"` for an unrecognized one; never free or
modify the string. The Rust `Error` type maps every `TLV_ERR_*` code.

Unless a function says otherwise, an error leaves its output parameters unchanged. A
writer also keeps its position unchanged on failure, but an encoding callback failure can
leave modified bytes beyond that position. Each function documents which codes it can
return; this page explains what each code means and what to check first.

## Codes

| Code | Value | Meaning | What to check |
| --- | --- | --- | --- |
| `TLV_OK` | 0 | The operation succeeded. | |
| `TLV_ERR_BUFFER_TOO_SHORT` | 1 | A supplied buffer is too small for the data or the output. | Reading: the input ends before the tag, length or value does (truncated input). Writing: the output capacity is smaller than `tlv_encoded_size` reports. |
| `TLV_ERR_INVALID_LENGTH` | 2 | A length is malformed, out of range, or does not fit `size_t`. | The format's length limits (for example the length width for [configurable fixed-width TLV](../formats/fixed/configurable.md), 65,535 for [Default TLV](../formats/default/README.md)), the reserved BER length prefix `FF`, or a total that overflows `size_t`. |
| `TLV_ERR_NULL_ARG` | 3 | A required pointer argument is `NULL`. | Required outputs and descriptors; `NULL` data is valid only with size zero. |
| `TLV_ERR_OUT_OF_MEMORY` | 4 | An allocation failed. | No current C core function returns it, because the core reads and writes without allocating. It is reserved for code that allocates. |
| `TLV_ERR_END_OF_BUFFER` | 5 | No further element exists, or the input is empty. | Normal end of iteration with `tlv_reader_next`; for a single read, empty input. |
| `TLV_ERR_INVALID_TAG` | 6 | A tag is malformed or invalid for the format or profile. | Unterminated multi-byte BER tags, or a tag the profile rejects. |
| `TLV_ERR_VISITOR` | 7 | A visitor callback requested an error stop. | Your visitor returned `TLV_VISIT_ERROR` or an unknown result. |
| `TLV_ERR_LIMIT` | 8 | A configured depth, size or element-count limit was exceeded. | The limits passed to the tree walker or profile function, `TLV_WALK_MAX_DEPTH` (64), `TLV_BER_MAX_DEPTH` (64). Limits are inclusive and zero is a real limit. |
| `TLV_ERR_SCHEMA` | 9 | Input violates a schema rule. | The error offset points at the offending element: a forbidden or unknown tag, a duplicate or excess occurrence, a kind mismatch, or an invalid rule table. |
| `TLV_ERR_INVALID_ARG` | 10 | An argument has an invalid value that no more specific code describes. | A required callback missing from a format descriptor, or an invalid option value. |
| `TLV_ERR_INVALID_TAG_SIZE` | 11 | A tag size is outside the range the operation or format supports. | A tag length the selected format rejects (for example more than 8 bytes for BER, CER and DER, or anything but one byte for the default format), or an empty tag where the operation needs bytes. Also the numeric tag conversions for empty tags and tags longer than 8 bytes. `tlv_tag_t` itself has no size limit. |
| `TLV_ERR_INVALID_BYTE_ORDER` | 12 | A byte order is unknown or unsupported. | The `TLV_BYTE_ORDER_*` value passed to the integer conversion functions in `tlv/endian.h` and `tlv/tag.h`, or `tlv_fixed_config_t.order` in [configurable fixed-width TLV](../formats/fixed/configurable.md). |
| `TLV_ERR_OVERFLOW` | 13 | An unsigned value cannot fit the requested numeric width. | The value against the destination width in the same integer conversion functions. |
| `TLV_ERR_INVALID_VALUE` | 14 | Universal primitive content is malformed or fails a canonical DER rule. | Strict DER or CER functions and schema-aware DER validation: for example a noncanonical BOOLEAN, INTEGER, string or time value, or a wrongly ordered SET. |
| `TLV_ERR_UNSUPPORTED_TYPE` | 15 | A universal tag number has no implemented canonical validation. | Strict mode returns this instead of silently accepting a type it does not check; see the list in the [DER profile](../profiles/der/README.md#strict-universal-value-validation). |
| `TLV_ERR_SCHEMA_MISSING` | 16 | A required field is absent. | Its offset is the end of the enclosing parent's value, not an element; see below. |

## Offsets and diagnosis

Several APIs report an `error_offset` that is changed only on failure. For the DER profile
functions it identifies the start of the failing field, relative to the input: tag
errors point to the tag, length errors to the length prefix, and truncated values to their
value start, including missing fields at the end of the input. Value-size limits point to
the length field and depth or count limits to the first disallowed element. Argument,
configuration, total-size and destination-capacity errors use offset zero. The CER profile
reports its own `error_offset`; see the [CER profile](../profiles/cer/README.md).

`TLV_ERR_SCHEMA_MISSING` is different from `TLV_ERR_SCHEMA`: its offset is the end of the
parent's value, a scope boundary, and can coincide with the start of an unrelated sibling,
so a tag read there is not reliably the cause. Every other schema violation returns
`TLV_ERR_SCHEMA` with an offset anchored to the actual element.

Custom format callback errors propagate unchanged through the generic reader and writer,
so a custom format can return any of the codes above.

## See also

- [C API reference](c-api.md) for the documented codes per function.
- [Format documentation](../formats/README.md#reading-one-element) for the reader and
  writer error behavior.
- [Scanning and recovery](../guides/scanner.md) for continuing after an error.
