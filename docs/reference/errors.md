# Error codes

This page describes the **currently implemented API**. The accepted
[failure model](../concepts/error-model.md) (#551) defines a replacement taxonomy,
typed diagnostic layering, locations and propagation rules. Its implementation
will break API and ABI compatibility; the target names and signatures are not
available yet, except for `TLV_ERR_INVALID_STATE` and Query kind `STATE` (#552),
and `TLV_ERR_INVALID_SCHEMA` with Schema failure classification (#553). The
tables below describe the current codes and behavior.

Core operations return a `tlv_result_t` from `tlv/error.h`; Codec operations
currently have a separate `tlv_codec_result_t`. Zero is success; nonzero core
results include errors, end-of-input and the resumable
`TLV_NEED_MORE_DATA` condition. `tlv_strerror` returns a static, readable
description of any code and `"unknown error"` for an unrecognized one; never free or
modify the string. The Rust `Error` type maps every `TLV_ERR_*` code.

Unless a function says otherwise, an error leaves its output parameters unchanged. A
writer also keeps its position unchanged on failure, but an encoding callback failure can
leave modified bytes beyond that position. Each function documents which codes it can
return; this page explains what each code means and what to check first.

## Result and diagnostic invariant

When an API initializes a non-NULL diagnostic output, every subsequent non-OK
return describes that result:

- `tlv_diagnostic_t` and the active diagnostic in an embedding type have
  `diagnostic.code == rc`.
- `tlv_query_diagnostic_t` has `kind != TLV_QUERY_ERROR_NONE`. A `READER` detail
  also has `reader.diagnostic.code == rc`; a `CODEC` detail has a non-OK codec result.
- An initialized Query diagnostic for `TLV_ERR_INVALID_STATE` has kind
  `TLV_QUERY_ERROR_STATE`. Pre-initialization preservation exceptions below still apply.
- Schema Query has alternative detail channels: a false assertion sets
  `schema.diagnostic.code`, while an execution failure fills `query`.

The rule includes `TLV_ERR_END_OF_BUFFER` and `TLV_NEED_MORE_DATA` when returned
through an initialized diagnostic channel. These are still normal iteration or
resumption conditions where the API says so. Query represents resumable Reader
status as `READER`; this does not poison the execution.

Diagnostics are failure outputs, so the general unchanged-output rule above does
not prevent filling them on failure. A successful call need not clear an old
diagnostic; inspect it only in conjunction with the returned result. Report
collections describe individual findings, rather than repeating an aggregate
validation result in every entry.

Pre-initialization checks leave the diagnostic untouched. In particular:

- Query overlap checks protect borrowed input and execution storage. Reentrant
  calls and rejected continuations of failed executions preserve the outer or
  original failure. Do not move initialization ahead of these guards.
- Compiler prepare/commit/load entry points can reject required arguments,
  output extents, alignment or overlapping storage before their first diagnostic
  initialization (including initialization by a delegated compiler call).
- Low-level Reader/Tree and Schema entry points can reject preflight arguments
  or resources before producing detail. An enclosing API which has already
  initialized its own diagnostic must nevertheless describe a propagated error.

Query now uses `STATE` for lifecycle/reentrancy failures and `EVENTS` with
`INVALID_VALUE` for invalid structural feeds. Until the remaining
[failure-model migration](../concepts/error-model.md#migration-inventory),
`STORAGE` still covers compiler/plan arguments and capacities, `BINDING` covers
binding arguments, `CAPABILITY` covers incompatible formats or hook configuration,
and `EVENTS` also covers visitor/callback failures. Diagnostic layouts are unchanged.

### Regression enforcement

`tests/diagnostic_assertions.h` checks the invariant after an operation, including
calls shared by table-driven Query tests. Tests for pre-initialization rejection
instead verify that protected outputs remain unchanged.

Run `python scripts/test_diagnostic_returns.py` and
`python scripts/check_diagnostic_returns.py` for the CI source guard. The guard
reports direct error returns after explicit diagnostic initialization in C
functions with a diagnostic output. A directly populated return requires an
adjacent `diagnostic-return:` comment explaining where its detail was set.
This lexical check is deliberately conservative: indirect initialization,
propagated variables and callback behavior require runtime tests; it is not a
control-flow proof. A separate lexical rule rejects `INVALID_ARG` returns under
`busy`, `finished`, `invalid` or `query_callbacks` member predicates, including
pre-initialization checks. Diagnostic-return comments do not waive that rule.

## Codes

Numbers below describe this release. They are not stable ABI identifiers during
the breaking #551 migration; `INVALID_STATE = 19` does not promise append-only enums.

| Code | Value | Meaning | What to check |
| --- | --- | --- | --- |
| `TLV_OK` | 0 | The operation succeeded. | |
| `TLV_ERR_BUFFER_TOO_SHORT` | 1 | A supplied buffer is too small for the data or the output. | Reading: more bytes are required to complete the header, value or trailer (incomplete input). Writing: the output capacity is smaller than `tlv_encoded_size` reports. |
| `TLV_ERR_INVALID_LENGTH` | 2 | A length is malformed or invalid for the wire encoding. | The format's length limits (for example the length width for [configurable fixed-width TLV](../formats/fixed/configurable.md)), or the reserved BER length prefix `FF`. |
| `TLV_ERR_NULL_ARG` | 3 | A required pointer argument is `NULL`. | Required outputs and descriptors; `NULL` data is valid only with size zero. |
| `TLV_ERR_OUT_OF_MEMORY` | 4 | An owning operation could not obtain storage. | Document allocation and allocation-size checks. Caller-supplied workspace exhaustion can currently use other codes; see the target failure model for the planned distinction. |
| `TLV_ERR_END_OF_BUFFER` | 5 | No further element exists, or the input is empty. | Normal end of iteration with `tlv_reader_next`; for a single read, empty input. |
| `TLV_ERR_INVALID_TAG` | 6 | A tag is malformed or invalid for the format or standard. | Malformed BER identifier digits, or a tag the selected format rejects. Incomplete identifiers return `TLV_ERR_BUFFER_TOO_SHORT`. |
| `TLV_ERR_VISITOR` | 7 | A visitor callback requested an error stop. | Your visitor returned `TLV_VISIT_ERROR` or an unknown result. |
| `TLV_ERR_LIMIT` | 8 | A configured depth, size or element-count limit was exceeded. | The limits passed to the Tree Reader or validation function, available frame capacity, `TLV_BER_MAX_DEPTH` (64). Limits are inclusive and zero is a real limit. |
| `TLV_ERR_SCHEMA` | 9 | Input violates a valid schema. | Missing or forbidden fields, excess occurrences, kind/order mismatches, and length or Value constraints. Schema detail identifies the reason, including `MISSING`. |
| `TLV_ERR_INVALID_ARG` | 10 | An argument has an invalid value that no more specific code describes. | A required callback missing from a format descriptor, or an invalid option value. |
| `TLV_ERR_INVALID_TAG_SIZE` | 11 | A tag size is outside the range the operation or format supports. | A tag length the selected format rejects (for example more than 8 bytes for BER, CER and DER, or a tag width different from the configured Fixed width), or an empty tag where the operation needs bytes. Also the numeric tag conversions for empty tags and tags longer than 8 bytes. `tlv_tag_t` itself has no size limit. |
| `TLV_ERR_INVALID_BYTE_ORDER` | 12 | A byte order is unknown or unsupported. | The `TLV_BYTE_ORDER_*` value passed to the integer conversion functions in `tlv/endian.h` and `tlv/tag.h`, or `tlv_fixed_format_t.length.byte_order` in [configurable fixed-width TLV](../formats/fixed/configurable.md). |
| `TLV_ERR_OVERFLOW` | 13 | An unsigned value cannot fit the requested numeric width, or logical size arithmetic overflows. | The value against the destination width in the same integer conversion functions. |
| `TLV_ERR_INVALID_VALUE` | 14 | Content or its interpretation is invalid. | DER/CER canonical Value checks and SET ordering; Query codec, scalar cardinality and unavailable Source metadata failures; malformed structural event streams. |
| `TLV_ERR_UNSUPPORTED_TYPE` | 15 | A type, Query capability or program-image version is unsupported. | Strict ASN.1 validation rejects unchecked types; see [DER validation](../standards/der/README.md#strict-universal-value-validation). Query also uses this code outside ASN.1; Schema definition checks use it for valid graphs exceeding fixed checking capacity. |
| `TLV_ERR_INVALID_SCHEMA` | 16 | A schema definition is invalid independently of input. | Constraint kinds and bounds, required references, rule/group tables and DER type definitions. |
| `TLV_ERR_NATIVE_SIZE` | 17 | A logical size exceeds the native address space. | Checked conversion to `size_t`; the logical quantity itself remains valid. |
| `TLV_NEED_MORE_DATA` | 18 | Incremental input is exhausted or incomplete. | Supply an extended window or declare EOF. No element is published and the cursor does not advance. |
| `TLV_ERR_INVALID_STATE` | 19 | The operation is forbidden by the current lifecycle state. | Reset a failed or used Query execution before reuse; leave the callback before mutating; close Tree Writer parents before finishing; only skip a pending Reader subtree. Stale Document results also use this code. |

### Arguments versus lifecycle state

`TLV_ERR_INVALID_STATE` distinguishes lifecycle/reentrancy rejection from
`TLV_ERR_INVALID_ARG`, which still describes bad arguments, configuration,
and overlap. Malformed structural event input uses `TLV_ERR_INVALID_VALUE`;
new Query state diagnostics use `TLV_QUERY_ERROR_STATE`.
A state rejection does not bypass pre-initialization guards: callback reentrancy
and rejected continuation of failed executions preserve protected outputs and
the original diagnostic. Repeated successful Query finish and normal iterator
exhaustion retain their existing behavior. Reader input may be relocated after
EOF, but cannot be reopened or extended.

The node-only Tree Writer source callback returning impossible preorder depth
still reports `INVALID_ARG`. Reclassifying callback contract violations to the
planned `CALLBACK` result is separate follow-up work.

## Offsets and diagnosis

Diagnostic paths retain the outermost 32 enclosing tags. `path.omitted` counts
innermost tags that did not fit; zero means the path is complete. Path text
marks omissions with `> ...`. The affected tag is still available separately
in Schema diagnostics. See [Hierarchical paths](../guides/diagnostics.md#hierarchical-paths).

`tlv_der_schema_write()` reports schema/value failures relative to the would-be
DER output, accounting for enclosing headers and canonical SET ordering. A
missing required SEQUENCE component points where it would start; a missing SET
component points to the enclosing content end. For an empty SEQUENCE the offset
is 2. Leaf constraints point to the Value bytes. Argument, configuration and
capacity failures have unknown byte location. When a diagnostic is requested,
composition can visit remaining components after detecting a failure. If a
later callback or scratch failure prevents completing the hypothetical encoding,
the original result and detail are retained with unknown byte location. The destination and `written`
remain unchanged on failure.

Several APIs report an `error_offset` that is changed only on failure. For the DER validation
functions it identifies the start of the failing field, relative to the input: tag
errors point to the tag, length errors to the length prefix, and truncated values to their
value start, including missing fields at the end of the input. Value-size limits point to
the length field and depth or count limits to the first disallowed element. Argument,
configuration, total-size and destination-capacity errors use offset zero. The CER validation
reports its own `error_offset`; see the [CER validation](../standards/cer/README.md).

Schema validators distinguish invalid definitions (`TLV_ERR_INVALID_SCHEMA`) from
valid definitions rejecting input (`TLV_ERR_SCHEMA`). Length constraints are Schema
violations; malformed wire Length encodings still use `TLV_ERR_INVALID_LENGTH`.
Missing required fields, groups, DHCP End and DER components/root use `SCHEMA`
with `TLV_SCHEMA_ISSUE_MISSING`, consistently across generic Schema and builtins.
`TLV_ERR_SCHEMA_MISSING` has been removed without an alias.

`tlv_schema_validate()`, DER schema check/read/write, LLDP and DHCP container
validation return `tlv_schema_diagnostic_t` detail when requested. Its `anchor`
distinguishes an existing element, scope end, insertion point and unknown position.
A missing field is not an element at its anchor; never decode a tag there to
explain the failure. Generic report findings now use scope end for missing fields,
including known offset zero for an empty root. Definition failures have no input
byte location. The remaining offset-only APIs migrate separately under #555.

The Schema diagnostic layout and affected signatures changed in #553. Rebuild
native clients and use the matching binding version. C++ errors expose
`schema_kind()` and `anchor()`; Python uses `InvalidSchemaError` for definitions
and `SchemaError` with `kind="missing"` for required absence.

Custom format callback errors propagate unchanged through the generic reader and writer,
so a custom format can return any of the codes above.

## See also

- [C API reference](c-api.md) for the documented codes per function.
- [Format documentation](../formats/README.md#reading-one-element) for the reader and
  writer error behavior.
- [Pull-based reading](../guides/reader.md) for end, incomplete input and parsing errors.
