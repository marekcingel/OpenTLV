# Error codes

This page describes the **currently implemented API**. The accepted
[failure model](../concepts/error-model.md) (#551) defines a replacement taxonomy,
typed diagnostic layering, locations and propagation rules. Migration proceeds
through breaking API and ABI changes: lifecycle (#552),
Schema classification (#553), resource/callback classification (#554), locations
(#555), shared Codec results and propagation (#556), diagnostic names and
Document lookup failure channels (#557), and the `END`, `TRUNCATED` and
`SYNTAX` results (#578). The tables below describe the current
codes, not target names still awaiting implementation.

Core and Codec operations return the shared `tlv_result_t` from `tlv/error.h`. Zero is success. `TLV_END` (normal end
of iteration) and `TLV_NEED_MORE_DATA` (resumable non-final input) are control
statuses, not failures; every other nonzero result is a failure. `tlv_strerror` returns a static, readable
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
  sets `has_reader` and stores its result, location and path only in `diagnostic`; a `CODEC` detail has a non-OK codec result.
- An initialized Query diagnostic for `TLV_ERR_INVALID_STATE` has kind
  `TLV_QUERY_ERROR_STATE`. Pre-initialization preservation exceptions below still apply.
- Schema Query has alternative detail channels: a false assertion sets
  `schema.diagnostic.code`, while an execution failure fills `query`.

The rule includes `TLV_END` and `TLV_NEED_MORE_DATA` when returned
through an initialized diagnostic channel; their severity is `INFO`, not `ERROR`. These are still normal iteration or
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
while visitor/provider failures use `CALLBACK`. Diagnostic layouts changed in
issues #553, #555 and #556; rebuild native consumers with matching headers and bindings.

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

Codes are grouped by category: success, control statuses, invalid input data,
invalid use of the API, capacity, resources and numeric ranges, capabilities,
and callbacks. Numbers below describe this release. Before 1.0.0 they are not
stable ABI identifiers and may change to keep categories together.

| Code | Value | Meaning | What to check |
| --- | --- | --- | --- |
| `TLV_OK` | 0 | The operation succeeded. | |
| `TLV_END` | 1 | Control status: normal end of iteration, or an empty single-read region. Not a failure. | `tlv_reader_next` and other iterators after the last element; `tlv_read` on empty input. No element is published. |
| `TLV_NEED_MORE_DATA` | 2 | Control status: incremental input is exhausted or incomplete. | Supply an extended window or declare EOF. No element is published and the cursor does not advance. |
| `TLV_ERR_TRUNCATED` | 3 | Final input ends inside a required representation. | Supply complete input; a larger output buffer cannot help. Non-final Reader input reports `TLV_NEED_MORE_DATA` for the same cut. |
| `TLV_ERR_INVALID_TAG` | 4 | A tag is malformed or invalid for the format or standard. | Malformed BER identifier digits, or a tag the selected format rejects. Incomplete identifiers return `TLV_ERR_TRUNCATED`. |
| `TLV_ERR_INVALID_TAG_SIZE` | 5 | A tag size is outside the range the operation or format supports. | A tag length the selected format rejects (for example more than 8 bytes for BER, CER and DER, or a tag width different from the configured Fixed width), or an empty tag where the operation needs bytes. Also the numeric tag conversions for empty tags and tags longer than 8 bytes. `tlv_tag_t` itself has no size limit. |
| `TLV_ERR_INVALID_LENGTH` | 6 | A length is malformed or invalid for the wire encoding. | The format's length limits (for example the length width for [configurable fixed-width TLV](../formats/fixed/configurable.md)), or the reserved BER length prefix `FF`. |
| `TLV_ERR_INVALID_VALUE` | 7 | Content or its interpretation is invalid. | DER/CER canonical Value checks and SET ordering; Query operand types, variable bindings, malformed images, invalid converted Values and scalar cardinality; malformed structural event streams. Configuration and provider contract violations use separate results. |
| `TLV_ERR_SYNTAX` | 8 | Text does not match the requested grammar. | Query expressions and V1 paths. Query diagnostics pair it with kind `SYNTAX` and an expression span. |
| `TLV_ERR_SCHEMA` | 9 | Input violates a valid schema. | Missing or forbidden fields, excess occurrences, kind/order mismatches, and length or Value constraints. Schema detail identifies the reason, including `MISSING`. |
| `TLV_ERR_NULL_ARG` | 10 | A required pointer argument is `NULL`. | Required outputs and descriptors; `NULL` data is valid only with size zero. |
| `TLV_ERR_INVALID_ARG` | 11 | An API configuration or argument descriptor is invalid. | A required callback missing from a format descriptor, an invalid option value, or an unknown `TLV_BYTE_ORDER_*` value. |
| `TLV_ERR_INVALID_STATE` | 12 | The operation is forbidden by the current lifecycle state. | Reset a failed or used Query execution before reuse; leave the callback before mutating; close Tree Writer parents before finishing; only skip a pending Reader subtree. Stale Document results also use this code. |
| `TLV_ERR_INVALID_SCHEMA` | 13 | A schema definition is invalid independently of input. | Constraint kinds and bounds, required references, rule/group tables and DER type definitions. |
| `TLV_ERR_BUFFER_TOO_SHORT` | 14 | A caller-supplied destination or workspace is too small. | Writing: the output capacity is smaller than `tlv_encoded_size` reports; also frame arrays, arenas and scratch. Never used for incomplete input. |
| `TLV_ERR_LIMIT` | 15 | A configured depth, size or element-count limit was exceeded. | The limits passed to the Tree Reader or validation function, `TLV_BER_MAX_DEPTH` (64). Limits are inclusive and zero is a real limit. |
| `TLV_ERR_OVERFLOW` | 16 | An unsigned value cannot fit the requested numeric width, or logical size arithmetic overflows. | The value against the destination width in the same integer conversion functions. |
| `TLV_ERR_NATIVE_SIZE` | 17 | A logical size exceeds the native address space. | Checked conversion to `size_t`; the logical quantity itself remains valid. |
| `TLV_ERR_OUT_OF_MEMORY` | 18 | An owning operation could not obtain storage. | Document allocation and allocation-size checks. Caller-supplied workspace exhaustion uses `BUFFER_TOO_SHORT`. |
| `TLV_ERR_UNSUPPORTED` | 19 | A type, Query capability or program-image version is unsupported. | Strict ASN.1 validation rejects unchecked types; see [DER validation](../standards/der/README.md#strict-universal-value-validation). Query also uses this code outside ASN.1; Schema definition checks use it for valid graphs exceeding fixed checking capacity. |
| `TLV_ERR_VISITOR` | 20 | A visitor callback requested an error stop. | Your visitor returned `TLV_VISIT_ERROR`. Unknown visitor results produce `CALLBACK`. |
| `TLV_ERR_CALLBACK` | 21 | A callback violates its declared contract. | Invalid discriminator or success payload; correct the provider. Legitimate provider failures keep their original result. |

### End, truncated input and buffer capacity

These outcomes need different responses and never share a code:

| Situation | Result |
| --- | --- |
| Final input, no further element | `TLV_END` |
| Final input ends inside a Tag, Length, Value or trailer | `TLV_ERR_TRUNCATED`, with an INPUT location |
| Non-final input, either of the above | `TLV_NEED_MORE_DATA` |
| Destination or workspace too small | `TLV_ERR_BUFFER_TOO_SHORT` |

Format decode callbacks report incomplete input as `TLV_ERR_TRUNCATED`;
decoding has no destination, so `TLV_ERR_BUFFER_TOO_SHORT` from a decoder is
a `CALLBACK` violation. `TLV_ERR_END_OF_BUFFER` and `TLV_ERR_INVALID_BYTE_ORDER`
were removed without aliases; an unknown byte order is `TLV_ERR_INVALID_ARG`.

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

### Capabilities, resources and callbacks

`UNSUPPORTED` replaces the former `UNSUPPORTED_TYPE` name without an alias.
A valid DER/CER `max_depth` above the fixed implementation capacity is
`UNSUPPORTED`; exceeding an accepted depth or element budget is `LIMIT`.
Invalid options and inconsistent API descriptors are `INVALID_ARG`.
Caller-provided frame arrays, tag storage, DER byte arenas and sorting records
that cannot hold the required data produce `BUFFER_TOO_SHORT`.

Callback errors that satisfy the callback contract retain their result. Invalid
return discriminators, forbidden control statuses and inconsistent successful
payloads produce `CALLBACK`. This includes Format source/framing sizes, Field
Encoding extents, DER presence/size changes and impossible preorder depths.
Explicit visitor error stops remain `VISITOR`; unknown visitor actions are
`CALLBACK`, while normal early stop remains success.

Query hook output with a wrong type, nonempty NULL span or invalid UTF-8 returns
`CALLBACK` with Query kind `CALLBACK`, preserving the reported codec result
(including `TLV_OK`). Ordinary conversion failures preserve their original
result and typed cause with Query kind `CODEC` (or `STATE` for lifecycle misuse).
Malformed stored images use `INVALID_VALUE` plus `IMAGE`; a recognized image
with an incompatible version uses `UNSUPPORTED` plus `IMAGE_VERSION`.

Optional path truncation keeps the operation's original result and increments
`path.omitted`. The standalone path-push helper reports `BUFFER_TOO_SHORT`.
Reports that explicitly permit partial collection retain their validation
result and stored/omitted counts.

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

Failure locations use the common `tlv_location_t` value: a domain, kind and
checked `[begin, end)` coordinates. UNKNOWN has no position; a POINT at zero or
an empty SPAN at EOF is known evidence. INPUT, OUTPUT, EXPRESSION, DEFINITION
and VALUE domains identify distinct coordinate spaces. Translation overflow
drops optional location evidence while retaining the original result.

DER/CER, DOL, Bluetooth AD, Document, Query paths and Tree visitors accept
structured diagnostics; their offset-only outputs were removed in #555.
DER/CER reads report INPUT points at the failing field, writes report OUTPUT
points in would-be encoding, and DOL reports INPUT positions within its DOL
descriptor even while writing. Argument/configuration failures remain unknown.
See [diagnostics](../guides/diagnostics.md#evidence-locations) for origins and ownership.

Schema validators distinguish invalid definitions (`TLV_ERR_INVALID_SCHEMA`) from
valid definitions rejecting input (`TLV_ERR_SCHEMA`). Length constraints are Schema
violations; malformed wire Length encodings still use `TLV_ERR_INVALID_LENGTH`.
Missing required fields, groups, DHCP End and DER components/root use `SCHEMA`
with `TLV_SCHEMA_ISSUE_MISSING`, consistently across generic Schema and builtins.
`TLV_ERR_SCHEMA_MISSING` has been removed without an alias.

`tlv_schema_validate()`, DER schema check/read/write, LLDP and DHCP container
validation return `tlv_schema_diagnostic_t` detail when requested. Its `diagnostic.location.kind`
distinguishes a point, span, scope end, insertion point and unknown position.
A missing field is not an element at its anchor; never decode a tag there to
explain the failure. Generic report findings now use scope end for missing fields,
including known offset zero for an empty root. Definition failures have no input
byte location; `definition.kind`, `owner` and `index` identify native definitions.

The Schema diagnostic layout and affected signatures changed in #553 and #555. Rebuild
native clients and use the matching binding version. C++ errors expose
`schema_kind()`, `location()` and `definition()`; Python uses `InvalidSchemaError` for definitions
and `SchemaError` with `kind="missing"` for required absence.

Custom Format callback failures permitted by the callback contract propagate
unchanged through the generic Reader and Writer. Unknown results, forbidden
control statuses and invalid successful payloads become `TLV_ERR_CALLBACK`;
see the public callback contracts in `tlv/format.h`.

## Diagnostic enum names

The C library owns the diagnostic names; callers need no parallel name tables.
Each function below returns a static NUL-terminated string, never NULL, with
`"unknown"` for an unrecognized value. Names use lowercase words and underscores
(for example `"image_version"`). Do not free or modify the returned storage.
These functions remain available with the processing capabilities disabled.

| Diagnostic value | Name function |
| --- | --- |
| Severity | `tlv_diagnostic_severity_string()` |
| Location domain / anchor | `tlv_location_domain_string()` / `tlv_location_kind_string()` |
| Query failure kind | `tlv_query_error_kind_string()` |
| Reader / Writer operation | `tlv_reader_operation_string()` / `tlv_writer_operation_string()` |
| Schema finding / definition object | `tlv_schema_issue_kind_string()` / `tlv_schema_definition_kind_string()` |
| Codec operation / delegated cause / callback violation | `tlv_codec_operation_string()` / `tlv_codec_cause_string()` / `tlv_codec_violation_string()` |

`tlv_strerror()` separately describes results, with `"unknown error"` as its
fallback. Enum-name strings describe detail; they do not replace result codes.

## Lookup and pointer-returning APIs

`tlv_document_find_path(document, query, &node)` returns `TLV_OK` with the first
match, or `TLV_OK` with NULL when the search completed without a match. Invalid
queries and arguments retain the original failure result and leave `node`
unchanged, even on an empty Document. The former pointer-returning signature
has been replaced without a compatibility wrapper. Rebuild native callers.
C++ path lookup throws `query_error`; Rust uses `Result<Option<Node>>` and
`Result<Option<NodeMut>>`; Python and Lua raise the native failure category.

The remaining exported pointer-returning APIs have these explicit contracts;
none performs a delegated fallible traversal or allocation:

| API family | Pointer / NULL contract |
| --- | --- |
| Document `first`, Node `first_child`, `next`, `parent`, `next_same_tag` | Borrowed node; NULL for no such node or a NULL input. |
| `tlv_document_find()` | Borrowed first direct match; NULL for no match, invalid Tag, or absent top-level Document. Parent ownership is a caller precondition. |
| `tlv_node_value_data()` | Borrowed primitive bytes; NULL for NULL node, empty Value, or constructed node. |
| `tlv_definition_find()`, `tlv_schema_find()` | Borrowed entry; NULL for no match or rejected arguments/table descriptor. They skip invalid entry Tags and do not validate complete definitions. |
| `tlv_value_constraint_name()` | Borrowed name; NULL for unavailable table/name, wrong constraint kind, or no match. |
| `tlv_asn1_named_bit_find()` | Borrowed name; NULL for no match or a NULL entry name. The caller supplies a valid table extent. |
| EMV `dictionary_for`, `schema_for` | Static table; NULL for invalid context. |
| EMV `dictionary_find`, `find` | Borrowed entry; NULL for no match or invalid lookup arguments/context. |
| `tlv_emv_symbol()`, `tlv_emv_display_label()` | Borrowed/static optional text; NULL for absent metadata/label, including NULL input. |
| `tlv_query_builtin_hooks()` | Non-NULL static provider array; optional count output. |
| Version string and Git metadata accessors | Non-NULL static build metadata; no prerelease is an empty string, unavailable Git metadata uses `"unknown"`. |
| Diagnostic name functions, `tlv_strerror()`, `tlv_emv_value_kind_description()` | Non-NULL static text with the documented unknown-value fallback. |

A NULL lookup result alone therefore does not distinguish absence from rejected
arguments unless the API has a separate result channel. Follow each header's
argument, extent and lifetime preconditions.

## Conversion failures

Codec, Structure Codec and Query conversions return the same `tlv_result_t`.
The separate Codec enum, constants and strerror entry point were removed in #556.
Callbacks and entry points accept optional `tlv_codec_diagnostic_t` output.
Structure validation preserves the original Reader/Schema/resource result and
cause; Query retains this evidence alongside its related expression span.
Invalid callback discriminators or successful output contracts report `CALLBACK`
while preserving the callback's reported value, including `OK`.

This changes callback signatures and the Query diagnostic layout. Rebuild native
clients and use matching bindings. Valid conversion bytes are unchanged.

## Binding diagnostics

Bindings use the C result domain, including resumable `NEED_MORE_DATA`, and
preserve the independent detail, primary location and delegated cause. Category
names come from the C string functions; an unrecognized value is named
`unknown`. A raw callback `reported` result stays numeric so invalid provider
results remain inspectable.

| Facade | Diagnostic categories |
| --- | --- |
| C++ | `errc`, `query_issue`, `reader_phase`, `writer_phase`, `schema_issue`, `schema_definition_kind`, `codec_phase`, `codec_cause`, `codec_violation`; `message(category)` calls C. |
| Rust | `Error` and typed `QueryErrorKind`, `ReaderOperation`, `WriterOperation`, `SchemaIssue`, `SchemaDefinitionKind`, `CodecOperation`, `CodecCause`, `CodecViolation`, `Severity`; category `name()` calls C. Categories are `#[non_exhaustive]`; `Unrecognized(RawCategory)` retains unrecognized values. |
| Python | Typed result exceptions; Query `query["query_kind"]`, Schema report fields and Codec detail fields use `IntEnum` categories exported by `opentlv`. Their `label` property calls C. Reader/Writer `operation` remains a canonical string. |
| Go | `errors.Is` classifies results and `errors.As` retrieves owned details. `ProgramError.Kind`, `QuerySchemaError.Kind` and Codec categories are typed; `String()` calls C. Reader/Writer errors expose typed `Phase()` methods; `Diagnostic.ReaderPhase()` and `WriterPhase()` type Query Reader causes too. |
| Lua | Error tables preserve result `code`, `location`, optional path and contexts. `query.kind_name` and Codec `operation_name`, `cause_name`, `violation_name` come from C alongside numeric values. |
| JS/WASM | `QueryError` carries the C message, structured `location` and owned Query evidence. `query.kind_name`, Reader `operation_name` and Codec names accompany numeric categories. Common evidence appears once in `query.diagnostic`. |

For example, Rust consumers match `failure.kind == QueryErrorKind::Syntax`;
Python consumers compare `error.query["query_kind"] is QueryErrorKind.SYNTAX`.
Use `.as_raw()` in Rust when an external protocol explicitly requires the C
integer. These diagnostic field changes are source-breaking; rebuild bindings
against the matching C library.

Unknown locations have no meaningful numeric coordinates. A known point at
zero is distinct from absence. Related Query expression spans do not replace
the primary input/output/Value location. Retained paths hold outermost scopes;
`path_omitted` counts omitted innermost scopes. Go's `HasReader` guards the
Reader-specific part of a Query failure.

CLI diagnostics identify the location domain and anchor kind. Compact output
includes truncated paths and omitted counts; Query JSON includes common
diagnostic metadata and delegated Codec or Reader evidence.

## See also

- [C API reference](c-api.md) for the documented codes per function.
- [Format documentation](../formats/README.md#reading-one-element) for the reader and
  writer error behavior.
- [Pull-based reading](../guides/reader.md) for end, incomplete input and parsing errors.
