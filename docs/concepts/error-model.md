# Failure model

This is the accepted design for [#551](https://github.com/marekcingel/OpenTLV/issues/551),
for authors of C capabilities and language facades. Read the
[architectural rules](architectural-rules.md) and
[current error reference](../reference/errors.md) first.

**Status: design decided; lifecycle implemented by #552, Schema classification
by #553, capability/resource/callback results by #554, and common locations by #555. Remaining API and binding
migration is separate work.** This page defines the target contract.
`TLV_ERR_INVALID_STATE`, `TLV_ERR_INVALID_SCHEMA`, `TLV_ERR_UNSUPPORTED` and
`TLV_ERR_CALLBACK` are public, together with Query kinds `STATE`, `CALLBACK`,
`TYPE` and `IMAGE`. Other new target names are not yet public declarations. The reference page continues to describe the running
implementation. This design does not preserve source, binary, enum-number or
diagnostic-layout compatibility. Removed names get no aliases, compatibility
wrappers or deprecation period. Native consumers and bindings migrate together.

## One failure, four questions

For example, a missing mandatory field and a malformed schema definition are
different failures even if the same validator detects both:

| Question | Missing mandatory field | Invalid occurrence bounds in a schema |
| --- | --- | --- |
| Result: what failed? | `TLV_ERR_SCHEMA` | `TLV_ERR_INVALID_SCHEMA` |
| Detail: what happened in this layer? | Schema `MISSING`, expected tag and occurrence count | Schema definition detail, minimum greater than maximum |
| Location: where is the evidence? | Enclosing scope end or insertion point; absent tag is not an element at that byte | Definition location if available; otherwise unknown |
| Propagation: what does an enclosing operation retain? | Same result and Schema detail | Same result and definition detail |

Results describe reusable failure classes. Detail identifies the detecting
layer, operation and reason. Location identifies evidence without changing the
result class. Propagation adds context without replacing the original cause.
Protocol names, universal tag numbers and builtin-specific policies belong in
detail, never in the common result enum.

## Result taxonomy

### Admission rule

Add a result only when it denotes a distinct, protocol-independent condition
with a different caller response that cannot be expressed by an existing class.
The distinction must remain useful without diagnostics and across native,
runtime-configured and generated implementations. Name prefixes such as
`INVALID_` do not decide membership. A new layer, operation, missing field,
syntax production or protocol restriction alone does not justify a result.

There are three kinds of outcome: success, control status and failure. A caller
must not treat every nonzero result as a fatal error. `TLV_OK` remains zero;
this design makes no other promise about numeric assignments.

### Target results

| Target result | Meaning and caller response |
| --- | --- |
| `TLV_OK` | Operation completed successfully. |
| `TLV_END` | Normal end of an iteration or an empty single-read region. No element is published. |
| `TLV_NEED_MORE_DATA` | Non-final incremental input is insufficient; extend the window or declare EOF and resume. |
| `TLV_ERR_TRUNCATED` | Final input ends inside a required representation. Supply a complete input; increasing output or workspace capacity cannot repair it. |
| `TLV_ERR_BUFFER_TOO_SHORT` | Caller-supplied destination or workspace capacity is insufficient. Supply the required capacity; detail identifies the buffer and its units. |
| `TLV_ERR_NULL_ARG` | A required pointer is NULL. Empty spans may use NULL where documented. |
| `TLV_ERR_INVALID_ARG` | API configuration or an argument descriptor is invalid: alignment, overlap, option value, inconsistent extent, missing mandatory callback or contradictory configuration. Correct the call. |
| `TLV_ERR_INVALID_STATE` | The object or operation sequence is invalid: stale handle, uninitialized/failed execution, forbidden reentrancy or operation after finalization. Correct the lifecycle or reset. |
| `TLV_ERR_INVALID_SCHEMA` | A schema definition is internally invalid, independent of the data being validated. Correct the definition. |
| `TLV_ERR_SYNTAX` | Text does not conform to the requested language grammar. Correct the text; Query and future OTLV share this class. |
| `TLV_ERR_UNSUPPORTED` | A valid requested capability, operation, representation version or configuration is not implemented by this provider/backend. Choose a supporting implementation or change the request. |
| `TLV_ERR_INVALID_TAG` | An identifier violates the selected wire Format's identifier rules. |
| `TLV_ERR_INVALID_TAG_SIZE` | Identifier byte count is outside the operation's supported range. This remains distinct from malformed identifier bytes. |
| `TLV_ERR_INVALID_LENGTH` | A wire Length encoding or encoded length is invalid for the selected Format. Schema Value-length constraints use `SCHEMA`. |
| `TLV_ERR_INVALID_VALUE` | Data or its application representation is invalid for the requested interpretation: malformed Value content, canonicality violation, type/cardinality mismatch or malformed stored program image. It is not a fallback for configuration, lifecycle or callback defects. |
| `TLV_ERR_SCHEMA` | Input violates a valid structural or semantic schema constraint, including absence of required content. |
| `TLV_ERR_LIMIT` | A valid configured processing budget is exceeded: depth, elements, work or logical input/value size. Raising the budget may permit processing. |
| `TLV_ERR_OVERFLOW` | Arithmetic or numeric conversion exceeds its logical numeric range. |
| `TLV_ERR_NATIVE_SIZE` | A valid logical quantity cannot be addressed by the host's `size_t`. Keep this separate from logical arithmetic overflow. |
| `TLV_ERR_OUT_OF_MEMORY` | An explicitly allocating operation's allocation failed. Caller workspace shortage is not allocation failure. |
| `TLV_ERR_VISITOR` | A visitor explicitly requests an error stop through its valid control result. Normal early stop is success. |
| `TLV_ERR_CALLBACK` | A callback violates its declared contract: invalid return discriminator, impossible extent, wrong successful result type or other invalid success payload. Correct the provider. |

### Boundaries and precedence

`INVALID_ARG` validates how an operation is requested; `INVALID_VALUE` validates
the data being interpreted. An invalid codec configuration is `INVALID_ARG`;
bytes that fail a valid codec configuration are `INVALID_VALUE`. Query text
syntax is `SYNTAX`; a valid expression with incompatible operand types is
`INVALID_VALUE` with a type detail. A corrupt internal program image is
`INVALID_VALUE` with image detail, while insufficient caller storage is
`BUFFER_TOO_SHORT` and a recognized incompatible image version is `UNSUPPORTED`.
An invalid event stream is data (`INVALID_VALUE`); calling feed on a failed
execution is lifecycle misuse (`INVALID_STATE`).

`INVALID_SCHEMA` applies to malformed constraints, rule/group tables,
references and schema graphs. A NULL top-level required schema pointer is still
`NULL_ARG`; a missing required reference inside a supplied schema definition is
`INVALID_SCHEMA`. A well-formed schema that uses an unimplemented feature is
`UNSUPPORTED`. Model loading uses these same classes: malformed syntax is
`SYNTAX`, an invalid Schema description is `INVALID_SCHEMA`, and unresolved
non-Schema model symbols are `INVALID_VALUE` with model detail. There is no
protocol-specific or universal catch-all model error.

Resource classification depends on the resource, not when it was exhausted:

| Condition | Result |
| --- | --- |
| Depth/work/elements exceed a valid configured processing maximum | `LIMIT` |
| Caller frame array, arena, compilation scratch or report storage is too small for a required operation | `BUFFER_TOO_SHORT` |
| Maximum has an illegal value or contradicts other options | `INVALID_ARG` |
| Valid configuration exceeds a fixed implementation capability | `UNSUPPORTED` |
| Allocation requested by an owning operation fails | `OUT_OF_MEMORY` |
| Optional diagnostic path cannot retain another tag | Mark the path truncated; do not replace the operation's result |

Zero is a valid inclusive budget where the API defines it that way; it is not
automatically invalid configuration. A report API that explicitly permits
partial collection reports stored/omitted counts and retains the aggregate
validation result instead of substituting a capacity error. The standalone
path-push helper reports `BUFFER_TOO_SHORT` when it records an omission.

Validate required pointers and safe extents before dereferencing, reject
forbidden overlap and reentrancy before writing diagnostics, then validate
configuration/state before processing data. Within data processing, retain the
first failure in the operation's documented traversal order. More specific
semantic distinctions do not authorize speculative reads or a second callback
invocation. Existing safe validation ordering remains relevant: NULL Tag bytes
precede width checks; width checks precede content policy checks.

Missing required content is always `SCHEMA` with `MISSING` detail. Remove
`SCHEMA_MISSING`; its former location distinction is represented explicitly.
This covers generic Schema, DHCP End requirements, LLDP mandatory fields and
DER required components, including a missing required root. There is no
exception based on which builtin performs the validation. Mandatory framing
bytes missing inside a wire element instead produce `TRUNCATED`; semantic
schema requirements must not be inferred by the generic Reader.

## Typed detail and common diagnostics

Keep `tlv_diagnostic_t` as the common diagnostic base and keep specialized
Reader, Writer, Schema and Query value types. The target Query diagnostic
embeds the common base and retains typed Query span, resource, binding,
cardinality, codec and Reader detail. Replace the present instruction that
layers must use context nodes *instead of* specialized types: typed detail is
the normal machine-readable extension; borrowed text contexts are optional
human-readable enrichment. Programs must not parse context strings to classify
an error.

The base carries the returned result, severity, origin layer, primary location
and optional path/expected/actual information. Specialized detail identifies the
operation and reason, including the original lower-layer detail when delegated.
Result and detail are orthogonal: `READER` may legitimately accompany
`INVALID_TAG`, `LIMIT`, `BUFFER_TOO_SHORT` or `NEED_MORE_DATA`. The mapping tables
below constrain combinations rather than requiring a function from kind to
result. Detail is discriminated; inactive fields must not be interpreted.

Query detail kind `STATE` is implemented by #552; `TYPE`, `IMAGE` and `CALLBACK`
by #554. `ARGUMENT` remains to be added for cases currently forced into
`STORAGE`, `EVENTS` or `CAPABILITY`. Keep
`IMAGE_VERSION` for a recognized version mismatch. `CODEC` denotes conversion
context; a callback contract violation during conversion uses `CALLBACK` and
records the codec operation and reported result, including a reported `OK`.
Ordinary invalid encoded values remain `CODEC` plus `INVALID_VALUE`.

Schema input findings retain `MISSING`, `DUPLICATE`, `UNEXPECTED`, `KIND`,
`LENGTH`, `ORDER` and `ASSERTION`; add `VALUE` for a direct semantic constraint
violation. Schema definition failures have a separate typed definition reason
(invalid bounds, rule/group entry, reference, enum or graph), not an input
finding attached to fictitious wire bytes.

### Ownership and cost

Diagnostics remain allocation-free, caller-owned and optional. Shared result
and detail vocabulary is available without linking Reader, Query or Codec
implementations. No successful parsing path must format strings, allocate,
collect paths or build context chains for an unrequested diagnostic.

The target common base stores a bounded path by value, with an explicit
presence flag and `omitted` count. It retains the outermost 32 enclosing tags;
the omitted count saturates. Path entries copy Tag spans, not Tag bytes, so
their immutable backing storage must outlive the diagnostic. The affected Tag
is separate from enclosing ancestors. Bounded inline storage avoids pointers
from an embedded base into its enclosing specialized object. Native copies
preserve valid external borrows without pointer rebasing. Query span and
resource numbers are inline; expected/actual text and context chains may borrow
external storage with explicit lifetimes. Do not attach stack-local strings,
paths or context nodes to an escaping diagnostic.

Bindings that retain diagnostics beyond those lifetimes copy the relevant
bytes, paths and text into language-owned storage. They expose the same result,
detail discriminator, location domain and omitted count through the idiomatic
facade. They must not reconstruct semantic causes from messages or offsets.

### Initialization and publication

Retain the contract established by #548: after diagnostic initialization,
every non-OK return has `diagnostic.code == rc`, including propagated control
status. Query also has a meaningful active detail; Reader control statuses use
`READER`. Diagnostic initialization is an explicit publication boundary, not
permission to overwrite aliased input, an active callback's output or the first
failure of an already failed execution.

Pre-initialization argument, overlap, reentrancy and failed-continuation guards
may leave diagnostic outputs untouched as documented. A wrapper that has
already initialized its own output must describe a delegated failure even
when the lower call rejected before publishing detail. Initialize absent
fields instead of copying uninitialized lower-layer storage. On success,
diagnostics need not be cleared; callers inspect them only with the result.
Individual report findings describe their own errors rather than copying an
aggregate result into every record.

Control status does not invalidate an incremental execution. Preserve its
documented resume/reset behavior. Severity is presentation metadata, not the
test for success, resumability or lifecycle validity.

## Locations

Location is a generic diagnostic value; it is not Element identity. The target
location records a domain and an anchor kind, with checked coordinates. A
domain distinguishes input wire bytes, would-be output wire bytes, expression
text and definition text. Each API identifies the source object and origin
associated with these coordinates; two offsets in different inputs cannot be
compared without that context. Native definitions without text use a typed
rule/component index rather than invented definition byte offsets.

| Anchor kind | Contract |
| --- | --- |
| Unknown | No byte position is known. Do not interpret numeric fields. |
| Point | A known byte position, possibly zero or EOF. It does not assert that an element starts there. |
| Span | Half-open `[begin, end)` evidence range in one domain; `begin <= end`, and an empty EOF span is valid. |
| Scope end | Boundary of the enclosing Value or top-level region; appropriate for unordered missing content. |
| Insertion point | Known position at which missing ordered content would begin. No offending element exists there. |

Absence of a location differs from a known zero offset, empty EOF span or
truncated path. A span describes bytes actually available. Required lengths,
declared lengths and an enclosing boundary are separate typed quantities; do
not extend an evidence span beyond its source to show missing bytes. Coordinate
conversion uses checked arithmetic. If optional location enrichment cannot be
represented, retain the original failure and mark the location unknown rather
than returning a new overflow error.

Reader locations are relative to the documented input origin, including the
absolute origin of an incremental window. Query expression spans and input
Source offsets remain separate. On Reader/Codec propagation, the original
input location stays primary and the Query expression span is related context;
do not overwrite one with the other. If the lower layer gives a Value-relative
position, translate it only when the Value origin is known. Without it, retain
the local domain/origin information or mark the enclosing source position
unknown. Do not manufacture an absolute offset.

Preserve #549's useful DER write semantics: locations refer to would-be output
with enclosing headers and canonical SET order. A missing SEQUENCE component
uses an insertion point; a missing SET component uses scope end. If computing
that layout encounters a later callback or scratch failure, preserve the first
result and mark its location unknown. Do not retry callbacks merely to obtain
a location. Argument/configuration/capacity errors have unknown byte location
unless the operation actually knows relevant evidence.

### Replacing offset-only APIs

Replace public failure-reporting `size_t* error_offset` parameters with the
appropriate common or typed diagnostic output in the implementation work.
Remove the offset-only signatures; there is no compatibility wrapper or zero
sentinel convention in the target API. Operations needing no diagnostic pass
NULL. This concerns error outputs, not ordinary cursor or source-range APIs.

Migrate each producer at the point where its coordinate origin and anchor kind
are known. Update all callers, builtin adapters, tests, examples and bindings
in the same change. Do not infer `has_location` from `offset != 0`, or recover
the missing anchor kind from an old result code. Existing offset-zero fallback
cases become unknown; actual failures at byte zero remain located.

## Propagation and callbacks

Use one result domain throughout the target C API: Codec operations and their
callbacks return `tlv_result_t`. Remove `tlv_codec_result_t` and its independent
success/error enum. A codec remains a Value converter; sharing error vocabulary
does not make it a wire parser or require Reader/Schema dependencies. Structure
codecs already compose those capabilities and must preserve their results.
The target typed codec diagnostic can carry Reader or Schema cause detail
when it delegates, as well as its conversion operation and representation.
Codec entry points, descriptor callbacks and Query conversion hooks receive an
optional typed diagnostic output so that this cause can cross the callback
boundary. When NULL, only the common result is propagated. Adding this output
is part of the breaking callback-signature migration, not a second conversion
engine or a required allocation.

1. Propagate a lower-layer result unchanged when the operation delegates that
   work. Add layer/operation context and preserve its typed cause and location.
2. When there is only a result and no lower diagnostic, preserve that result
   and origin with unknown detail/location; do not invent a cause.
3. Reject a callback's invalid success payload or invalid return discriminator
   as `CALLBACK`. Record the violated contract and reported result. A callback
   legitimately returning an error is not itself a callback contract failure.
4. Admit control statuses only where the callback contract explicitly allows
   them. Returning `END` from a callback required to produce one encoded Value
   is a contract violation, not end of an enclosing Reader iteration.
5. A deliberate visitor error stop is `VISITOR`; an unknown visit result is
   `CALLBACK`; a deliberate normal stop is `OK`. Preserve any separately
   documented richer visitor error channel without fabricating one.

There is no target codec-to-core or core-to-codec lossy conversion. In
particular, structure validation must not collapse `LIMIT`, `TRUNCATED`,
`INVALID_SCHEMA` or `SCHEMA` into an invalid-structure bucket. The historical
mapping below is for changing producers, not a runtime compatibility adapter.

Reader resource failures within Query retain Reader origin and `READER`
detail. An exhausted Reader processing budget remains `LIMIT`; Query does not
rewrite it into its own `LIMIT` detail. The intent of
`TreeResourceLimitsHaveOwnedSafeReaderDiagnostics` remains mandatory. Its
frame-capacity case changes to `BUFFER_TOO_SHORT`, while depth/element budget
cases remain `LIMIT`. All preserve safe absent fields and Reader provenance.

## Migration inventory

This inventory is based on the public vocabulary at `977a60e7`, after
issues #548, #549 and #550. It covers every current common result, codec result, Query error
kind, Schema issue kind and Reader/Writer operation. Rows with multiple target
outcomes require classification at the producer, not an enum-wide replacement.
Names in the target columns omit `TLV_ERR_` where unambiguous.

### Every current common result

| Current code | Target classification |
| --- | --- |
| `TLV_OK` | Keep `TLV_OK`. |
| `TLV_ERR_BUFFER_TOO_SHORT` | Final incomplete input -> `TRUNCATED`; non-final incremental input -> `TLV_NEED_MORE_DATA`; destination/workspace shortage -> `BUFFER_TOO_SHORT`. |
| `TLV_ERR_INVALID_LENGTH` | Wire encoding/range -> `INVALID_LENGTH`; Schema Value-length rule -> `SCHEMA` + `LENGTH`; malformed length configuration -> `INVALID_ARG`. |
| `TLV_ERR_NULL_ARG` | Missing required pointer -> `NULL_ARG`; invalid non-NULL descriptor currently lumped here -> `INVALID_ARG`. |
| `TLV_ERR_OUT_OF_MEMORY` | Actual allocation failure -> `OUT_OF_MEMORY`; allocation-size arithmetic overflow currently lumped here -> `OVERFLOW`, or `NATIVE_SIZE` when the logical size is valid but not host-addressable. |
| `TLV_ERR_END_OF_BUFFER` | Normal exhaustion -> `TLV_END`; missing mandatory schema content -> `SCHEMA` + `MISSING`; exhaustion inside a required encoding -> `TRUNCATED`. |
| `TLV_ERR_INVALID_TAG` | Invalid wire identifier -> `INVALID_TAG`; valid identifier rejected only by a schema -> `SCHEMA` + `UNEXPECTED` or `KIND`. |
| `TLV_ERR_VISITOR` | Explicit error stop -> `VISITOR`; unknown visitor result -> `CALLBACK`. |
| `TLV_ERR_LIMIT` | Processing budget -> `LIMIT`; caller storage/frame shortage -> `BUFFER_TOO_SHORT`; invalid option -> `INVALID_ARG`; valid request beyond a fixed implementation capability -> `UNSUPPORTED`; optional path truncation -> omission metadata. |
| `TLV_ERR_SCHEMA` | Input violation -> `SCHEMA` with finding detail; invalid schema definition -> `INVALID_SCHEMA`; a callback contradicting its own declared result -> `CALLBACK`. |
| `TLV_ERR_INVALID_ARG` | API configuration/storage descriptors -> `INVALID_ARG`; lifecycle/reentrancy -> `INVALID_STATE`; text grammar -> `SYNTAX`; invalid schema definition -> `INVALID_SCHEMA`; unsupported capability -> `UNSUPPORTED`; invalid data/image/types/bindings -> `INVALID_VALUE`; provider contract violation -> `CALLBACK`. |
| `TLV_ERR_INVALID_TAG_SIZE` | Keep operation-specific identifier-width class; an invalid configured width is `INVALID_ARG`. |
| `TLV_ERR_INVALID_BYTE_ORDER` | Unknown enum/configuration -> `INVALID_ARG`; valid but unimplemented order -> `UNSUPPORTED`. Remove the old result. |
| `TLV_ERR_OVERFLOW` | Keep logical numeric/arithmetic overflow. |
| `TLV_ERR_INVALID_VALUE` | Invalid interpreted data/canonicality -> `INVALID_VALUE`; Schema constraint -> `SCHEMA`; bad callback success payload -> `CALLBACK`; invalid configuration -> `INVALID_ARG`. |
| Former `TLV_ERR_UNSUPPORTED_TYPE` | Replaced by `UNSUPPORTED` with type/capability/version detail in #554. |
| `TLV_ERR_SCHEMA_MISSING` | `SCHEMA` + `MISSING` and explicit scope-end/insertion location. Remove the old result. |
| `TLV_ERR_NATIVE_SIZE` | Keep host-addressability distinction. |
| `TLV_NEED_MORE_DATA` | Keep resumable control status; never convert a non-final shortage into a fatal error. |

### Every current Codec result

| Current code | Target producer result and detail |
| --- | --- |
| `TLV_CODEC_OK` | `TLV_OK`; invalid successful payload is detected by the caller as `CALLBACK`. |
| `TLV_CODEC_ERR_NULL_ARG` | `NULL_ARG` for a missing pointer; `INVALID_ARG` for invalid non-NULL configuration/descriptor. |
| `TLV_CODEC_ERR_BUFFER_TOO_SHORT` | Destination/workspace shortage -> `BUFFER_TOO_SHORT`; incomplete required encoded structure -> `TRUNCATED`. A complete Value of the wrong codec width is `INVALID_VALUE`. |
| `TLV_CODEC_ERR_INVALID_VALUE` | Invalid Value or application representation -> `INVALID_VALUE`; invalid configuration -> `INVALID_ARG`; detected provider breach -> `CALLBACK`. |
| `TLV_CODEC_ERR_UNSUPPORTED` | `UNSUPPORTED`; preserve conversion direction/capability detail. |
| `TLV_CODEC_ERR_INVALID_STRUCTURE` | Remove the catch-all and preserve the actual Reader/Schema/resource result and cause. A malformed supplied object with no lower-layer failure is `INVALID_VALUE`. |

C++ `codec_errc` and `typed_error` projections and all other language mappings
must adopt the shared result domain. Preserve codec operation detail without
retaining a second semantic result taxonomy. No numeric casts between the old
enums constitute a migration.

### Every current Query error kind

| Current kind | Target result/detail rule |
| --- | --- |
| `TLV_QUERY_ERROR_NONE` | No active failure detail. Not valid after initialized non-OK publication. |
| `TLV_QUERY_ERROR_SYNTAX` | `SYNTAX` + `SYNTAX` for grammar; resource exhaustion while parsing remains `LIMIT` + `LIMIT`; static type errors move to `INVALID_VALUE` + `TYPE`. |
| `TLV_QUERY_ERROR_CAPABILITY` | `UNSUPPORTED` + `CAPABILITY` for unavailable features; invalid environment/hook/format configuration -> `INVALID_ARG` + `ARGUMENT`; type failure -> `INVALID_VALUE` + `TYPE`; Tag adapter errors retain the original result and adapter detail under `CAPABILITY`. |
| `TLV_QUERY_ERROR_LIMIT` | `LIMIT` + `LIMIT` for Query processing budgets; caller storage shortage -> `BUFFER_TOO_SHORT` + `STORAGE`. |
| `TLV_QUERY_ERROR_STORAGE` | `BUFFER_TOO_SHORT` + `STORAGE` for capacity; invalid alignment/extents/overlap/options -> `INVALID_ARG` + `ARGUMENT`, subject to pre-initialization guards. |
| `TLV_QUERY_ERROR_EVENTS` | Invalid structural feed -> `INVALID_VALUE` + `EVENTS`; lifecycle/reentrancy -> `INVALID_STATE` + `STATE`; deliberate visitor error -> `VISITOR` + `CALLBACK`; callback contract violation -> `CALLBACK` + `CALLBACK`. |
| `TLV_QUERY_ERROR_SOURCE` | Required metadata absent on supplied data -> `INVALID_VALUE` + `SOURCE`; backend cannot provide the requested metadata at all -> `UNSUPPORTED` + `SOURCE`. Neither invents an offset. |
| `TLV_QUERY_ERROR_READER` | Preserve the Reader result and typed detail, including `LIMIT`, `BUFFER_TOO_SHORT`, `TLV_END` or `TLV_NEED_MORE_DATA`. |
| `TLV_QUERY_ERROR_BINDING` | Missing/unknown/duplicate/incompatible variable binding -> `INVALID_VALUE` + `BINDING`; NULL API pointer -> `NULL_ARG` + `ARGUMENT`; invalid binding array extent -> `INVALID_ARG` + `ARGUMENT`. |
| `TLV_QUERY_ERROR_CARDINALITY` | `INVALID_VALUE` + `CARDINALITY`; expected/actual counts are typed detail. |
| `TLV_QUERY_ERROR_CODEC` | Preserve the shared result and typed conversion cause under `CODEC`; bad successful hook payload -> `CALLBACK` + `CALLBACK`. |
| `TLV_QUERY_ERROR_IMAGE_VERSION` | Recognized incompatible version -> `UNSUPPORTED` + `IMAGE_VERSION`; malformed image -> `INVALID_VALUE` + `IMAGE`. |

Adapter failures under `CAPABILITY` are propagation, not a claim that their
result is `UNSUPPORTED`. Invalid adapter success payloads instead use
`CALLBACK`. Query-owned numeric overflow remains `OVERFLOW` with `TYPE` detail;
do not label it an unsupported feature.

### Every current Schema issue kind

| Current kind | Target result/detail rule |
| --- | --- |
| `TLV_SCHEMA_ISSUE_MISSING` | `SCHEMA` + `MISSING`; absent Tag and scope-end/insertion anchor. |
| `TLV_SCHEMA_ISSUE_DUPLICATE` | `SCHEMA` + `DUPLICATE`; maximum and actual occurrence counts. |
| `TLV_SCHEMA_ISSUE_UNEXPECTED` | `SCHEMA` + `UNEXPECTED`; prohibited/unknown Tag in context. |
| `TLV_SCHEMA_ISSUE_KIND` | `SCHEMA` + `KIND`; required/actual primitive or constructed form. |
| `TLV_SCHEMA_ISSUE_LENGTH` | `SCHEMA` + `LENGTH`; Value size, bounds and multiple. |
| `TLV_SCHEMA_ISSUE_ORDER` | `SCHEMA` + `ORDER`; schema ordering rule and offending element. |
| `TLV_SCHEMA_ISSUE_ASSERTION` | `SCHEMA` + `ASSERTION` for false boolean assertions. Query evaluation errors preserve their own result and Query detail instead. |

### Every current Reader and Writer operation

Operation identifies the failed step, not a result class. All retain their
typed operation names; propagated callbacks retain that same step and cause.

| Current operation | Target interpretation |
| --- | --- |
| `TLV_READER_OP_TAG` | Identifier decoding. |
| `TLV_READER_OP_LENGTH` | Length decoding; whole-header operations use `HEADER` when the Format can identify them as such. |
| `TLV_READER_OP_VALUE` | Available Value extent or enclosing boundary. |
| `TLV_READER_OP_TRAILER` | Trailer/terminator framing. |
| `TLV_READER_OP_HEADER` | Whole header or an unnamed header field. |
| `TLV_WRITER_OP_TAG` | Identifier encoding. |
| `TLV_WRITER_OP_LENGTH` | Length encoding. |
| `TLV_WRITER_OP_VALUE` | Value publication. |
| `TLV_WRITER_OP_HEADER` | Header framing. |
| `TLV_WRITER_OP_TRAILER` | Trailer framing. |
| `TLV_WRITER_OP_COPY` | Raw encoded copy. |
| `TLV_WRITER_OP_PRESERVE` | Exact source preservation; changed semantic content is `INVALID_VALUE`. |
| `TLV_WRITER_OP_BEGIN` | Begin constructed output. |
| `TLV_WRITER_OP_END` | End constructed output; scratch shortage is `BUFFER_TOO_SHORT`, while invalid lifecycle is `INVALID_STATE`. |

The remaining control vocabulary is unchanged: `TLV_VISIT_CONTINUE` continues,
`TLV_VISIT_STOP` succeeds early, and `TLV_VISIT_ERROR` produces `VISITOR`.
`TLV_DIAGNOSTIC_SEVERITY_ERROR`, `WARNING` and `INFO` remain presentation levels.
Unknown visitor discriminators produce `CALLBACK`.

### Concrete producer changes

| Current producer or behavior | Required target change |
| --- | --- |
| Generator reports `NULL_ARG` for a non-NULL Format without read/write capability | `UNSUPPORTED`; missing required top-level pointers retain `NULL_ARG`. C++ uses the same capability-before-configuration precedence. Implemented in #572. |
| Generator rejects `max_depth > 64` as `INVALID_ARG` | `UNSUPPORTED` for a request beyond fixed implementation capability. Implemented in #572. |
| Generator exhausts attempts when every candidate's minimum Value size exceeds `max_value_size` or `max_case_size` | Reject the contradictory domain as `INVALID_ARG` in `tlv_generator_workspace_size()`. Check all descriptors but allow a mixture of usable and unusable candidates. Implemented in #572. |
| Generator hides callback failures and successful encode/decode semantic mismatches as candidate rejection | Propagate detected `CALLBACK` and classify changed identifier presence/bytes, Value, or incomplete successful decoding as `CALLBACK`; abort even inside a child stream or after partial success. Implemented in #572. |
| Generator rejects candidates that fail ordinary Format operations or byte-exact reconstruction with preserved semantics | Retain the bounded candidate search and `LIMIT` when no nonempty case is produced. Format-specific identifier/framing feasibility cannot be decided by the Format-independent workspace query. Implemented in #572. |
| Generator workspace/attempt arithmetic and caller buffer checks | Retain `OVERFLOW` for unrepresentable workspace or attempt budget, and `BUFFER_TOO_SHORT` for insufficient output/workspace. Algorithm version and valid deterministic bytes are unchanged by #572. |
| `tlv_value_constraint_validate()` returns `SCHEMA` for invalid bounds, enum or allowed-values storage | Validate the definition as `INVALID_SCHEMA`; valid constraints rejecting data produce `SCHEMA` + `VALUE`. |
| Generic Schema rule/group validation uses `SCHEMA` in fail-fast validation and `INVALID_ARG` in report preflight | Invalid definition -> `INVALID_SCHEMA`, independent of which validation entry point is called. |
| Generic Schema/LLDP/DHCP required-field checks and DER missing components differ | `SCHEMA` + `MISSING`; preserve builtin-owned requirements and explicit location anchors. |
| DER maximum depth exceeds `TLV_DER_MAX_DEPTH` | Valid request beyond implementation capability -> `UNSUPPORTED`; actual input exceeding the accepted configured depth remains `LIMIT`. |
| DER arena/scratch and Tree Reader frame exhaustion use `LIMIT` | `BUFFER_TOO_SHORT` with named workspace and capacity units. |
| DER required component has a different callback presence/size between measurement and encoding | `CALLBACK`, not input `SCHEMA` or `INVALID_VALUE`. |
| Query successful codec hook returns wrong type, nonempty NULL data or invalid UTF-8 | `CALLBACK`; record successful provider result and the violated output contract instead of inventing a codec failure. |
| Query currently maps every codec error to `INVALID_VALUE` | Propagate the new shared result and conversion detail. |
| Structure Codec collapses all validation failures | Preserve the original Reader/Schema result and detail. |
| Query lifecycle/provider/argument failures use temporary #548 categories | Apply the Query table while retaining pre-initialization safety guards. |
| Diagnostic path overflows its optional inline capacity | Retain outer ancestors and `omitted`; do not turn a deeper input error into a location-collection error. |

## Implementation handoff and validation

This design completes #551. Issue #552 implements `INVALID_STATE`, Query kind
`STATE`, facade mappings and `INVALID_VALUE` for malformed structural feeds.

Issue #554 implements unsupported capability, workspace and callback classifications
including impossible preorder depth returned by a Tree Writer source callback.
The separate Codec result domain and its lossless propagation migrate in #556;
other Query detail kinds and the remaining result classes are follow-up work. No append-only or numeric ABI guarantee is attached to
`INVALID_STATE = 19` or `STATE = 12`. The complete target API is not yet available.
The follow-up implementation replaces enums/signatures/layouts directly and
updates their Doxygen contracts. It must cover common result strings, all
native producers, C++ facades, Go/Rust/Python/Lua/JS-WASM, CLI rendering and
binding ownership/ABI declarations together. Rebuild native clients; regenerate
ABI snapshots and serialized internal Query images as needed. Do not preserve
obsolete enum numbers or introduce a translation mode for the old behavior.

Implementation acceptance requires the following semantic checks, in addition
to documentation and build checks:

- Every result and detail in the inventory has a target producer classification;
  no old enum name, codec conversion table or offset-only error signature remains.
- Invalid schema definitions are distinguishable from input violations before
  validating data; missing requirements behave uniformly across builtins.
- Final truncation, non-final shortage, normal EOF, destination shortage,
  workspace shortage and processing budgets have distinct specified outcomes.
- Reader and Codec failures survive Query/Schema/Document composition with their
  result, origin and typed detail. Reader limit tests include the frame-capacity
  reclassification and safe absent detail.
- Legitimate callback errors, valid early stops and invalid successful callback
  payloads exercise separate paths; providers are not called twice for diagnosis.
- Locations cover known zero, unknown, empty EOF spans, nested origins, absent
  ordered/unordered components, DER hypothetical output and truncated paths.
- Existing #548 aliasing, reentrancy, failed-execution and diagnostic publication
  tests remain effective under the target codes and kinds. #549/#550 coverage
  retains output-position and path information.
- Unit, integration, standalone fuzz assertions, capability-disabled builds,
  ABI checks and public binding conformance use the same target semantics.
  Targeted local success must be reported separately from full hosted coverage.

Use this inventory to implement producer changes, then update the
[error reference](../reference/errors.md) to the resulting public API. Keep
protocol policy in builtins and generic error semantics in the common contract.
