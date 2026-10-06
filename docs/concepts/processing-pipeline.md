# Canonical processing pipeline

The #401 audit covers the generic Reader, Tree Reader, Visitor, Query, Document,
Writer and Tree Writer engines and their C++, Rust and Python adapters.

This technical contract extends the
[canonical architecture overview](architecture.md#conceptual-model).
For practical API selection, begin with
[Choose a processing API](../guides/processing.md); current language coverage
is recorded in the [binding matrix](bindings.md#capability-implementation-matrix).
Document is the canonical owned mutable representation; structural events are
the borrowed traversal/construction representation.

## Canonical structural events (#402)

The canonical streaming representation is `tlv_tree_event_t` from `tlv/tree.h`:
`BEGIN`, `ELEMENT`, `END`. Document remains the materialized representation.
Tree Reader produces events with `tlv_tree_reader_next_event[_diag]`; Tree Writer
accepts them with `tlv_tree_writer_write_event[_diag]`. Neither depends on the
other. Both use the same Format-independent event contract.

| Representation considered | Decision |
| --- | --- |
| Element + depth | Complete preorder can describe a tree, but every consumer must infer closures and final EOF closure. Retained only as a node projection. |
| ENTER / ELEMENT / LEAVE | Equivalent if ENTER carries the container and ELEMENT only primitives; a separate container ELEMENT is redundant. |
| BEGIN / ELEMENT / END | Selected: explicit, balanced operations directly map to Writer. |
| Element + closure count | Requires expanding implicit closes and a terminal record; no consumer simplification. |

```text
BEGIN E1       depth=0
ELEMENT 01     depth=1
BEGIN E2       depth=1
ELEMENT 02     depth=2
END            depth=1
END            depth=0
```

BEGIN and ELEMENT carry the existing Element and optional Source metadata.
Reader BEGIN carries the complete original container Value. Writer ignores that
Value and encodes the children supplied between BEGIN and END, avoiding duplicate
children and regenerating lengths/framing with the destination Format. END carries
no Element, Tag or Source; depth identifies the closed level. Its offset is the
absolute end of the original Value, before any trailer. Empty containers emit
BEGIN then END. Roots form a sequence without a synthetic parent. EOF is a result,
not an event; every pending END must be delivered before final exhaustion.

Depth starts at zero. Writer rejects mismatched depth, unknown operations,
unmatched END, missing END at `finish()`, and classification incompatible with the
destination Format. BEGIN/ELEMENT count toward `max_elements`; END does not.
Reader needs a frame only when entering nonempty children, permitting skip after
a depth/capacity failure. Writer needs a frame for every BEGIN, including empty
containers. Both are iterative and allocation-free with caller-owned bounded
storage. Sequential Reader remains independently usable for flat sequences.

### Continuation, borrowing and subtree skipping

This is a structural event stream, not early-header streaming. BEGIN is published
only when the entire encoded parent is contiguous, preserving the complete-Element
Format/Reader contract. Known END events are delivered before NEED_MORE_DATA at
the next root. NEED_MORE_DATA publishes nothing and preserves cursor, frames and
output event. Resuming neither repeats successful events nor fabricates closure.
A malformed child inside an already complete parent is a terminal framing error;
appending input cannot repair it and no successful END is fabricated.

Node payloads borrow their original input/Format storage. A later pull does not
itself invalidate immutable retained views, but moving, overwriting or releasing
their backing storage does. Input replacement cannot retarget an old view.
Traversal frames store numeric continuations, never borrowed Elements. END
therefore remains available after parent headers have been discarded or relocated.

After BEGIN for a nonempty container, `skip_subtree()` omits descendants without
validating them; the next event is its END with `skipped=1`. Writer and Document
Builder reject omitted content rather than silently interpreting it as an empty
container. Skipping does not prescribe a transformation policy. For example, code
that copies a complete subtree itself must suppress that subtree's BEGIN and its
skipped END instead of forwarding them as a second encoding.

Writer normally borrows BEGIN Tags until matching END. Configure
`tlv_tree_writer_set_tag_storage()` to copy them into a bounded caller-owned arena
so a pipeline can discard input after each accepted event. Empty present Tags use
one byte to preserve presence; absent Tags need none. Arena exhaustion returns
LIMIT without consuming the event. Storage may be configured only with no open
parents. END releases its Tag capacity only on success. Binding facades also
support retaining owned Tags. Source metadata never determines output encoding.

On Writer failure keep the current event for retry before pulling another event.
Failures preserve the Writer cursor and accumulated bytes, following the existing
begin/write/end contracts. Output and scratch remain bounded; events do not add
an append-only output sink or remove whole-Value staging requirements.

### Consumers and projections

Visitor maps BEGIN/ELEMENT to existing node callbacks and ignores END; Query
uses that projection and its existing matcher. Query matches alone are not a
balanced stream. Document Builder consumes opens/closes directly. A selected-subtree builder consumes its
own END and leaves enclosing END events pending; its frontier can therefore
precede an enclosing trailer until the next pull. Document
encoding emits the same events to `tlv_tree_writer_measure_events()`. This one-shot
measurement helper stages exact bytes, reports required workspace, and requires
a fresh producer for retry, including after NEED_MORE_DATA. Persistent Writer
plus `write_event()` is the resumable path.

`tlv_tree_reader_next()` remains a thin node-only projection of the event engine;
it hides END, preserving existing item iteration. Node pulls can consume pending
ENDs left by a Builder before returning EOF or NEED_MORE_DATA; event pulls keep
the stronger one-event-or-no-state-change contract. Do not interleave node/Visitor
pulls and event pulls while expecting a complete balanced stream. There is one
traversal state machine. C++ exposes `next_event()`/`write_event()` and
`measure_tree_events()`, Rust `read_event()`/`write_event()`, and Python
`next_event()`/`write_event()`. Rust and Python retain owned BEGIN Tags until END.
Lua's existing missing Tree Reader/Writer facade remains a documented parity gap.

Rebuild C consumers and native bindings: Reader and Writer cursor layouts gained
state fields. Existing node-only entry points and serialized semantics remain
available; the shared event representation adds no protocol-specific policy.

## Removed superseded interfaces

The standalone C++ `visit_tree` template and `tlv++/reader/visitor.hpp` are removed.
Use `tlv::tree_reader` with caller-owned frames and its `visit()` method, which
also exposes diagnostics and incremental continuation.

The compact Schema report (`tlv_schema_issue_t`, `tlv_schema_report_t`,
`tlv_schema_validate_all`, `tlv_schema_issue_path_string`, `TLV_SCHEMA_PATH_MAX`)
is removed. Use `tlv_schema_diagnostic_t`, `tlv_schema_diagnostic_report_t` and
`tlv_schema_validate_all_diag`. The shared `tlv_diagnostic_path_t` contains
enclosing scopes; the affected tag is separate. Its capacity is
`TLV_DIAGNOSTIC_PATH_MAX`, replacing the old 16-tag limit. Format enclosing paths
through `tlv_diagnostic_path_string`, or copy the path and append the affected tag
when a full field path is needed and capacity permits.

C++ callers use `validate_all_diag`. Rust/Python callers use
`validate_diagnostics` and `SchemaDiagnosticReport.diagnostics`; `SchemaIssue`,
`SchemaReport` and the compact `validate_all` methods are removed. No compatibility
aliases remain. Rebuild consumers after this source/ABI-breaking removal.

## Dependency evidence

| Consumer | Implementation | Processing dependency |
| --- | --- | --- |
| Reader | `tlv/src/reader/reader.c` | `tlv_format_decode` through one shared read implementation |
| Tree Reader | `tlv/src/reader/tree.c` | `tlv_reader_next_source_diag`; iterative scope stack |
| Visitor | `tlv/src/reader/visitor.c` | Reader or Tree Reader pulls |
| Query | `tlv/src/query/query.c` | Tag/depth matcher; Tree Reader Visitor for buffer traversal |
| Document topology | `tlv/src/document/document.c` | Owned nodes and programmatic mutation; optional Format measurement validates inserted tags |
| Document parsing | `tlv/src/document/reader.c` | Reader + Document integration: resumable Builder consuming canonical structural events |
| Document lookup | `tlv/src/document/query.c` | Query + Document integration: node preorder feeding the same Query matcher |
| Document encoding | `tlv/src/document/writer.c` | Writer + Document integration: node events feeding `tlv_tree_writer_measure_events`, then Writer encoded copy |
| Tree Writer | `tlv/src/writer/tree.c` | Writer measurement and encoding; iterative parent stack |
| Writer | `tlv/src/writer/writer.c` | Format measurement and encoding |

These dependencies are acyclic. Definition registries and Schema/Codec are not
mandatory stages. Only Format and its reusable layout primitives interpret wire
framing. Constructed classification is a Format callback, including when used by
Tree Reader and Tree Writer.

Document's iterative node iteration, counting and destruction operate on owned
nodes, not encoded input. They must not be replaced with a byte parser. Likewise,
Tree Writer's semantic preorder callback supplies nodes; Tree Writer owns nested
encoding. The audited generic Reader/Writer tree engines contain no C recursion
or heap allocation. Format callbacks are caller-supplied code and have their own
resource and lifetime obligations.

Schema's scope occurrence/order checks may rescan a bounded scope through the
stateless Reader API; its nested validation uses Tree Reader. These are semantic
validation passes, not a second wire decoder. Protocol-specific semantic codecs
and complete parity for all binding capabilities are outside this pipeline audit.

## Ownership and continuation

Reader values borrow immutable input. Tags borrow input or immutable storage
provided by Format. Retained views require their original storage to remain live,
even when the cursor discards a prefix. Source ranges remain element-relative;
tree item offsets and Reader diagnostics identify absolute stream locations.

Incremental input publishes complete elements. A constructed parent requires its
complete contiguous extent before publication. `NEED_MORE_DATA` preserves cursor
state; malformed children inside a complete parent are terminal truncation errors.
Input replacement must retain the undiscarded suffix. Final EOF is distinct from
temporary exhaustion.

Reader frames, Writer frames, destination and scratch are caller-owned. Depth,
element count and workspace capacities bound their work/storage. Document is an
explicit allocating owner; its allocator copies selected content. Binding-owned
frames and language objects are also explicit higher-level ownership, not hidden
allocation in the C engine.

## Selecting a subtree

Feed each published item to the Query matcher. On a match, pass that same root
to `tlv_document_builder_create`; do not pull it again. Builder copies the root
immediately, consumes its descendants through the same Tree Reader, and leaves
the following sibling unread. Document depth limits are relative to the selected
root; the reader's global limits continue to apply.

C++ exposes `document_builder::current_subtree(reader)` and resumable `consume()`.
The reader is borrowed and must not be pulled, skipped or visited until the builder
finishes or is destroyed. Its Format/context must outlive the resulting document.

Rust exposes `DocumentBuilder::current_subtree(&mut reader, depth, count)` and
Python exposes `DocumentBuilder(reader, current_subtree=True)`. All three facades use the last
successful explicit pull, never a caller-fabricated root. Subsequent pulls, input
replacement, skips, visitors and builder creation invalidate this selection.
Match using `QueryMatcher.matches` before creating the builder. Visitor STOP
does not establish this explicit-pull selection. Rust exclusively borrows the
reader; Python rejects cursor operations during active building except input
replacement/status queries.

## Exact measurement and encoding

`tlv_tree_writer_measure` uses caller-owned output staging, scratch and frames.
It invokes the canonical encoding path because a Format may inspect encoded child
content when measuring a parent. Successful measurement therefore already has
complete output bytes. Reuse them through `tlv_writer_copy_encoded` instead of
replaying encoding.

On workspace exhaustion, required capacities are discovered lower bounds. Grow
storage and restart a deterministic semantic source. Source or Format callback
errors do not masquerade as workspace growth requests. Document handles workspace
ownership through its allocator. Separate Document size and encode calls each
prepare an encoding; a pure size-only, storage-free pass is not promised.

## Regression protection and limits of the audit

`Integration_Tlv_Pipeline` exercises a custom non-BER Format across all input
split positions, Query selection, Builder, mutation, exact measurement, output
capacity failures, absolute offsets and resource failures. Format callback counters
check that selection does not reparse its root or consume following siblings.
C++/Rust/Python Document tests exercise the facade transition and continuation.
Existing component tests cover Tree Writer workspace exhaustion and callback
failures, deep iteration, source preservation and format-family differences.

CTest's `architecture-pipeline` source guard rejects direct allocation in canonical
Reader/Writer engines, forbidden upward/protocol includes and direct Format
processing in higher layers. It is a targeted regression guard, not a general C
call-graph proof: new indirect callbacks or engines still require code review.
The [binding matrix](bindings.md#capability-parity-through-the-public-facade)
continues to track remaining capabilities, including Lua; this audit does not
claim full binding parity.
