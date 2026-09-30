# Canonical processing pipeline

The #401 audit covers the generic Reader, Tree Reader, Visitor, Query, Document,
Writer and Tree Writer engines and their C++, Rust and Python adapters.

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
| Document parsing | `tlv/src/document/document.c` | Resumable Builder consuming Tree Reader items |
| Document lookup | `tlv/src/document/document.c` | Node preorder feeding the same Query matcher |
| Document encoding | `tlv/src/document/document.c` | Node preorder feeding `tlv_tree_writer_measure`, then Writer encoded copy |
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

C++ exposes `document_builder::create(reader, &item)` and resumable `consume()`.
The reader is borrowed and must not be pulled, skipped or visited until the builder
finishes or is destroyed. Its Format/context must outlive the resulting document.

Rust exposes `DocumentBuilder::current_subtree(&mut reader, depth, count)` and
Python exposes `DocumentBuilder(reader, current_subtree=True)`. They use the last
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
