# C API reference

The C API reference is generated from the public [tlv](../../tlv/include/tlv)
headers with Doxygen and published with this site. Open the
[generated C API reference](api/c-api/html/index.html) for exact signatures,
ownership, lifetime and error contracts. It covers all shipped formats and
builtins, including those disabled in a particular library build.

Each area below pairs the generated reference with the guides and concepts
that explain it.

## Core types and utilities

[Generated reference](api/c-api/html/group__core.html). Read first:
[C core types](../concepts/core-types.md),
[borrowed values](../concepts/value.md),
[logical lengths](../concepts/length.md), [byte order](../concepts/endian.md)
and [memory ownership](../guides/memory.md).

## Diagnostics

[Generated reference](api/c-api/html/group__diagnostics.html). Read first:
[diagnostics](../guides/diagnostics.md).

## Reader

[Generated reference](api/c-api/html/group__reader.html). Read first:
[pull-based Reader](../guides/reader.md) and [formats](../formats/README.md).

## Writer

[Generated reference](api/c-api/html/group__writer.html). Read first:
[formats](../formats/README.md).

## Deterministic wire generation

The native `<tlv/generator.h>` API generates complete nonempty TLV streams
through Writer, with no allocation. The C++ facade is `<tlv++/generator.hpp>`.
Provide an ordered candidate table of borrowed identifiers and inclusive Value
size intervals, together with seed, case index and element/depth/Value/case
limits. Format alone classifies constructed tags; their Values are generated
child streams. Root depth is zero. Workspace requires
`(max_depth + 1) * max_case_size` bytes, disjoint from output and inputs.
Output capacity must be at least `max_case_size`; larger buffers do not alter
the generated case. Maximum supported depth is 64.

Algorithm version `TLV_GENERATOR_VERSION`, Format/configuration, ordered
candidates, all limits, seed and case index identify a reproducible case.
Generation does not depend on earlier calls. Each accepted element is decoded
and re-encoded with Writer to verify byte-exact reconstruction, including
constructed children. A bounded search returns `TLV_ERR_LIMIT` when no nonempty
case can be produced; output size is unchanged on failure, while buffer bytes
may change. Values sample interval ends and 127/128/255/256 boundaries.

Candidates describe independently composable wire elements. Exclude terminal
markers (such as DHCPv4 END or NFC Type 2 Terminator) and identifiers requiring
message-level ordering from the random table. Generation does not infer Schema,
Codec, terminators or protocol-level message rules. Primitive Value bytes are
arbitrary; validity here means Format/Writer-valid framing. For BER, use an
opaque identifier such as `04` and a constructed identifier such as `30`.
For Fixed, use identifiers of the configured width; Bluetooth LTV, DHCPv4 and
NFC Type 2 accept ordinary one-byte candidate tags. Custom bidirectional
Formats use the same API without builtin dispatch.

Executable C and C++ usage and reconstruction checks are in
[`generator_test.cpp`](../../tests/unit/generator_test.cpp). CLI generation,
language bindings and a dedicated property suite are separate work.

## Traversal

[Generated reference](api/c-api/html/group__traversal.html). Read first:
[pull-based Tree Reader](../guides/reader.md#pull-based-tree-traversal),
including caller-owned frame storage and Visitor adapters.

V1 paths use `<tlv/query/query.h>` with copyable opaque storage, bounded parsing
and canonical formatting. Full-language compilation and S0/S1/S2 execution use
`<tlv/query/program.h>`: discover scratch, immutable program and runtime workspace
requirements independently, then retain the execution across STOP/NEED_MORE_DATA.
S1 publishes proven root-scope decisions at END. S2 uses explicit candidate
capacity and stable borrowed input until finalized ordered publication. Compiled
Document execution uses the same VM with caller-owned Query storage, constructed
Value storage and Tree Writer staging; global preceding/following plans require it.
See [path queries](../guides/queries.md) and the
[Query language contract](../concepts/query-language.md) for syntax, resource
budgets, relative contexts and explicit validation/pruning coverage. Compiled
program facades in bindings are part of the later Query integration phase.

## Schemas

[Generated reference](api/c-api/html/group__schemas.html). Read first:
[schemas and length validation](../guides/schemas.md).

## Codecs

[Generated reference](api/c-api/html/group__codecs.html). Read first:
[value codecs](../guides/codecs.md).

## Formats

[Generated reference](api/c-api/html/group__formats.html). Read first:
[format overview](../formats/README.md), [BER](../formats/asn1/ber.md),
[DER](../formats/asn1/der.md) and [CER](../formats/asn1/cer.md).

## Builtins

[Generated reference](api/c-api/html/group__builtins.html). Read first:
[DER](../standards/der/README.md), [CER](../standards/cer/README.md) and
[EMV](../standards/emv/README.md).

## Copy utilities

[Generated reference](api/c-api/html/group__copy.html). Read first:
[copy helpers](../guides/copy.md).

## Mutable document

[Generated reference](api/c-api/html/group__document.html). Read first:
[mutable documents](../guides/document.md).

## Other entry points

[Files](api/c-api/html/files.html) and
[data structures](api/c-api/html/annotated.html). The C++ wrappers have their
own [C++ API reference](cxx-api.md), which links back to these C declarations.

To build the reference locally, see
[Generate the C API reference](../../CONTRIBUTING.md#generate-the-c-api-reference).
The generated pages exist only in a built site or in the Documentation
workflow artifacts, so the direct links above do not resolve when this page is
read on GitHub.
