# Phase 2 runtime model and canonical IR

This page defines the intended Phase 2 architecture for issue #420. It guides
Phase 1 design; it does not introduce an implemented runtime, OTLV syntax or
public model API. The [roadmap](../../ROADMAP.md) places Runtime Model & OTLV
after the Execution Foundation and before Compilation. The
[core architectural rules](architectural-rules.md) apply to all three phases.

## From source to execution

```text
.otlv source
     ↓
parser
     ↓
AST
     ↓
resolver / semantic analysis
     ↓
canonical IR
     ↓
tlv_model_t
     ↓
lowering
     ↓
execution descriptors
     ↓
Reader / Writer / Document
```

This is a conceptual construction and execution path, not a requirement for
separate public APIs at every step. Model construction includes lowering and
preparing execution contexts before publishing a successfully constructed,
immutable model. Processing bytes must not trigger deferred parsing, resolution
or allocating compilation work.

OTLV is one frontend for an OpenTLV model. Other frontends or programmatic
builders may produce the same canonical semantics. Native implementations
remain usable directly through the existing execution contracts without an
OTLV frontend or a runtime model.

## AST and semantic analysis

The abstract syntax tree (AST) represents source syntax. It may retain source
locations, names, imports, aliases, syntactic shorthand and unresolved
references. It belongs to the frontend and must not enter the TLV processing
path.

The resolver and semantic analysis establish symbol identity, resolve imports
and references, validate semantic consistency and normalize shorthand before
producing canonical IR. Invalid or unresolved source must not become an
executable model. Diagnostics may retain source provenance, but source spelling
and locations do not define runtime semantics.

Execution must not borrow AST nodes or depend on source text remaining alive.
Any data needed after construction must have an explicit model or external
lifetime contract.

## Canonical IR

The canonical intermediate representation describes resolved, normalized model
semantics: what the model means, independently of a particular execution
backend. Equivalent source descriptions should be capable of producing the
same conceptual IR despite differences in aliases, imports or shorthand. This
does not require a stable binary serialization or byte-identical IR storage.

The IR must express the existing conceptual boundaries:

| Concept | Semantic responsibility in the model |
| --- | --- |
| Definition | Identifiers and descriptive names within a registry; no wire encoding or contextual validation policy. |
| Format | Complete element framing, field order, length scope and constructed representation. |
| Field Encoding | Reusable fixed-width, variable-width and packed wire-field mechanics. |
| Layout | Rules/configuration for arranging wire parts and producing source ranges; concrete offsets belong to decoded instances. |
| Schema | Structural and contextual constraints such as occurrence, ordering, allowed children and field lengths. |
| Codec | Interpretation and conversion of Value bytes using the selected value representation. |

Layout needs this distinction because a compiled model describes reusable
rules, while the Layout of a particular Element is produced only when those
rules are applied to bytes. The existing `tlv_source_t` / `tlv_range_t` and
`tlv_element_t` contracts remain the runtime representations; the IR does not
introduce a parallel runtime Element.

Standard-specific policy stays in standards and extensions. The IR should
describe compositions of reusable mechanisms and explicit semantic
capabilities, rather than requiring protocol branches in generic Reader or
Writer code. Callback addresses and opaque backend contexts are not a
sufficient canonical description of model semantics.

## Model ownership and lifetime

The planned `tlv_model_t` is the ownership and lifetime boundary for a compiled
runtime model. It is an OpenTLV object, not an OTLV-specific syntax object.
It may own:

- canonical IR objects and resolved references;
- tag and constant storage;
- Format, Schema and Codec configuration;
- lookup tables and indexes;
- lowered execution contexts and descriptor storage.

A successfully constructed model is immutable. Any required execution
configuration must be prepared before it is published. Per-operation cursor
state, output buffers and scratch workspaces belong to the operation or caller,
not to mutable shared model state.

Descriptors and their immutable contexts may borrow model-owned storage.
The model must outlive every operation or retained descriptor using that storage.
Copying a lightweight descriptor does not extend the owner's lifetime. A
retained Element may also borrow model-owned identifier bytes, so its lifetime
must respect both model storage and input-buffer storage as applicable. Model
ownership does not imply ownership of the input TLV bytes.

Builders and loaders must make any external lifetime dependencies explicit;
they must not leave execution dependent on temporary frontend storage. The
exact destruction, handle and binding ownership APIs remain Phase 2 design
work. These requirements build on the existing
[Format context ownership contract](../guides/memory.md#format-context-ownership-and-lifetime).

## Lowering and execution descriptors

Existing descriptors such as `tlv_format_t` are lightweight execution interfaces
with function pointers and borrowed immutable contexts. They are optimized for
executing a contract, not for expressing or introspecting its full semantics.

```text
canonical IR
     ↓
lowering
     ↓
tlv_format_t + execution context
     ↓
Reader / Writer
```

Lowering selects implementations and prepares the configuration needed to
execute the resolved semantics. Schema and Codec configuration must likewise
use their shared execution contracts. Reader and Writer consume descriptors;
they do not parse OTLV, traverse the AST or interpret canonical IR objects.
Document composes the existing processing primitives and remains the owned
representation of message data, distinct from the model that describes it.

The dependency direction is from frontend/model construction toward execution
contracts. Generic processing must not depend on the frontend or model loader.
Reader still works with Format alone: Definition lookup, Schema validation and
Codec interpretation remain optional consumers rather than mandatory parsing
stages. See the [Format and Element contract](format-contract.md).

## Allocation boundary

> Allocation belongs to model construction, never to TLV processing.

For the runtime model, this means parsing, resolution, IR construction,
lowering and preparation of indexes/contexts may allocate. Once construction
has succeeded, using the immutable model must preserve the allocation-free
execution properties of the C core. Reader, Writer and other bounded hot-path
operations use explicit caller-provided buffers and workspaces; model-backed
callbacks must not introduce hidden heap allocation.

This principle does not remove the storage requirements of explicitly owning
operations such as Document construction, mutation or encoding with temporary
storage. Those allocations remain part of the owning API's documented
contract, separate from model execution. Loading a model does not make an
owning operation allocation-free.

A future caller-provided arena or workspace may also allow model construction
without heap allocation. Its capacity, lifetime and failure contracts are
future design work, not prerequisites for documenting this boundary.

## Shared IR for runtime and compilation

The same canonical IR must eventually support both backends:

```text
canonical IR ──→ runtime model / lowering ──→ execution descriptors
       │
       └───────→ optimizer / code generation ──→ generated implementation
```

The generated/optimized implementation must preserve the same wire, structural
and Value semantics and the same execution contracts. Runtime callback state
must not be the only place where meaning is recorded: that would force code
generation to reconstruct semantics from an execution implementation.

This is a Phase 1 design requirement and a Phase 3 backend direction, not a
request to implement compilation during Phase 1 or Phase 2. An alternative
frontend should not require a different runtime or compilation architecture.

## Evolution and standards playground

The canonical IR initially need not be a stable public C ABI. Phase 2 is the
period in which real models can expose missing abstractions and the IR,
runtime model and OTLV language can evolve together. Public APIs may expose
`tlv_model_t`, loading, builders and semantic introspection without exposing
the exact internal IR representation. Introspection must not require callers
to reverse-engineer execution callbacks or their opaque contexts.

Continue the Phase 1 standards-playground method at the model level:

```text
real standard
     ↓
OTLV model
     ↓
missing semantic capability?
     ↓
identify the smallest reusable abstraction
     ↓
extend / refine IR
     ↓
verify against other standards
```

Use independent standards to test the abstraction, while retaining their
specific policy in the corresponding standard model or extension. A single
standard's syntax should not dictate the canonical representation.

For each Phase 1 primitive, review:

1. Can it represent the real wire format generically?
2. Can the future IR describe it without protocol-specific runtime logic in
   the generic processing core?
3. Can that representation support both runtime lowering and future code
   generation?

These checks constrain the foundation without requiring Phase 2 implementation
or freezing its internal representation prematurely.
