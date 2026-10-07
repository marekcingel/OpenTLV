# Roadmap

[Back to project overview](README.md)

OpenTLV's planned foundational architecture has four phases:

1. Execution Foundation
2. Runtime Model & OTLV
3. Protocol Inference
4. Compilation

Phase 1 is the current focus. Later phases describe architectural direction,
not finalized language syntax, public APIs or implementation details. Phase 4
completes the planned foundational architecture; architectural phases and
semantic-version major numbers are separate concepts.

## Phase 1 — Execution Foundation

Discover, generalize, validate and stabilize the reusable generic C primitives
required to represent TLV format families. All later phases build on this
execution foundation and preserve its shared contracts.

Independent real-world standards such as BER/EMV, Bluetooth, LLDP, DHCP, NFC
and future formats form a standards playground: use them to discover missing
generic primitives and refine the shared TLV taxonomy. This is a validation
strategy, not a claim that every standard is already supported. See the
[format and standard support checklist](README.md#format-and-standard-support)
and [format expansion candidates](docs/formats/format-roadmap.md).

The canonical technical model remains centered around:

```text
REUSABLE DESCRIPTIONS
Definition    Format    Field Encoding    Schema    Codec

FORMAT CONSTRUCTION (implementation choices)
Field Encoding + composition rules -- optional helpers --+
Direct implementation ----------------------------------+--> Format contract

OPERATIONS                              RUNTIME REPRESENTATIONS
wire bytes -- Reader using Format ----> Element + source Layout
wire bytes <-- Writer using Format ---- Element

Definition, Schema and Codec are optional, not processing stages.
```

Field Encoding provides reusable wire-field mechanics. Composition belongs to
Format, not to a separate canonical layer. Generic composition helpers are
optional; a Format may implement the same complete contract directly. Reader
and Writer use Format without requiring Definition, Schema or Codec. Layout
describes source ranges for a concrete encoded instance; Writer can encode an
Element without a previously parsed Layout.
Document is the core owned representation built on these primitives.
See the [architectural rules](docs/concepts/architectural-rules.md) and
[architecture overview](docs/concepts/architecture.md) for their boundaries.

Scope includes the portable C99 execution core, the idiomatic C++11+ API, Reader,
Writer, tree traversal, Visitor, Document, Query, structural schemas and value
codecs, together with native formats and standard-specific capabilities.
Bindings, CLI tooling, testing, fuzzing, documentation and distribution make
these contracts usable and verifiable across supported environments.

Design Phase 1 with Phase 2 requirements in mind without implementing Phase 2
prematurely. For every generic primitive, consider:

1. Can it represent the required real-world TLV format generically?
2. Could a future declarative model and canonical IR describe it completely?
3. Could both runtime lowering and future code generation consume it?

These questions place design pressure on the primitives while protocol-specific
policy remains in standards and extensions.

## Phase 2 — Runtime Model & OTLV

The [runtime model and canonical IR architecture](docs/concepts/runtime-model.md)
defines the planned construction pipeline, ownership and execution boundaries.

Make the complete OpenTLV model dynamically describable, including both wire
representation and semantic/structural information. Runtime Format and runtime
Schema/Codec configuration belong to this same phase.

Planned scope:

- The `.otlv` declarative language, parser and abstract syntax tree (AST).
- Semantic analysis and symbol resolution.
- A canonical internal intermediate representation (IR).
- An immutable runtime `tlv_model_t`, model loading, ownership and introspection.
- Runtime Definition configuration.
- Runtime Format composition / Field Encoding configuration.
- Runtime Schema configuration.
- Runtime Codec configuration.
- OTLV developer tooling: CLI integration, diagnostics, editor support, syntax
  highlighting, completion, navigation, formatting, VS Code integration and
  language-aware tooling such as an LSP. These belong to the declarative-model
  phase; not every tool must block completion of the runtime architecture.

The conceptual pipeline is:

```text
.otlv → AST → semantic analysis → IR → tlv_model_t → execution descriptors
```

The runtime model is independent of the OTLV frontend. `.otlv`, programmatic
APIs and future Protocol Inference construct the same canonical semantic model.
Inference candidates and evidence belong to construction and analysis, not to
the immutable executable `tlv_model_t`.

The canonical IR is lowered to the existing execution contracts rather than
replacing them. `tlv_format_t` remains a lightweight execution descriptor; it
is not the canonical semantic representation of a Format. Runtime configuration
composes the same concepts as native implementations, without parallel runtime
Element, Schema or Codec architectures.

Model construction and loading may allocate. TLV processing using an already
constructed immutable model should remain allocation-free, using the execution
foundation's explicit buffer and workspace contracts. This does not remove the
owned storage requirements of Document or other explicitly owning operations.

## Phase 3 — Protocol Inference

Protocol Inference depends on Phase 2 but is a separate architectural phase.
It discovers models from observations rather than constructing a known model
from a description. It precedes Compilation so that incomplete candidates,
alternatives, contradictions and incremental refinement stress-test the
canonical semantic model and IR before generated implementations depend on them.
It is a planned capability, not an implemented inference engine. It observes
unknown binary/TLV traffic incrementally and produces
candidate structural descriptions using the normal Reader and execution
contracts. It must not introduce an inference-specific parser.

Planned principles:

- Search and refine candidate Format compositions and Field Encodings across
  observations, pruning alternatives and progressively sampling where needed.
- Infer Schema constraints from repeated messages, including occurrence,
  cardinality, length and nesting evidence.
- Retain supporting and contradicting observations, wire coverage, invalid
  boundaries, competing alternatives and convergence/stability information.
  Evidence remains inspectable rather than reduced to an opaque confidence score.
- Separate observed wire facts from analyst-added names, codecs and semantics;
  bytes alone do not establish a field's business meaning.
- Export validated discoveries as a normal editable `.otlv` model, so supported
  descriptions can use the normal decode, query, validate and diff tooling
  when those runtime-model tools exist.
- Keep AI optional and downstream from deterministic inference and evidence.

Runtime Model design should allow the same semantic model to be constructed
from `.otlv`, programmatic APIs and future inference. Incomplete candidates and
incremental observations are design considerations, not execution-ready models:
validate a candidate before publishing an immutable executable model. APIs,
algorithms, heuristics and delivery dates remain undecided.

## Phase 4 — Compilation

Use the same canonical model and IR to produce specialized compiled
implementations. Both backends reuse the OTLV frontend, including semantic
analysis and symbol resolution before IR construction:

```text
.otlv → AST → semantic analysis → IR → tlv_model_t → execution descriptors
.otlv → AST → semantic analysis → IR → optimizer/code generator → generated implementation
```

Runtime, native and compiled execution must preserve equivalent OTLV semantics,
including wire representation, structural validation and value interpretation.
Generated implementations specialize the same execution contracts instead of
creating a separate architectural model.

Phase 4 completes the planned foundational OpenTLV architecture.

## Phase dependencies and model construction

The intended progression is PROCESS → DESCRIBE → DISCOVER → COMPILE:

```text
Phase 1 — Execution Foundation
             ↓
Phase 2 — Runtime Model & OTLV
             ↓
Phase 3 — Protocol Inference
             ↓
Phase 4 — Compilation
```

The semantic model has multiple construction paths:

```text
.otlv frontend ─────┐
programmatic API ───┼──→ canonical semantic model ──┬──→ runtime execution
Protocol Inference ┘                              └──→ compiled execution
```

Inference refines observations into candidates, validates them, then publishes
the same canonical model or exports editable `.otlv` for existing tooling:

```text
unknown observations → inference → candidate model → validation/refinement
    → canonical model / .otlv → existing OpenTLV tooling
```

Phase 1 uses these later requirements as design pressure without prematurely
implementing runtime models or inference. Inference consumes and validates the
Phase 2 architecture; it does not weaken the immutable executable model contract.

## Milestone descriptions

The following descriptions organize the planned work. Existing release-series
labels do not require future phase numbers to match SemVer major versions.

### 1.x — Execution Foundation

Discover, validate and stabilize the generic C primitives that form OpenTLV's
execution foundation. Use independent real-world TLV standards to refine the
shared taxonomy across Definition, Format, Field Encoding, Layout, Element,
Schema, Codec and Document.

### 2.x — Runtime Model & OTLV

Make the complete OpenTLV model dynamically describable through OTLV. Introduce
the language frontend, semantic analysis, canonical IR, immutable runtime model,
runtime loading and introspection while preserving allocation-free TLV
processing after model construction.

### Protocol Inference milestone scope

Discover candidate models from unknown observations using the Phase 2 semantic
model and existing execution contracts. Preserve alternatives and evidence,
validate and refine candidates, and export editable `.otlv` descriptions.

### Compilation milestone scope

Compile the canonical OpenTLV model into specialized implementations. Reuse the
same OTLV frontend and IR for runtime and compiled backends while preserving
equivalent model semantics. This completes the planned foundational architecture.

## Versioning and architectural phases

Architectural phases and semantic-version major numbers are separate concepts.
Throughout and after the four phases, OpenTLV follows normal SemVer evolution:

- PATCH — compatible fixes.
- MINOR — backward-compatible functionality.
- MAJOR — breaking public API/ABI changes.

A future major release does not imply entry into the correspondingly numbered
architectural phase or the introduction of another phase.
