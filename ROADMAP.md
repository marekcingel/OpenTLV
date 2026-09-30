# Roadmap

[Back to project overview](README.md)

OpenTLV's planned foundational architecture has three phases:

1. Execution Foundation
2. Runtime Model & OTLV
3. Compilation

Phase 1 is the current focus. Later phases describe architectural direction,
not finalized language syntax, public APIs or implementation details. Phase 3
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
Definition → Format → Field Encoding → Layout → Element → Schema → Codec
```

This is a conceptual relationship, not a mandatory processing pipeline or
module dependency graph. Field Encoding provides reusable wire-field
mechanics for Format composition. Layout describes the location of a concrete
element's wire parts; reusable layout configuration belongs to Format.
Document is the core owned representation built on these primitives.
See the [architectural rules](docs/concepts/architectural-rules.md) and
[architecture overview](docs/concepts/architecture.md) for their boundaries.

Scope includes the portable C99 execution core, the C++11+ wrapper, Reader,
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

Make the complete OpenTLV model dynamically describable, including both wire
representation and semantic/structural information. Runtime Format and runtime
Schema/Codec configuration belong to this same phase.

Planned scope:

- The `.otlv` declarative language, parser and abstract syntax tree (AST).
- Semantic analysis and symbol resolution.
- A canonical internal intermediate representation (IR).
- An immutable runtime `tlv_model_t`, model loading, ownership and introspection.
- Runtime Definition configuration.
- Runtime Format / Field Encoding / Layout configuration.
- Runtime Schema configuration.
- Runtime Codec configuration.

The conceptual pipeline is:

```text
.otlv → AST → semantic analysis → IR → tlv_model_t → execution descriptors
```

The canonical IR is lowered to the existing execution contracts rather than
replacing them. `tlv_format_t` remains a lightweight execution descriptor; it
is not the canonical semantic representation of a Format. Runtime configuration
composes the same concepts as native implementations, without parallel runtime
Element, Schema or Codec architectures.

Model construction and loading may allocate. TLV processing using an already
constructed immutable model should remain allocation-free, using the execution
foundation's explicit buffer and workspace contracts. This does not remove the
owned storage requirements of Document or other explicitly owning operations.

## Phase 3 — Compilation

Use the same canonical model and IR to produce specialized compiled
implementations. Both backends reuse the OTLV frontend, including semantic
analysis and symbol resolution before IR construction:

```text
.otlv → AST → IR → runtime model
.otlv → AST → IR → optimizer/code generator → generated implementation
```

Runtime and compiled execution must preserve equivalent OTLV semantics,
including wire representation, structural validation and value interpretation.
Generated implementations specialize the same execution contracts instead of
creating a separate architectural model.

Phase 3 completes the planned foundational OpenTLV architecture.

## Milestone descriptions

The following release-series labels organize the planned work; they do not
make architectural phases a permanent numbering scheme for major releases.

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

### 3.x — Compilation

Compile the canonical OpenTLV model into specialized implementations. Reuse the
same OTLV frontend and IR for runtime and compiled backends while preserving
equivalent model semantics. This completes the planned foundational architecture.

## Versioning after Phase 3

Architectural phases and semantic-version major numbers are separate concepts.
After Phase 3, OpenTLV continues normal SemVer evolution:

- PATCH — compatible fixes.
- MINOR — backward-compatible functionality.
- MAJOR — breaking public API/ABI changes.

Future `4.0.0`, `5.0.0` and later releases therefore do not imply Phase 4,
Phase 5 or additional foundational architectural phases.
