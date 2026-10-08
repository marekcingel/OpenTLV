# Core architectural rules

These rules guide OpenTLV design, implementation and review. They define the
shared conceptual model and dependency boundaries for current and future work.
The [architecture overview](architecture.md) maps these concepts to the current
repository; the [Format and Element contract](format-contract.md) specifies the
current C API invariants.

The [roadmap](../../ROADMAP.md) defines four architectural phases: Execution
Foundation, Runtime Model & OTLV, Protocol Inference, and Compilation. Phase 4
completes the planned
foundational architecture; future SemVer major releases do not imply more phases.

The [architecture overview](architecture.md#conceptual-model) is the canonical
technical model; this page states its constraints. Protocol Inference is planned
Phase 3, consuming and validating the Phase 2
semantic model before Phase 4 Compilation. It reuses the same Reader, execution
contracts and canonical model rather than adding an inference-specific parser.
Incomplete candidates, alternatives and evidence belong to construction and
analysis; they must not weaken the immutable executable model contract.
Rules for `.otlv`, runtime models and generated implementations constrain future
design; they do not claim that these facilities are already implemented.

## 1. Generic core first

OpenTLV core must contain only generic TLV mechanisms.

- No EMV-specific logic in core.
- No ASN.1-specific logic in core.
- No Bluetooth-specific logic in core.
- Standards and protocols are built on top of generic primitives.
- Dependency direction is always:

```text
extensions / standards / presets
              |
              v
             core
```

Core must never depend on a specific standard.

---

## 2. Stable conceptual model

OpenTLV separates reusable descriptions, their implementation and the
operations that produce or consume runtime representations:

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

Composition belongs to Format rather than adding a canonical layer. Generic
composition helpers are optional; a Format can implement the same complete
contract directly. Reader and Writer use Format without requiring Definition,
Schema or Codec. Writer can encode an Element without a previously parsed
source Layout. Layout records source ranges for a concrete encoded instance.
See the [conceptual model](architecture.md#conceptual-model) for the mapping to
the current implementation.

Their responsibilities must remain separated.

### Definition

Provides a minimal registry of identifiers and their descriptive names.

It answers:

> What identifier is this, and what is its descriptive name in this registry?

It must not define how the identifier is encoded on wire.

Identifier meaning is scoped to a registry; a name is not a unique domain
identity. Generic Definition must not acquire codec pointers, schema references,
ASN.1 types, EMV value kinds, length rules or other standard-specific metadata.
Standards may own richer dictionaries that compose these capabilities, optionally
reusing Definition entries. A dictionary is domain composition, not a new
mandatory layer; a factory is only a possible implementation choice.
Definition lookup is not a required parsing step.

See the [Definition boundary audit](definition-boundaries.md) for the evidence
and the separate assessment of logical identity versus identifier mapping.

### Format

Defines how an element is represented on wire.

It answers:

> How do I find Tag / Length / Value in these bytes?

Examples of Format properties:

- field ordering
- tag encoding
- length encoding
- fixed/variable widths
- endian rules
- constructed representation
- length scope
- additional Header fields and Trailer framing

Format must not interpret the semantic meaning of Value.

### Field Encoding

Provides reusable mechanics at two levels:

- Low-level bit, byte and integer primitives, including packed unsigned fields.
- Identifier and Length encodings, including fixed-width, variable-width and
  escape-prefixed fields and their read/write callback contracts.

These mechanics live under `tlv/field/` and do not describe complete elements.
Format may compose them with field ordering, length scope, tag-only selection
and boundary resolution through the optional helpers in `tlv/formats/compose.h`.
Composition is part of Format, not a separate architectural layer.
Configurations embed the reusable Identifier and Length descriptions; adapters
follow the single-field validation and prefix-reporting contract in `tlv/field/`.
Protocol-specific restrictions remain in the standard implementation; field
mechanics do not interpret Value semantics. Call these mechanisms field
encodings; reserve Codec for conversion
between Value bytes and application values.

### Layout

Represents where the parts of one concrete encoded element are located in the source bytes.

Examples:

- Header range
- optional Tag range
- optional Length range
- Value range
- Trailer range
- complete element range

Layout is runtime information produced while parsing.

In the current C API, `tlv_source_t` and `tlv_range_t` carry this information;
`tlv_decoded_t` pairs it with the semantic Element. Reusable configuration
belongs to Format composition; Layout is reserved for the ranges of a concrete
decoded instance.

Format defines the rules.
Layout describes the result of applying those rules to concrete bytes.

### Element

`tlv_element_t` is the format-independent representation of a recognized TLV element.

Conceptually:

```text
Element
├── Identifier / Tag
├── Length
└── Value
```

Length here means the logical Value byte count, currently `tlv_element_t.value.size`.
It is not an additional raw Length field. An identifier or an explicit wire
Length field may be absent if the Format permits it.

It must not contain Format-specific parsing state.

It is the common boundary reused by Reader, Schema, Codec, Document,
Query, diagnostics, bindings, runtime formats and generated/native formats.

Do not introduce parallel representations such as:

```text
runtime_element_t
compiled_element_t
ber_element_t
emv_element_t
```

unless they represent genuinely different concepts.

### Schema

Defines how elements may be composed.

It answers:

> Where may this element occur and under what constraints?

Examples:

- required / optional
- occurrence counts
- nesting
- ordering constraints
- allowed children
- structural constraints

Schema must not define wire encoding.

### Codec

Interprets the bytes contained in Value.

It answers:

> What do these Value bytes mean?

Examples:

- INTEGER
- BOOLEAN
- STRING
- ENUM
- date/time
- protocol-specific semantic values

Codec operates on Value, not on the wire representation of the complete element.
Standards should reuse generic value codecs and declarative codec configuration
where their Value encoding and C representation match. Extract reusable
conversion primitives rather than duplicating them across standards; retain
specialized codecs for domain semantics that generic composition cannot express.
Native and future `.otlv` dictionaries must compose the same contracts, differing
in construction and ownership rather than creating parallel semantic models.
The caller or domain dictionary selects a value codec for a tag in context before
invoking it. A value codec does not look up its enclosing tag in a Definition
registry or dictionary to decide what it is decoding.
Structure codecs may compose Reader/Writer, Schema and value codecs to map
complete objects. They still delegate wire interpretation to Format.

---

## 3. Declarative descriptions vs runtime objects

Definition, Format, Field Encoding, Schema and Codec are descriptions/contracts.

Element and Layout are runtime representations. Document is the core owned
representation built on these primitives.

Do not create architectural layers merely because a new runtime object is needed.

---

## 4. Phase 2 must not introduce another architecture

Phase 2 dynamically configures the same abstractions established by Phase 1.

Runtime:

```text
runtime Definition
runtime Format composition / Field Encoding configuration
runtime Schema
runtime Codec
```

must implement the same contracts as their compile-time/native equivalents.

Phase 2 must not introduce:

```text
RuntimeFormat
RuntimeSchema
RuntimeElement
RuntimeValidator
```

as parallel architectural concepts.

Runtime configuration is another implementation strategy of the same model.
Phase 2 describes the complete wire, structural and semantic model together:

```text
.otlv → AST → semantic analysis and symbol resolution → IR → tlv_model_t → execution descriptors
```

The canonical internal IR lowers to the existing execution contracts.
`tlv_format_t` remains a lightweight execution descriptor, not the canonical
semantic representation of a Format. The planned immutable `tlv_model_t` owns
the loaded model and supports introspection; it does not replace Element or
other execution contracts. Model construction/loading may allocate, while TLV
processing with an already constructed immutable model should remain
allocation-free using explicit buffers and workspaces. Explicitly owning
operations such as Document retain their storage requirements.

See the [Phase 2 runtime model and canonical IR](runtime-model.md) for the
complete pipeline, ownership and lifetime requirements, allocation boundary
and the distinction between semantic IR and execution descriptors.

---

## 5. Runtime / compiled / native are implementation strategies

A layer may be implemented as:

- runtime configuration
- generated/compiled representation
- hand-optimized native implementation

but all implementations must preserve the same contract and semantics.

For example:

```text
generic runtime BER Format
generated BER Format
optimized native BER Format
```

must still behave as the same conceptual Format.

Phase 4 reuses the same OTLV frontend and canonical IR for optimization and
code generation. Runtime lowering and compiled implementations must preserve
equivalent OTLV semantics. Optimization must not create a second OpenTLV API.

---

## 6. Tag / identifier is byte identity

A TLV identifier is fundamentally a sequence of bytes.

Do not treat a Tag as a host integer.

Therefore:

- no implicit endian conversion
- no numeric normalization
- no architecture-dependent representation
- comparison is based on bytes
- representation must be deterministic across platforms

Conceptually:

```text
identifier = { bytes, size }
```

The same wire identifier must have the same identity on little-endian
and big-endian machines.

---

## 7. Endianness belongs to wire interpretation

Endianness describes how numeric fields encoded on wire are interpreted.

It must never depend on CPU endianness.

For example:

```text
wire length = big-endian
```

means OpenTLV interprets it as big-endian on every architecture.

The host CPU may affect which optimized implementation is used,
but never the externally visible result.

---

## 8. Length has two different concepts

Do not confuse:

1. encoded Length field
2. logical Value size

The wire Length representation may contain:

- fixed-width integer
- variable-width integer
- continuation encoding
- protocol-specific representation

while the resulting logical value size is represented using OpenTLV's
size type.

Never assume:

```text
encoded length bytes == size_t
```

and never perform unchecked conversions to `size_t`.

---

## 9. Writer regenerates wire representation

An Element represents logical TLV information.

When writing an Element using a Format, the Writer generates the wire
representation required by the destination Format.

Therefore a parsed Length encoding must not force the Writer to reproduce
the original Length bytes unless an explicit lossless/raw mode requires it.

In the current API, exact preservation uses `tlv_source_preserve()` with the
original immutable source and semantically unchanged content. Changed content
requires fresh encoding; preservation must reject it rather than reuse stale
framing. A destination Format may reject identifiers or values it cannot
represent; conversion does not implicitly remap identifier identity.

This enables transformations such as:

```text
source Format A
    ↓
  Element
    ↓
destination Format B
```

---

## 10. Source location is metadata, not Element identity

Source offsets/ranges are important for:

- diagnostics
- editors
- Wireshark integration
- highlighting
- Document
- Query results

but they do not define the logical Element.

Therefore source location belongs to Reader/Layout/Source/Diagnostics metadata,
rather than polluting the format-independent Element contract.

---

## 11. Borrow by default

Core parsing should remain zero/minimal-copy.

Parsed elements normally borrow their Value and identifier bytes from the
input buffer. Formats with transformed identifiers may borrow immutable
format-supplied identifier storage under the [Format contract](format-contract.md#decoded-identifier-consistency);
Value still borrows the input. All borrowed storage must outlive retained results.

Therefore:

- Element does not own the source buffer.
- Reader/document lifetime contracts must be explicit.
- Bindings may provide safer ownership wrappers.
- Core must not silently allocate just to simplify ownership.

---

## 12. Reader must not require Schema or Codec

The basic parser pipeline must work as:

```text
bytes
  ↓
Format
  ↓
Reader
  ↓
Element
```

Schema and Codec are optional higher-level functionality.

Therefore it must always be possible to parse unknown TLV data without
having a Schema or Codec.

---

## 13. TLV / LTV is ordering, not a separate architecture

TLV and LTV describe field ordering.

For example:

```text
TLV = Tag → Length → Value
LTV = Length → Tag → Value
```

Generic Format configuration should represent this as field ordering.

Do not create completely separate parser architectures merely because
the fields appear in a different order.

Bluetooth LTV can therefore reuse generic ordering primitives while keeping
Bluetooth-specific semantics inside the Bluetooth extension.

---

## 14. OTLV is declarative

`.otlv` must describe data, not implement programs.

Do not introduce general control-flow constructs such as:

```text
if / else
for
while
switch
break
continue
```

Use declarative primitives instead:

- variants
- identifiers
- ranges
- counts
- repetition
- continuation
- until
- size
- references
- constraints

If OpenTLV needs a general-purpose programming language to describe a TLV
format, the abstraction is probably wrong.

---

## 15. New functionality does not automatically mean a new layer

Before adding another architectural layer, determine whether the concept is
actually:

- a Format property
- Schema constraint
- Codec
- Definition metadata
- Layout/runtime metadata
- reusable primitive
- extension
- preset
- tooling

A module is a reusable unit that may provide any subset of OpenTLV capabilities:
Definition, Format, Schema and Codec. A definition-only module or a format-only
module is valid. Module describes composition; it adds no architectural layer.

Builtins are functionality implemented natively and optionally compiled into
OpenTLV. They remain independent of modules and of the future `.otlv` runtime
interpreter. `.otlv` is a runtime description, not a requirement for using a
builtin. Native C, runtime `.otlv` and future generated code must supply the
same contracts to the generic core. No runtime engine is introduced here.

---

## 16. Standards should be compositions of generic primitives

A standard implementation should ideally look like:

```text
generic OpenTLV primitives
          +
    standard configuration
          +
  standard-specific semantics
```

rather than:

```text
completely separate parser
```

Examples:

- Bluetooth may be a preset/configuration over generic Fixed/LTV primitives.
- BER uses generic Format mechanisms plus BER-specific rules.
- EMV builds on generic TLV + Schema + Codec + Definition functionality.

Whenever a standard exposes a reusable concept, move the concept into the
generic layer and keep only the standard-specific policy in the extension.

---

## 17. Phase 1 must prove genericity

Phase 1 discovers, generalizes, validates and stabilizes the generic C execution
foundation. Independent standards such as BER/EMV, Bluetooth, LLDP, DHCP, NFC
and future formats serve as a playground for discovering missing primitives
and refining the shared taxonomy, not as a claim of implemented support.

Phase 2 requirements guide Phase 1 design without requiring premature runtime
model implementation. For every generic primitive, ask:

1. Can it represent the required real-world TLV format generically?
2. Could a future declarative model and canonical IR describe it completely?
3. Could both runtime lowering and future code generation consume it?

Before considering it complete, it should demonstrate that genuinely
different TLV families can be represented without protocol-specific hacks.

The architecture should be tested against formats with differences such as:

- TLV vs LTV
- fixed vs variable fields
- different tag encodings
- different length encodings
- different endian rules
- primitive / constructed elements
- BER-style formats
- Bluetooth-style formats
- absent explicit Tag or Length fields
- additional Header fields and Trailer framing
- semantic round trips and exact preservation of unchanged source bytes

If supporting another legitimate TLV format requires bypassing the core
architecture, the Phase 1 abstraction is not generic enough yet.

---

## 18. Features must remain independently usable

Users should be able to use only the parts they need.

For example:

```text
Reader only
Reader + Schema
Reader + Codec
Document + Query
full runtime OTLV stack
```

Capabilities compose through explicit integrations rather than mandatory
ownership dependencies. Core primitives form the stable foundation; Reader,
Writer, Document, Query, Schema and Codec are capabilities above that foundation.
Document is an owned tree, not intrinsically the output of Reader. Wire import,
wire serialization and query evaluation belong to their integration boundaries.

The build graph must implement **pay only for what you use**: disabling a
capability excludes its implementation while unrelated capabilities remain usable.
Linker dead stripping alone does not satisfy this requirement. Convenient binding
methods such as `document.parse()` or `document.write()` do not change C dependency
ownership. Future Dump, export, model and inference operations should compose with
their data sources rather than becoming intrinsic Document responsibilities.

Disabled functionality must introduce no unnecessary:

- runtime cost
- binary-size cost
- dependency cost

Higher layers depend on lower layers, not the reverse.

---

## 19. Bindings expose the same OpenTLV model

Rust, Python, Go, Java, Lua, WASM and other bindings should not invent
different conceptual APIs.

The language ergonomics may differ, but users should still recognize:

- Format
- Reader
- Writer
- Element
- Schema
- Codec
- Document
- Query
- Diagnostics

Learning OpenTLV in one language should transfer to another language.

Every supported binding must expose the complete public C capability set
through its public, idiomatic language facade. Raw FFI access alone does not
satisfy parity, and users must not need to bypass the facade for advanced
operations. Exposing raw FFI publicly is optional.

The facade adapts ownership, lifetimes, iteration and error handling while
delegating processing semantics to the C engine. It must not implement an
independent parser, tree traversal engine, Query semantics or wire encoder.
See the [binding capability contract](bindings.md#capability-parity-through-the-public-facade)
for scope, ownership requirements and how existing gaps are tracked.

---

## 20. Ergonomics belong above the stable core

The C core defines the stable low-level contracts.

Higher-level APIs may provide:

- RAII
- ownership
- iterators
- exceptions/results
- Pythonic APIs
- Rust lifetimes
- Java objects
- Lua tables/userdata

without changing the semantics of the underlying OpenTLV model.

---

## 21. Diagnostics must preserve useful raw context

Diagnostics should be layered on top of the normal parsing model rather than
requiring a separate parser.

Useful diagnostic information includes:

- error code
- source offset
- identifier/tag
- path
- expected value
- actual value
- schema context
- raw/declared length information where relevant

Fast paths that do not request diagnostics should not be forced to pay the
full diagnostics cost.

The [failure model](error-model.md) decides the target Result / Detail / Location /
Propagation contract (#551). Results classify generic conditions; protocol and
operation specifics belong in typed detail. Invalid schema definitions are
distinct from input violations, and location shape does not determine a result
class. Higher layers preserve delegated results and cause detail. Common
diagnostics may be embedded in specialized value types; text contexts do not
replace machine-readable detail.

The design permits breaking enum, signature and layout replacement, including
a shared result domain for Codec. These are implementation requirements, not
claims about the current ABI. The [error reference](../reference/errors.md)
documents the implemented behavior until that migration is complete.

---

## 22. OpenTLV scope remains binary TLV

Even when implementing ASN.1-related functionality, OpenTLV remains focused
on binary TLV representation.

For ASN.1/X.680/X.690 this means reusing relevant concepts across:

```text
Format
Schema
Codec
```

without turning OpenTLV core into:

- an ASN.1 language parser
- ASN.1 AST
- module/import system
- complete ASN.1 compiler
- complete ASN.1 constraint language

Generic capabilities discovered while implementing ASN.1 should become
OpenTLV primitives where appropriate.

---

## Architectural invariant

A useful test for every future OpenTLV feature is:

> Can this functionality be expressed using the existing generic contracts
> without teaching the core about a particular protocol or creating a parallel
> representation of the same concept?

If yes, compose the existing architecture.

If no, first determine whether OpenTLV is missing a genuinely generic primitive
before introducing protocol-specific machinery.
