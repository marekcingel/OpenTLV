# Roadmap

[Back to project overview](README.md)

This document describes OpenTLV's long-term architectural direction across
major versions. It is a statement of direction, not a frozen specification:
stages beyond 1.x describe planned scope and the problems each stage solves,
not committed APIs, wire formats, or implementation details. Those are
worked out in their own GitHub issues and design documents as each stage is
built, and OTDL syntax, runtime format APIs, semantic APIs, and compiler
interfaces may all change before their corresponding release.

GitHub milestones and roadmap-tracking issues use the same stage names as
this document (`1.x - Foundation`, `2.x - Runtime Format Engine`,
`3.x - Semantic Engine`, `4.x - OpenTLV Compiler`) to keep planning and
documentation aligned.

## 1.x - Foundation

1.x is the current and only committed stage: a stable, portable, dependency-free
TLV core with a compile-time API. Every other stage in this document builds on
top of it rather than replacing it.

Scope:

- Stable and portable C99 core, unchanged in its ownership and error-handling
  contracts across the 1.x series.
- Header-only C++11+ wrapper (`tlv++`).
- Reader, writer, visitor, and tree traversal APIs.
- Structural schemas and value codecs.
- Built-in TLV formats and profiles (default/fixed-width, BER/DER/CER, EMV
  Contact Book 3), as tracked in the [README format checklist](README.md#format-and-profile-support)
  and [format expansion candidates](docs/formats/format-roadmap.md).
- CLI and developer tooling for TLV inspection and validation.
- Language bindings beyond C/C++.
- Testing, fuzzing, coverage, documentation, and packaging/distribution.

All formats and profiles in 1.x are defined at compile time: adding a new
format means writing C or C++ code against the reader/writer callback
contracts. The remaining stages exist to lift that constraint.

## 2.x - Runtime Format Engine

2.x introduces the ability to describe a TLV format as data and parse or
produce it without writing format-specific code, alongside the existing
compile-time formats from 1.x.

Planned scope:

- Runtime format definitions: a TLV layout described and loaded at runtime
  instead of implemented as C/C++ format callbacks.
- **OpenTLV Definition Language (OTDL)**: the planned format-definition model
  for 2.x and later stages. OTDL is how a format's framing is described data;
  its concrete syntax is not yet finalized and will evolve during 2.x design
  and prototyping.
- Data-driven parsing: reading and writing driven by a loaded definition
  rather than by compiled format callbacks.
- Runtime schema and introspection: inspecting a loaded format's structure
  and validating data against it without a compile-time schema.
- External format definitions: distributing and loading OTDL definitions
  independently of the OpenTLV core.
- BER and DER as reference formats for the runtime engine: re-expressing the
  existing built-in BER/DER support as OTDL definitions, both to validate
  that OTDL can describe a real, non-trivial format and to give the engine a
  known-correct baseline to test against.
- **X.509 DER certificates** as a real-world integration proof: parsing X.509
  certificate structure through the runtime engine and its BER/DER OTDL
  definitions, as evidence the runtime approach holds up on a widely used,
  independently specified format rather than only on formats designed for
  OpenTLV.

## 3.x - Semantic Engine

3.x builds on the runtime format engine to interpret decoded values according
to a data-driven semantic model, rather than only exposing raw tag/length/value
structure.

Planned scope:

- Runtime semantic model: describing what a decoded value *means* (its type,
  constraints, and relationships to other values), separately from how it is
  framed on the wire.
- Semantic codecs: value interpretation driven by the semantic model, in the
  same spirit as 1.x's compile-time value codecs but resolved at runtime.
- Bidirectional decoding and encoding: the semantic model drives both
  directions, not just parsing.
- Validation and transformations expressed against the semantic model.
- Round-trip processing: decoding to a semantic representation and
  re-encoding it, as a way of validating that the model preserves everything
  the wire format needs.

## 4.x - OpenTLV Compiler

4.x closes the loop opened by 2.x and 3.x: instead of interpreting an OTDL
definition and semantic model at runtime, generate native source code from
them ahead of time.

Planned scope:

- **`opentlv-gen`**: a code generation tool that consumes OTDL format
  definitions (and, where applicable, semantic models from 3.x) and emits
  native source.
- OTDL-to-C generation, producing code that follows the same conventions as
  the 1.x C core.
- OTDL-to-C++ generation, producing code that follows the same conventions as
  the 1.x C++ wrapper.
- Strongly typed generated APIs: generated code exposes types and functions
  specific to the input definition, rather than the generic runtime
  interfaces from 2.x/3.x.
- Standalone and embedded generation: generated code that can be used on its
  own, or embedded into a project without a runtime dependency on the format
  engine.
