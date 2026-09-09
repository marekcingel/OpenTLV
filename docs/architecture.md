# Layered OpenTLV architecture (#65)

OpenTLV provides one C library (`tlv`) and a header-only C++ interface (`tlv++`)
that links to it. Core is a logical responsibility, not a directory. Optional
components are concrete formats and profiles, rather than entire layers.

## Responsibilities and dependency direction

| Area | Responsibility | Allowed dependencies |
| --- | --- | --- |
| Shared contracts | Borrowed buffers, raw tags, errors, format callbacks | Standard C types |
| Reader / writer | Bounded raw TLV I/O, iteration, copies, generic traversal | Shared contracts |
| Formats | Tag/length wire encoding and identification of nested containers | Shared contracts; private wire helpers |
| Schemas | Tag length, occurrence, primitive/container and child membership rules | Shared contracts, raw reader and traversal |
| Codec | Value conversion and complete-structure object mappings (bindings) | Shared contracts; structure codecs may use schemas and raw I/O |
| Profiles | Standard-specific tables and composition of formats, schemas and codecs | The facilities above |

The format descriptor is a shared contract consumed by generic I/O; concrete
format implementations never need to be named by the reader/writer. A codec
does not have to use a schema. Existing C++ tag-associated codecs remain valid.
Bindings are part of the codec area, not another architectural layer.

`reader/scanner` is a recovery utility above the raw reader and schema lookup.
Its location groups reading-related tools, without classifying every file in
that folder as the lowest-level core. Profiles compose lower facilities; lower
generic facilities do not include profiles. DER's wire callbacks and bounded
profile operations live in separate files. BER and DER share a private wire
backend; selecting DER does not require the public BER component.

## Layout

Public headers under `tlv/include/tlv/` and sources under `tlv/src/` use:

```text
tlv/
  types.h, error.h, endian.h, copy.h, tlv.h
  formats/
    format.h
    default/ default.h
    fixed/   fixed_1byte.h
    asn1/    ber.h, der.h
  reader/    reader.h, walker.h, scanner.h
  writer/    writer.h
  schemas/   schema.h
  codec/     codec.h, structure.h, emv.h
  profiles/  emv.h, emv_tags.def, der.h
```

The tree shows the public layout; corresponding implementation files use `.c`.
BER and DER share `src/formats/asn1/ber_internal.c` and its private header.
The default encoding and fixed-width encodings have their own folders.
Internal schema validation, BER helpers and EMV value codecs have dedicated
source files. `config.h` and `version.h` are generated into the build include
directory. The public aggregate `tlv/tlv.h` includes enabled components; generic
headers include only their direct contracts. Use explicit headers for small
consumers. C++ common types are in `tlv++/types.hpp`, independent of codecs.

## Traversal and recovery

* `tlv_reader_next` iterates adjacent elements without interpreting their values.
* `tlv_walk` visits adjacent elements and fails at invalid framing.
* `tlv_walk_tree` performs bounded preorder traversal using a separate
  `is_constructed` predicate. It exposes depth and absolute element offsets. A NULL
  visitor validates framing only. It uses a bounded stack, without allocation
  or C recursion. C++ offers `tlv::walk_tree` with a callable visitor.
* `tlv_scan` searches byte offsets for a complete candidate after corruption.
  Its optional flat schema filters tags and lengths. A candidate is not proof
  of an original network message boundary; it is not a streaming reassembler.

The nesting contract covers containers whose value views contain a sequence
in the same format, including BER indefinite lengths/EOC. A NULL nesting
callback disables tree descent. BER still inspects descendant framing when
needed to locate an indefinite element's end. Generic traversal separates the
value end from the complete encoded end and skips enclosing trailers when
resuming siblings. Mixed-format child payloads and stream reassembly remain
outside this contract. Definite single-element I/O keeps values opaque;
explicit BER indefinite writing validates child framing before writing.

## Structural rules and object codecs

`tlv_schema_t` retains lightweight tag lookup and length validation for recovery
and dictionaries. `tlv_structure_schema_t` adds per-parent rules: inclusive
lengths, minimum/maximum occurrences, primitive/container constraints, nested
schemas and explicit unknown-tag policy. Sibling order is unrestricted.
Validation does not decode values or implement cross-field business rules.
An empty container still has to satisfy required-child rules. Limits bound
tree depth and the total number of elements. Validation rescans each scope for
each rule rather than allocating occurrence counters.

`tlv_codec_t` converts an individual raw value. `tlv_structure_codec_t` maps a
complete sequence into a caller-owned object, using explicit `reader_format` and `writer_format` pointers, an optional
`is_constructed` predicate, and an optional structure schema. Decode requires
only the reader format. Encode needs the writer format and the matching reader
format for validation of produced bytes. It validates input before calling the object decoder
and validates encoded bytes before reporting success. It does not infer member
offsets or allocate application objects. Application callbacks map fields and
can invoke value codecs. Both APIs document object representation and ownership
through the selected descriptor. C++ offers `decode_structure<T>` and
`encode_structure` wrappers with caller-owned output storage.

Raw C++ writers only accept tags and bytes. `tlv::write_value(writer, value)`
is the explicit codec convenience function for existing `T::tag` types. That
helper retains its temporary `std::vector` and may allocate; raw I/O and the C
codec wrappers do not allocate. C++ errors and user-defined object types may
also allocate according to their representation.

## Build configuration

All generic facilities are always available. These concrete components default
to ON and can be disabled independently:

| CMake option / generated config macro | Included component |
| --- | --- |
| `OPENTLV_FORMAT_DEFAULT` | One-byte tag with legacy definite BER-style length |
| `OPENTLV_FORMAT_FIXED_1BYTE` | One-byte tag and length |
| `OPENTLV_FORMAT_BER` | Public BER format |
| `OPENTLV_FORMAT_DER` | DER format and bounded DER profile operations |
| `OPENTLV_PROFILE_EMV` | EMV dictionary, schemas and value codecs |

EMV tables/codecs can be used without built-in BER; the caller may supply a
compatible format. DER uses private BER wire helpers even when public BER is
disabled. Disabling both BER and DER removes that backend. No component creates
another public binary library. `tlv/config.h` exposes the configured selection.
Explicitly including a disabled component's header does not provide its symbols;
consumers should use the config macros when supporting reduced builds.

Tests that require disabled components and examples that demonstrate them are
omitted. Generic architecture tests use an application-defined format and run
even when all built-ins are disabled. The benchmark uses the default format and
is built only when that component is enabled.

```sh
cmake -S . -B build-minimal -DOPENTLV_FORMAT_DEFAULT=OFF \
  -DOPENTLV_FORMAT_FIXED_1BYTE=OFF -DOPENTLV_FORMAT_BER=OFF \
  -DOPENTLV_FORMAT_DER=OFF -DOPENTLV_PROFILE_EMV=OFF
cmake --build build-minimal --parallel
```

## Migration

Update flat includes to the folders above (`tlv/reader.h` becomes
`tlv/reader/reader.h`, `tlv/format.h` becomes `tlv/formats/format.h`, and so on).
Concrete format declarations use `tlv/formats/default/default.h`,
`tlv/formats/fixed/fixed_1byte.h`, `tlv/formats/asn1/ber.h`, or
`tlv/formats/asn1/der.h`; the public aggregate includes enabled formats.
Replace typed `writer.write(value)` with
`tlv::write_value(writer, value)`. Raw `writer.write(tag, bytes)` is unchanged.
Split custom descriptors into `tlv_reader_format_t` and `tlv_writer_format_t`.
Use matching `tlv_reader_format_<name>` / `tlv_writer_format_<name>` constants
at each call site. Runtime construction uses `tlv_reader_format_init` and
`tlv_writer_format_init`; either direction can be implemented independently.

Pass the nesting predicate (or NULL) immediately after the reader format in
`tlv_walk_tree`, `tlv_schema_validate`, `tlv::walk_tree`, and `tlv::validate`.
It receives the reader format context. BER and DER provide
`tlv_ber_is_constructed` and `tlv_der_is_constructed`. Structure codecs store
both format pointers and the separate nesting predicate, and decode/encode
callbacks receive their corresponding format type. Rebuild all consumers
because the descriptor and affected API layouts have changed. (#68)
