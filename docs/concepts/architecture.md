# Layered OpenTLV architecture (#65, #279, #280, #281)

OpenTLV provides one C library (`tlv`) and a header-only C++ interface (`tlv++`)
that links to it. Core is a logical responsibility, not a directory. Optional
components are concrete formats and profiles, rather than entire layers.

## Responsibilities and dependency direction

| Area | Responsibility | Allowed dependencies |
| --- | --- | --- |
| Shared contracts | Borrowed values, logical lengths, raw tags, errors, format callbacks | Standard C types |
| Reader / writer | Bounded raw TLV I/O, iteration, copies, generic traversal | Shared contracts |
| Formats | Tag/length wire encoding and identification of nested containers | Shared contracts; private wire helpers |
| Schemas | Tag length, occurrence, primitive/container and child membership rules | Shared contracts, raw reader and traversal |
| Codec | Value conversion and complete-structure object mappings (bindings) | Shared contracts; structure codecs may use schemas and raw I/O |
| Profiles | Standard-specific tables and composition of formats, schemas and codecs | The facilities above |

The format descriptor is a shared contract consumed by generic I/O; concrete
format implementations never need to be named by the reader/writer. A codec
does not have to use a schema. Existing C++ tag-associated codecs remain valid.
Bindings are part of the codec area, not another architectural layer.

Formats and profiles are roles, not folders: every concrete format or profile
implementation OpenTLV ships (ASN.1, EMV, Bluetooth LTV, the fixed formats)
lives under `builtins/<protocol>/`, grouped by protocol rather than by role,
so all of a protocol's format, schema, codec and profile files sit together.
Generic subsystems (`reader/`, `writer/`, `query/`, `schema/`, `codec/`,
`document/`) never depend on `builtins/`.

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
  view.h, value.h, length.h, error.h, endian.h, copy.h, format.h, tlv.h
  reader/    reader.h, walker.h, scanner.h
  query/     query.h
  document/  document.h
  writer/    writer.h
  schema/    schema.h
  codec/     codec.h, structure.h
  builtins/
    fixed/     default.h, fixed_1byte.h
    bluetooth/ bluetooth_ltv.h
    asn1/      ber.h, der.h, cer.h, der_profile.h, cer_profile.h, der_schema.h
    emv/       emv.h, emv_schema.h, emv_tags.def, dol.h, emv_codec.h
```

The tree shows the public layout; corresponding implementation files use `.c`.
Small fundamental types (`tag.h`, `length.h`, `value.h`, `view.h`, and the
generic `format.h` descriptor contracts) sit directly under `tlv/`, alongside
the generic subsystem folders. Every concrete format or profile OpenTLV ships
lives under `builtins/<protocol>/`, so all of a protocol's functionality is
in one place instead of scattered across role-based folders: EMV's schema,
codec, DOL and umbrella profile header are all under `builtins/emv/`, and
ASN.1's wire formats and bounded DER/CER profile operations are all under
`builtins/asn1/`. Wire-level `der.h`/`cer.h` and the bounded profile headers
that build on them would otherwise share a name, so the profile headers are
`der_profile.h`/`cer_profile.h`; similarly `builtins/emv/emv_codec.h` (moved
from `codec/emv.h`) is distinct from the umbrella `builtins/emv/emv.h`.
BER and DER share `src/builtins/asn1/ber_internal.c` and its private header.
Internal schema validation, BER helpers and EMV value codecs have dedicated
source files. `config.h` and `version.h` are generated into the build include
directory. The public aggregate `tlv/tlv.h` includes enabled components; generic
headers include only their direct contracts. Use explicit headers for small
consumers. C++ common types are in `tlv++/types.hpp`, independent of codecs.

Public headers under `tlv++/include/tlv++/` mirror the same layout (#280),
grouping the C++ wrapper for each generic subsystem alongside its C
counterpart and each protocol's wrapper under `builtins/<protocol>/`:

```text
tlv++/
  types.hpp, compat.hpp, diagnostic.hpp, tlv.hpp
  reader/    reader.hpp, walker.hpp
  query/     query.hpp
  document/  document.hpp
  writer/    writer.hpp
  schema/    schema.hpp
  codec/     codec.hpp, structure.hpp, registry.hpp
  builtins/
    fixed/ fixed_format.hpp
    asn1/  ber.hpp
```

`tlv++` is header-only, so there is no separate `tlv++/src/`. `registry.hpp`
sits under `codec/` alongside `codec.hpp` and `structure.hpp`: it is a
runtime-dispatch complement to the compile-time `TlvCodec` concept, with no C
counterpart. Only the generic subsystems and protocols that already have a
C++ wrapper get a folder; a protocol built-in only in C (Bluetooth LTV, EMV)
has no `tlv++/builtins/<protocol>/` folder until a C++ wrapper for it exists.
Every `tlv++` header keeps using full paths from the include root
(`#include "tlv++/reader/reader.hpp"`, not a relative `#include
"reader.hpp"`), so moving a header between folders only requires updating
`#include` lines that name it, not every include inside sibling headers.

`tests/unit/`, `tests/integration/` and `tests/fuzz/` (#281) each keep their
own existing top-level meaning — component contracts, concrete wire formats
and layer interactions, and libFuzzer harnesses, respectively (see
[tests](../getting-started/README.md#build-and-run-tests)) — and each
independently mirrors `tlv/src`'s own layout underneath: a generic
subsystem's tests sit under its own `reader/`, `writer/`, `query/`, `schema/`,
`codec/` or `document/` folder, and a built-in's tests sit together under
`builtins/<protocol>/`, regardless of whether they exercise its schema, codec,
DOL or parser. Small core-type tests and cross-cutting tests (such as
`architecture_test.cpp`, and the `tlv++` aggregate `test_tlvpp.cpp`) stay
directly under `tests/unit/` or `tests/integration/`, without a subsystem
folder, the same way `tag.h` and `value.h` sit directly under `tlv/`. A
shared folder's C and C++ files are told apart by name, not by a separate
`tlv`/`tlv++` folder (`document_test.cpp` next to `test_document.cpp`).
`tests/fuzz/` uses the same subsystem/`builtins/<protocol>/` split for its
harnesses, each with its checked-in seed corpus in a sibling `corpus/` folder
(`tests/fuzz/reader/read.c` and `tests/fuzz/reader/corpus/read/`,
`tests/fuzz/builtins/asn1/der.c` and its `corpus/der/`); it keeps its own
`tests/fuzz/CMakeLists.txt` since `OPENTLV_BUILD_FUZZING` is independent of
`OPENTLV_BUILD_TESTS`. Compile/API checks stay separate from this tree.

## Mutable document

`document/document.h` is a layer above the reader, writer and query facilities. It
parses input into an owned tree, lets the tree be searched, changed, extended and
shortened, and encodes it again through the writer. It is the only component that
allocates, it can use a caller-supplied allocator, and it is the `OPENTLV_DOCUMENT`
option. Nothing below it depends on it, so the reader, writer and walker stay
zero-copy and allocation-free whether or not it is built. See
[mutable documents](../guides/document.md).

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

## Include only what you need

A build contains only the components it asks for. A project that needs just the
generic core builds just the core. A project that also needs BER enables BER and gets
no other format. Formats and profiles are selectable components (see
[Build configuration](#build-configuration)), and each concrete component is compiled
into the library only when it is enabled. Dependencies between components are explicit,
for example the ASN.1 chain below, and nothing is pulled in implicitly. The header-only
C++ wrapper adds cost only for the headers a program includes.

Every new format or profile, including the candidates in the
[format expansion candidates](../formats/format-roadmap.md), follows the same rule: its
own option, and no code or dependency added to builds that do not enable it.

Language bindings are expected to follow the same rule: a binding should expose a
component only when the matching C component is enabled, so a binding build can also be
limited to what it needs. **This is not implemented yet for the Rust bindings.**
`opentlv-sys` configures the C library with its default options, so all built-in
components are included, and the `opentlv` crate has no Cargo features for choosing
components. Mapping the component options to Cargo features is a requirement for
future work; see [Rust bindings](../development/rust.md#build). Ready-made CMake recipes are in
[building only the components you need](../guides/select-components.md).

## Build configuration

All generic facilities are always available. These concrete components default
to ON and can be disabled independently:

| CMake option / generated config macro | Included component |
| --- | --- |
| `OPENTLV_FORMAT_DEFAULT` | One-byte tag with legacy definite BER-style length |
| `OPENTLV_FORMAT_FIXED_1BYTE` | One-byte tag and length |
| `OPENTLV_FORMAT_BLUETOOTH_LTV` | Bluetooth Length, Type, Value framing |
| `OPENTLV_FORMAT_ASN1` | ASN.1-related wire formats (BER, DER, CER) |
| `OPENTLV_FORMAT_BER` | Public BER format |
| `OPENTLV_FORMAT_DER` | DER format and bounded DER profile operations |
| `OPENTLV_FORMAT_CER` | CER format and bounded CER profile operations |
| `OPENTLV_PROFILE_EMV` | EMV dictionary, schemas and value codecs |
| `OPENTLV_DOCUMENT` | Optional [mutable document](../guides/document.md); the only component that allocates |

`OPENTLV_FORMAT_ASN1`, `OPENTLV_FORMAT_BER`, `OPENTLV_FORMAT_DER`, and
`OPENTLV_PROFILE_EMV` form a chain (ASN1 -> BER -> DER -> EMV): disabling an
option forces every option below it OFF as well, regardless of how that
option was set, so `-DOPENTLV_FORMAT_BER=OFF` also disables DER, CER and EMV.
`OPENTLV_FORMAT_CER` is an independent sibling of `OPENTLV_FORMAT_DER` under
`OPENTLV_FORMAT_BER`, not a descendant of it: CER never depends on DER (or
vice versa), and disabling DER does not affect CER or EMV. This cascade is
centralized in `cmake/format_options.cmake`. No component creates
another public binary library. `tlv/config.h` exposes the configured
selection, including `OPENTLV_FORMAT_ASN1`. Explicitly including a disabled
component's header does not provide its symbols; consumers should use the
config macros when supporting reduced builds.

Tests that require disabled components and examples that demonstrate them are
omitted. Generic architecture tests use an application-defined format and run
even when all built-ins are disabled. The benchmark uses the default format and
is built only when that component is enabled.

```sh
cmake -S . -B build-minimal -DOPENTLV_FORMAT_DEFAULT=OFF \
  -DOPENTLV_FORMAT_FIXED_1BYTE=OFF -DOPENTLV_FORMAT_ASN1=OFF
cmake --build build-minimal --parallel
```

## Migration

Update flat includes to the folders above (`tlv/reader.h` becomes
`tlv/reader/reader.h`, and so on). Concrete format declarations use
`tlv/builtins/fixed/default.h`, `tlv/builtins/fixed/fixed_1byte.h`,
`tlv/builtins/asn1/ber.h`, or `tlv/builtins/asn1/der.h`; the public
aggregate includes enabled formats.

`tlv/formats/` and `tlv/profiles/` (#279) no longer exist: every built-in
protocol implementation moved under `builtins/<protocol>/`. Concrete format
headers keep their names (`tlv/formats/asn1/der.h` becomes
`tlv/builtins/asn1/der.h`); the bounded DER/CER profile headers are renamed
to avoid colliding with the wire-format headers of the same name
(`tlv/profiles/der.h` becomes `tlv/builtins/asn1/der_profile.h`,
`tlv/profiles/cer.h` becomes `tlv/builtins/asn1/cer_profile.h`). EMV moves
and consolidates under `tlv/builtins/emv/`: `tlv/profiles/emv.h` becomes
`tlv/builtins/emv/emv.h`, `tlv/profiles/emv_schema.h`,
`tlv/profiles/emv_tags.def` and `tlv/profiles/dol.h` move alongside it
unchanged, and `tlv/codec/emv.h` (the semantic value codecs) becomes
`tlv/builtins/emv/emv_codec.h` to avoid colliding with the umbrella EMV
header. `tlv/schemas/schema.h` becomes `tlv/schema/schema.h`.

`tlv++`'s previously flat `tlv++/include/tlv++/*.hpp` headers (#280) move
into the same folders as their C counterparts:
`tlv++/reader.hpp`/`tlv++/walker.hpp` become
`tlv++/reader/reader.hpp`/`tlv++/reader/walker.hpp`;
`tlv++/writer.hpp`, `tlv++/query.hpp` and `tlv++/schema.hpp` become
`tlv++/writer/writer.hpp`, `tlv++/query/query.hpp` and
`tlv++/schema/schema.hpp`; `tlv++/codec.hpp`, `tlv++/structure.hpp` and
`tlv++/registry.hpp` become `tlv++/codec/codec.hpp`,
`tlv++/codec/structure.hpp` and `tlv++/codec/registry.hpp`;
`tlv++/document.hpp` becomes `tlv++/document/document.hpp`; and
`tlv++/ber.hpp`/`tlv++/fixed_format.hpp` become
`tlv++/builtins/asn1/ber.hpp`/`tlv++/builtins/fixed/fixed_format.hpp`.
`tlv++/types.hpp`, `tlv++/compat.hpp`, `tlv++/diagnostic.hpp` and the
aggregate `tlv++/tlv.hpp` are unaffected. No type, function or namespace
changed; only header locations did.

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

See also the generated [C API reference](../reference/c-api.md) and [C++ API reference](../reference/cxx-api.md).
