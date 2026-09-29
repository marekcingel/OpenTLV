# Layered OpenTLV architecture (#65, #279, #280, #281, #327)

OpenTLV provides one C library (`tlv`) and a header-only C++ interface (`tlv++`)
that links to it. Core is a logical responsibility, not a directory. Optional
components are concrete formats and standard-specific capabilities, rather than entire layers.

The [core architectural rules](architectural-rules.md) define the design and
review constraints. This page describes how the current repository implements
those responsibilities.

## Conceptual model

OpenTLV separates reusable definitions and rules, concrete runtime data, and
operations that apply those rules to the data:

```text
DECLARATIVE / SEMANTIC MODEL
────────────────────────────
Definition
Format
Schema
Codec

RUNTIME REPRESENTATION
────────────────────────────
Element
Layout

OPERATIONS
────────────────────────────
Reader
Writer
Document
Query
Visitor
...
```

The declarative/semantic model describes meaning and rules: a Definition
associates an identifier with a descriptive name in a registry, Format defines wire encoding,
Schema defines structural constraints, and Codec defines conversion between
Value bytes and application values. These roles can be implemented by tables,
descriptors and executable callbacks.

The runtime representation describes a concrete instance. Element holds its
semantic identifier and Value. Layout describes how that instance occupies
wire bytes: Header, optional Tag and Length fields, Value, Trailer and their
ranges. In the current C API, this source information belongs to `tlv_source_t`
and `tlv_range_t`; `tlv_decoded_t` pairs it with `tlv_element_t`. The field and
binary layouts declared in `tlv/layout.h` configure Format composition; they
are reusable rules rather than a decoded instance's runtime layout.

Operations consume or produce these representations using the selected model.
Reader and Writer process caller-owned buffers, Document supports editable collections of
elements, Query selects elements, and Visitor participates in traversal.
Operations can carry runtime state; these categories describe their primary
roles, not a one-to-one mapping to directories or C types.

See the [Format and Element contract](format-contract.md) for the precise
boundary between semantic content, source layout and wire preservation.

## Responsibilities and dependency direction

| Area | Responsibility | Allowed dependencies |
| --- | --- | --- |
| Shared contracts | Borrowed values, logical lengths, raw tags, errors, format callbacks | Standard C types |
| Reader / writer | Bounded raw TLV I/O, iteration, copies, generic traversal | Shared contracts |
| Formats | Complete Header/Value/Trailer framing and identification of nested containers | Shared contracts; private wire helpers |
| Schemas | Tag length, occurrence, primitive/container and child membership rules | Shared contracts, raw reader and traversal |
| Codec | Value conversion and complete-structure object mappings (bindings) | Shared contracts; structure codecs may use schemas and raw I/O |

The format descriptor is a shared contract consumed by generic I/O; concrete
format implementations never need to be named by the reader/writer. A codec
does not have to use a schema. Existing C++ tag-associated codecs remain valid.
Bindings are part of the codec area, not another architectural layer.

A module is a reusable unit that may provide any subset of Definition, Format,
Schema and Codec. This is composition, not a fifth capability or a layer.
For example, a vendor tag module may provide only Definition, while another
module provides only Format. No module registry or runtime loader is added.

Builtins are native implementations optionally compiled into OpenTLV. Shipped
protocol-specific functionality lives under `builtins/<protocol>/`, grouped by
protocol. Builtins work without the future `.otlv` interpreter. Native C,
runtime `.otlv` descriptions and future generated code all supply the same
contracts to generic consumers. Generic subsystems (`reader/`, `writer/`,
`query/`, `schema/`, `codec/`, `document/`) never depend on `builtins/`.

A format mechanism that names no protocol -- it is parameterized entirely by
caller-supplied widths and byte order, with no knowledge of any concrete
wire standard -- lives under the separate top-level `formats/` instead. The
configurable fixed-width format is the only member so far; other protocol-
agnostic mechanisms (not per-protocol formats) would join it there. This is
narrower than the pre-#279 `tlv/formats/` (see Migration): that one held
every concrete format regardless of whether it was protocol-specific, and was
retired in favor of `builtins/<protocol>/` for exactly the protocol-specific
ones. `formats/` returns only for mechanisms that stay protocol-agnostic.

Reader is the canonical pull-based cursor; Tree Reader composes it for nested
traversal, and Walker provides compatibility callback adapters.
Recovery and resynchronization are application policies implemented, when needed,
using the public single-element `tlv_read()` primitive. Standard-specific
implementations compose generic facilities; generic facilities do not depend on them. DER's wire callbacks and bounded
validation operations live in separate files. BER uses generic Variable primitives
through a private ASN.1 field adapter also consumed by DER/CER. The wrappers
retain their concrete rules and current component dependencies.

## Repository layout

Public headers under `tlv/include/tlv/` and sources under `tlv/src/` use:

```text
tlv/
  element.h, value.h, length.h, size.h, error.h, endian.h, copy.h, format.h, tlv.h
  compiler.h, attributes.h, definition.h
  reader/    reader.h, walker.h
  query/     query.h
  document/  document.h
  writer/    writer.h
  schema/    schema.h
  codec/     codec.h, structure.h
  formats/
    fixed.h
  builtins/
    bluetooth/ bluetooth_ltv.h, ad_types.h
    asn1/      ber.h, der.h, cer.h, der_validation.h, cer_validation.h, der_schema.h
    emv/       emv.h, emv_schema.h, dol.h, emv_codec.h
```

The tree shows the public layout; corresponding implementation files use `.c`.
`definition.h` provides borrowed identifier/name entries and a generic registry
lookup. Bluetooth AD types use this model independently of their wire format;
definitions neither validate structure nor decode values.
Identifier meaning is scoped to the selected registry, and descriptive names are
not unique domain identities. Rich standard dictionaries may compose Definition,
Schema and Codec without adding protocol fields to the generic Definition or
requiring Definition lookup before parsing or decoding. The caller/dictionary
selects the value codec; the codec does not resolve its enclosing tag.
The [Definition boundary audit](definition-boundaries.md) records this contract,
evidence across five standard families and the identifier-mapping decision.
Small fundamental types (`tag.h`, `length.h`, `size.h`, `value.h`, `element.h`, and the
generic `format.h` descriptor contracts) sit directly under `tlv/`, alongside
the generic subsystem folders. `formats/fixed.h` and `formats/variable.h` hold
format mechanisms that name no protocol; every protocol-specific format or standard
OpenTLV ships lives under `builtins/<protocol>/`, so all of a protocol's
functionality is in one place instead of scattered across role-based folders: EMV's schema,
codec, DOL and dictionary header are all under `builtins/emv/`, and
ASN.1's wire formats and bounded DER/CER validation operations are all under
`builtins/asn1/`. Wire-level `der.h`/`cer.h` and the bounded validation headers
that build on them would otherwise share a name, so the validation headers are
`der_validation.h`/`cer_validation.h`; similarly `builtins/emv/emv_codec.h` (moved
from `codec/emv.h`) is distinct from the umbrella `builtins/emv/emv.h`.
BER, DER and CER share the ASN.1 field adapter in
`src/builtins/asn1/ber_internal.c` and its private header. Reusable variable-width
identifier and definite-length algorithms live in `src/formats/variable.c`.
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
  formats/
    fixed_format.hpp
  builtins/
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
own existing top-level meaning â€” component contracts, concrete wire formats
and layer interactions, and libFuzzer harnesses, respectively (see
[tests](../getting-started/README.md#build-and-run-tests)) â€” and each
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

## Reader and traversal

* `tlv_reader_next` iterates adjacent elements without interpreting their values.
* `tlv_walk` visits adjacent elements and fails at invalid framing.
* `tlv_tree_reader_next` returns one preorder item with depth, absolute source
  offset, source metadata and Format-owned construction classification. It uses
  caller-provided structural frames and runtime depth/count limits, without
  allocation or C recursion. Input windows and subtree skipping preserve Reader's
  complete-element and borrowed-storage contracts.
* `tlv_walk_tree` is a compatibility callback adapter over Tree Reader, with a
  fixed stack capacity. A NULL visitor validates framing only. C++ offers
  `tlv::walk_tree` with a callable visitor.

The [Reader contract](../guides/reader.md) distinguishes an available element,
final end of input, resumable input shortage and parsing errors. Incremental
input uses caller-owned contiguous windows with absolute logical offsets. Scanner is removed
from the core API (#391); applications own any recovery policy.

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
complete sequence into a caller-owned object, using an explicit `format` pointer (whose own
`is_constructed` predicate governs nesting) and an optional structure schema. Decode requires
`format` to be able to read. Encode needs it to also be able to write, since
producing bytes and then validating them both go through the same descriptor.
It validates input before calling the object decoder
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
no other format. Formats and standard-specific capabilities are selectable components (see
[Build configuration](#build-configuration)), and each concrete component is compiled
into the library only when it is enabled. Dependencies between components are explicit,
for example the ASN.1 chain below, and nothing is pulled in implicitly. The header-only
C++ wrapper adds cost only for the headers a program includes.

Every new format or standard, including the candidates in the
[format expansion candidates](../formats/format-roadmap.md), follows the same rule: its
own option, and no code or dependency added to builds that do not enable it.

Language bindings are expected to follow the same rule: a binding should expose a
component only when the matching C component is enabled, so a binding build can also be
limited to what it needs. Rust maps its default `lldp` Cargo feature to
`OPENTLV_LLDP`; other components still use the C library defaults. Mapping the
remaining component options to Cargo features is future work; see
[Rust bindings](../development/rust.md#build). Ready-made CMake recipes are in
[building only the components you need](../guides/select-components.md).

## Build configuration

All generic facilities, including the configurable Fixed format, are always available.

### Generic core formats

| Format | Availability |
| --- | --- |
| [Configurable fixed-width TLV](../formats/fixed/configurable.md) | Always built; shared C implementation and C++ wrapper |

### Built-in standards

These packages default to ON and can be disabled subject to the dependencies below.

| CMake option / generated config macro | Included component |
| --- | --- |
| `OPENTLV_DHCP` | [DHCPv4 option framing](../formats/dhcp/README.md), including Pad and End |
| `OPENTLV_BLUETOOTH` | Bluetooth LTV format, containers, definitions, schemas and codecs |
| `OPENTLV_LLDP` | LLDP packed framing, base definitions and binding presets; no LLDPDU schemas/codecs |
| `OPENTLV_FORMAT_ASN1` | ASN.1-related wire formats (BER, DER, CER) |
| `OPENTLV_FORMAT_BER` | Public BER format |
| `OPENTLV_FORMAT_DER` | DER format and bounded DER validation operations |
| `OPENTLV_FORMAT_CER` | CER format and bounded CER validation operations |
| `OPENTLV_EMV` | EMV framing, dictionary, schemas and value codecs |

The [mutable document](../guides/document.md) is a separate optional generic component,
controlled by `OPENTLV_DOCUMENT`; it is not a format or a standard package.

`OPENTLV_FORMAT_ASN1`, `OPENTLV_FORMAT_BER`, `OPENTLV_FORMAT_DER`, and
`OPENTLV_EMV` form a tree (ASN1 -> BER -> DER/CER/EMV): disabling an
option forces every option below it OFF as well, regardless of how that
option was set, so `-DOPENTLV_FORMAT_BER=OFF` also disables DER, CER and EMV.
`OPENTLV_FORMAT_CER` is an independent sibling of `OPENTLV_FORMAT_DER` under
`OPENTLV_FORMAT_BER`, not a descendant of it: CER never depends on DER (or
vice versa), and disabling DER does not affect CER or EMV. This cascade is
centralized in `cmake/format_options.cmake`. EMV element framing uses generic
variable-width primitives directly; the BER build dependency remains only for
the unchanged DOL identifier helper. No component creates
another public binary library. `tlv/config.h` exposes the configured
selection, including `OPENTLV_FORMAT_ASN1`. Explicitly including a disabled
component's header does not provide its symbols; consumers should use the
config macros when supporting reduced builds.

Tests that require disabled components and examples that demonstrate them are
omitted. Generic architecture tests use an application-defined format and run
even when all protocol extensions are disabled. The benchmark uses BER and
is built only when that component is enabled.

```sh
cmake -S . -B build-minimal \
  -DOPENTLV_BLUETOOTH=OFF -DOPENTLV_LLDP=OFF -DOPENTLV_DHCP=OFF -DOPENTLV_FORMAT_ASN1=OFF
cmake --build build-minimal --parallel
```

## Migration

OpenTLV is before 1.0.0, so the public API is still allowed to change; see
[C ABI compatibility](../development/abi-compatibility.md). This section is a
best-effort record of the breaking changes below, not a compatibility
guarantee or an exhaustive migration guide.

Update flat includes to the folders above (`tlv/reader.h` becomes
`tlv/reader/reader.h`, and so on). Concrete format declarations use
`tlv/formats/fixed.h`,
`tlv/builtins/asn1/ber.h`, or `tlv/builtins/asn1/der.h`; the public
aggregate includes enabled formats.

`tlv/formats/` and `tlv/profiles/` (#279) no longer exist: every built-in
protocol implementation moved under `builtins/<protocol>/`. Concrete format
headers keep their names (`tlv/formats/asn1/der.h` becomes
`tlv/builtins/asn1/der.h`); the bounded DER/CER validation headers are renamed
to avoid colliding with the wire-format headers of the same name
(`tlv/profiles/der.h` becomes `tlv/builtins/asn1/der_validation.h`,
`tlv/profiles/cer.h` becomes `tlv/builtins/asn1/cer_validation.h`). EMV moves
and consolidates under `tlv/builtins/emv/`: `tlv/profiles/emv.h` becomes
`tlv/builtins/emv/emv.h`, `tlv/profiles/emv_schema.h`,
and `tlv/profiles/dol.h` move alongside it unchanged, and `tlv/codec/emv.h` (the semantic value codecs) becomes
`tlv/builtins/emv/emv_codec.h` to avoid colliding with the umbrella EMV
header. The former `emv_tags.def` X-macro is subsequently removed in #381;
EMV uses explicit domain dictionary tables. `tlv/schemas/schema.h` becomes `tlv/schema/schema.h`.

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

Traversal and schema APIs obtain the optional nesting predicate from
`tlv_format_t::is_constructed`; it receives the format context and parsed tag.
BER, DER and CER share `tlv_asn1_is_constructed`. Structure codecs likewise
use their Format descriptor for framing and constructed-element detection.

Reunify the reader and writer format descriptors that #68 split apart:
`tlv_reader_format_t`/`tlv_writer_format_t` are replaced by one `tlv_format_t`
whose read and write callback groups are each independently optional. A
format that only fills in the read group cannot be used to write, and vice
versa; a format missing the capability an operation needs now fails at
`tlv_reader_init`/`tlv_writer_init`/`tlv_structure_decode`-or-`_encode`/
`tlv_document_create` time instead of being rejected by the compiler. Replace
`tlv_reader_format_<name>`/`tlv_writer_format_<name>` constants with the
single `tlv_format_<name>` per format. Replace
`tlv_reader_format_init`/`tlv_writer_format_init`/`tlv_reader_format_init_element`/
`tlv_writer_format_init_header` with the canonical `tlv_format_init`,
and the private `tlv_reader_format_usable`/`tlv_writer_format_usable` checks
with the now-public `tlv_format_can_read`/`tlv_format_can_write`.
`tlv_fixed_reader_format_init`/`tlv_fixed_writer_format_init` become one
`tlv_fixed_format_init`. `tlv_structure_codec_t` and `tlv_document_options_t`
each replace their separate `reader_format`/`writer_format` pointers with one
`format` field, and `tlv_document_options_init` drops its `writer_format`
parameter. `tlv::document_format` and `tlv::fixed_format<>` (`tlv++`) collapse
the same way, with `fixed_format<>::reader()`/`::writer()` replaced by
`::format()`. Rebuild all consumers. (#326)

Move the configurable fixed-width format out of `builtins/` into the new
top-level `formats/`, since it names no protocol: `tlv/builtins/fixed/fixed.h`
becomes `tlv/formats/fixed.h`, and `tlv++/builtins/fixed/fixed_format.hpp`
becomes `tlv++/formats/fixed_format.hpp`. This is a narrower, second
reintroduction of a `formats/` folder than the one #279 removed (see above):
it holds only mechanisms that are themselves protocol-agnostic, not every
concrete format regardless of protocol. `tlv_fixed_config_t` is renamed to `tlv_fixed_format_t`
without any other change to its fields or to `tlv_fixed_format_init()`'s
behavior. No compatibility shim; rebuild all consumers. (#327)

`tlv::fixed_format<>` (`tlv++`) no longer reimplements the wire-format
callbacks; `format()` now builds and returns a descriptor from
`tlv_fixed_format_init()`, so the C and C++ APIs share one implementation.
Two consequences follow: the descriptor's `context` is no longer `NULL` (it
is a static `tlv_fixed_format_t` built from `TagWidth`, `LengthWidth` and
`Order`), and `tlv::fixed_format<>` links to the always-built C Fixed
implementation. `static_assert`-checked compile-time validation of `TagWidth`,
`LengthWidth` and `Order` is unchanged. No compatibility shim; rebuild all
consumers.

Move constructed-element detection into `tlv_format_t` as an optional
`is_constructed` field, instead of passing a separate `tlv_is_constructed_fn`
predicate alongside a format: `tlv_walk_tree`, `tlv_schema_validate`,
`tlv_schema_validate_all`, `tlv_schema_validate_all_diag`, `tlv_query_walk`,
`tlv::walk_tree`, `tlv::query::walk`, `tlv::validate`, `tlv::validate_all` and
`tlv::validate_all_diag` each drop that parameter and read
`format->is_constructed` instead. `tlv_document_options_t`/
`tlv::document_format` and `tlv_structure_codec_t` likewise drop their own
separate `is_constructed` field, and `tlv_document_options_init()` drops its
`is_constructed` parameter. The BER, DER and CER format descriptors
(`tlv_format_ber`, `tlv_format_der`, `tlv_format_cer`) now set
`is_constructed` themselves; Fixed formats still leave it
`NULL`. No compatibility shim; rebuild all consumers.

See also the generated [C API reference](../reference/c-api.md) and [C++ API reference](../reference/cxx-api.md).

The current wire boundary is specified by the [Format/Element contract](format-contract.md).

### Removing Profile (#380)

The architectural capabilities are Definition, Format, Schema and Codec. Module
means a reusable composition of any subset of them. Builtins remain native,
optional implementations that work without the future `.otlv` interpreter.

| Previous public name | Replacement |
| --- | --- |
| `OPENTLV_PROFILE_EMV` | `OPENTLV_EMV` (same defaults and dependencies) |
| `tlv_config_profile_emv()` | `tlv_config_emv()` |
| `tlv/builtins/asn1/der_profile.h` | `tlv/builtins/asn1/der_validation.h` |
| `tlv/builtins/asn1/cer_profile.h` | `tlv/builtins/asn1/cer_validation.h` |
| CLI `--profile emv` | `--module emv` |
| CLI/WASM JSON `profile` | `module` |
| WASM `PROFILES`, `api.profiles`, parse option `profile` | `MODULES`, `api.modules`, `module` |
| Rust `Profile::Der`, `Profile::Cer` | `Format::Der`, `Format::Cer` |
| Rust `ProfileError` | `ValidationError` |

The old names have no compatibility aliases. Reconfigure existing builds using
`OPENTLV_EMV`; an old cache entry does not control the renamed option. Rust
`default_limits()` now returns a `Result`; bounded validation operations reject
formats other than DER/CER with `InvalidArg` at offset zero. Reader/Writer keep
using their selected Format directly. Standard guides now live in `standards/`.

CLI `--module emv` selects the existing native EMV definitions, schemas and
codecs for the relevant command; `--format` selects framing independently. WASM
uses the selected module's definitions to annotate parsed elements. Neither
selector loads `.otlv` files or requires a runtime interpreter.
