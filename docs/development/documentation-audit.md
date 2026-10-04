# Documentation audit for #513

This inventory covers tracked Markdown entry points, learning pages, reference,
formats, standards, examples, bindings and contributor material. Generated
Doxygen content is reviewed through its source roots and reference entry pages;
it remains generated rather than copied here.

## Findings and canonical sources

| Area | Finding | Canonical source and action |
| --- | --- | --- |
| Root README | Support/candidate lists preceded first usage; complete examples duplicated onboarding | Compact landing page; support inventory and roadmap retain detailed scope |
| Website and GitHub indexes | Two broad indexes repeated the same choices | Website homepage is the shared user index; GitHub README points to it |
| Installation and first programs | Loader/build detail appeared before language choice | Getting Started owns integration and verified multi-language first programs |
| Concepts and architecture | Deep contracts lacked an introductory bridge | Basic model introduces Element, Reader/Writer and Document; architecture owns exact responsibilities |
| Task guides | Navigation placed advanced memory/schema topics before Reader | Read/write/edit first; optional consumers and contracts follow |
| Bindings | User and development material have distinct responsibilities | Language guides own public usage; binding matrix owns parity; component README links guide first |
| CLI | Build details preceded useful commands | First inspection with exact input/output precedes build reference |
| WebAssembly | Build tooling is needed for embedding, but not browser inspection | Playground is the user entry; WebAssembly guide owns embedding/build details |
| Formats and standards | Scope descriptions are useful and must survive README reduction | Support inventory owns availability; individual pages own framing/conformance limits |
| Memory and diagnostics | Safety must remain visible without requiring exhaustive contracts | First examples keep lifetime/error checks; memory and diagnostic guides own advanced rules |
| Custom formats | Callback contracts require the shared model | Link from basic model and format overview; keep custom-format implementation reference |
| Examples | Marked blocks already have source synchronization | Keep runnable sources and existing example checks; avoid new competing complete snippets |
| Roadmap | Current and future models can be confused | ROADMAP and runtime-model pages own plans; explicitly label future diagrams |
| Contributors | Layout guidance exists but progressive disclosure is implicit | Record audience, prerequisites, diagrams and navigation conventions |

## Review boundaries

This is an information-architecture and entry-point review, not a new protocol
conformance audit or proof of binding parity. Preserve technical sections and
source examples. Existing support limitations remain authoritative. The existing
documentation inventory checker verifies source-derived coverage, not prose.

Paths stay unchanged for existing pages. README heading anchors remain as
migration entry points; their links route to canonical detailed pages. No new
redirect service or runtime API is introduced.

## Page inventory

The table records each tracked Markdown page's audience, prerequisite level and
review decision. Links identify its current canonical location. Topic-specific
prerequisites are clarified in the learning pages rather than copied into API
reference or release notes.

| Page / canonical location | Audience | Prerequisite | Review decision |
| --- | --- | --- | --- |
| [PULL_REQUEST_TEMPLATE.md](../../.github/PULL_REQUEST_TEMPLATE.md) | User | None or selected API setup | Use task entry and recommended next step |
| [Repository instructions](../../AGENTS.md) | Contributor | Build workflow | Keep separate from user onboarding |
| [Changelog](../../CHANGELOG.md) | Lookup | Topic-specific | Keep exact contracts/status; link from learning pages |
| [Contributor Covenant Code of Conduct](../../CODE_OF_CONDUCT.md) | Contributor | Build workflow | Keep separate from user onboarding |
| [Contributing to OpenTLV](../../CONTRIBUTING.md) | Contributor | Build workflow | Keep separate from user onboarding |
| [README.md](../../README.md) | User | None or selected API setup | Use task entry and recommended next step |
| [Roadmap](../../ROADMAP.md) | Lookup | Topic-specific | Keep exact contracts/status; link from learning pages |
| [Security Policy](../../SECURITY.md) | Contributor | Build workflow | Keep separate from user onboarding |
| [Local benchmarks](../../benchmarks/README.md) | User | None or selected API setup | Use task entry and recommended next step |
| [Benchmark baselines](../../benchmarks/baselines/README.md) | User | None or selected API setup | Use task entry and recommended next step |
| [Go binding (experimental)](../../bindings/go/README.md) | Binding user / contributor | Language toolchain | Link public user guide before native/build details |
| [opentlv (Lua, experimental)](../../bindings/lua/README.md) | Binding user / contributor | Language toolchain | Link public user guide before native/build details |
| [opentlv-core (experimental)](../../bindings/python/opentlv-core/README.md) | Binding user / contributor | Language toolchain | Link public user guide before native/build details |
| [opentlv (experimental)](../../bindings/python/opentlv/README.md) | Binding user / contributor | Language toolchain | Link public user guide before native/build details |
| [Documentation](../../docs/README.md) | User | None or selected API setup | Use task entry and recommended next step |
| [OpenTLV logo](../../docs/assets/README.md) | User | None or selected API setup | Use task entry and recommended next step |
| [Command-line tool](../../docs/cli/README.md) | User | None or selected API setup | Use task entry and recommended next step |
| [TLV JSON document](../../docs/cli/json-schema.md) | User | None or selected API setup | Use task entry and recommended next step |
| [Core architectural rules](../../docs/concepts/architectural-rules.md) | User / extension author | Basic model | Add learning context; preserve detailed contracts |
| [Layered OpenTLV architecture (#65, #279, #280, #281, #327)](../../docs/concepts/architecture.md) | User / extension author | Basic model | Add learning context; preserve detailed contracts |
| [Common conceptual model for language bindings](../../docs/concepts/bindings.md) | User / extension author | Basic model | Add learning context; preserve detailed contracts |
| [C core types](../../docs/concepts/core-types.md) | User / extension author | Basic model | Add learning context; preserve detailed contracts |
| [C++ built-in standards](../../docs/concepts/cxx-builtins.md) | User / extension author | Basic model | Add learning context; preserve detailed contracts |
| [C++ Format customization](../../docs/concepts/cxx-formats.md) | User / extension author | Basic model | Add learning context; preserve detailed contracts |
| [C++ public and native boundary](../../docs/concepts/cxx-native-boundary.md) | User / extension author | Basic model | Add learning context; preserve detailed contracts |
| [Definition boundary audit (#381)](../../docs/concepts/definition-boundaries.md) | User / extension author | Basic model | Add learning context; preserve detailed contracts |
| [Integer byte-order conversions](../../docs/concepts/endian.md) | User / extension author | Basic model | Add learning context; preserve detailed contracts |
| [Format and Element contract](../../docs/concepts/format-contract.md) | User / extension author | Basic model | Add learning context; preserve detailed contracts |
| [Logical TLV value lengths](../../docs/concepts/length.md) | User / extension author | Basic model | Add learning context; preserve detailed contracts |
| [Canonical processing pipeline](../../docs/concepts/processing-pipeline.md) | User / extension author | Basic model | Add learning context; preserve detailed contracts |
| [Phase 2 runtime model and canonical IR](../../docs/concepts/runtime-model.md) | User / extension author | Basic model | Add learning context; preserve detailed contracts |
| [Borrowed TLV values](../../docs/concepts/value.md) | User / extension author | Basic model | Add learning context; preserve detailed contracts |
| [C ABI compatibility](../../docs/development/abi-compatibility.md) | Contributor | Build workflow | Keep separate from user onboarding |
| [Where documentation belongs](../../docs/development/documentation-layout.md) | Contributor | Build workflow | Keep separate from user onboarding |
| [Fuzzing the C API](../../docs/development/fuzzing.md) | Contributor | Build workflow | Keep separate from user onboarding |
| [Go binding development](../../docs/development/go.md) | Contributor | Build workflow | Keep separate from user onboarding |
| [Lua bindings (experimental)](../../docs/development/lua.md) | Contributor | Build workflow | Keep separate from user onboarding |
| [Python bindings (experimental)](../../docs/development/python.md) | Contributor | Build workflow | Keep separate from user onboarding |
| [Rust bindings (experimental)](../../docs/development/rust.md) | Contributor | Build workflow | Keep separate from user onboarding |
| [WebAssembly build (experimental)](../../docs/development/webassembly.md) | Contributor | Build workflow | Keep separate from user onboarding |
| [Development workflow](../../docs/development/workflow.md) | Contributor | Build workflow | Keep separate from user onboarding |
| [C library formats](../../docs/formats/README.md) | Format user | Reader and matching format | Keep scope and limitations canonical |
| [BER-TLV](../../docs/formats/asn1/ber.md) | Format user | Reader and matching format | Keep scope and limitations canonical |
| [CER-TLV](../../docs/formats/asn1/cer.md) | Format user | Reader and matching format | Keep scope and limitations canonical |
| [DER-TLV](../../docs/formats/asn1/der.md) | Format user | Reader and matching format | Keep scope and limitations canonical |
| [Bluetooth LTV](../../docs/formats/bluetooth/README.md) | Format user | Reader and matching format | Keep scope and limitations canonical |
| [Application-defined format example](../../docs/formats/custom/README.md) | Format user | Reader and matching format | Keep scope and limitations canonical |
| [DHCPv4 option framing](../../docs/formats/dhcp/README.md) | Format user | Reader and matching format | Keep scope and limitations canonical |
| [Configurable fixed-width TLV](../../docs/formats/fixed/configurable.md) | Format user | Reader and matching format | Keep scope and limitations canonical |
| [Format candidate catalogue](../../docs/formats/format-catalogue.md) | Format user | Reader and matching format | Keep scope and limitations canonical |
| [Format trees and byte examples](../../docs/formats/format-examples.md) | Format user | Reader and matching format | Keep scope and limitations canonical |
| [Format expansion candidates](../../docs/formats/format-roadmap.md) | Format user | Reader and matching format | Keep scope and limitations canonical |
| [LLDP requirements and Format/Layout review](../../docs/formats/lldp-review.md) | Format user | Reader and matching format | Keep scope and limitations canonical |
| [LLDP TLV support](../../docs/formats/lldp/README.md) | Format user | Reader and matching format | Keep scope and limitations canonical |
| [LLDP reference tests and conformance boundary](../../docs/formats/lldp/conformance.md) | Format user | Reader and matching format | Keep scope and limitations canonical |
| [NFC Forum Type 2 Tag TLV framing](../../docs/formats/nfc/README.md) | Format user | Reader and matching format | Keep scope and limitations canonical |
| [Implemented format and standard capabilities](../../docs/formats/support.md) | Format user | Reader and matching format | Keep scope and limitations canonical |
| [Configurable variable-width TLV](../../docs/formats/variable.md) | Format user | Reader and matching format | Keep scope and limitations canonical |
| [Getting started](../../docs/getting-started/README.md) | User | None or selected API setup | Use task entry and recommended next step |
| [C value codecs](../../docs/guides/codecs.md) | User | None or selected API setup | Use task entry and recommended next step |
| [Explicit TLV copies](../../docs/guides/copy.md) | User | None or selected API setup | Use task entry and recommended next step |
| [C++ examples](../../docs/guides/cxx-examples.md) | User | None or selected API setup | Use task entry and recommended next step |
| [Diagnostics](../../docs/guides/diagnostics.md) | User | None or selected API setup | Use task entry and recommended next step |
| [Mutable documents](../../docs/guides/document.md) | User | None or selected API setup | Use task entry and recommended next step |
| [Executable examples and workflow coverage](../../docs/guides/examples.md) | User | None or selected API setup | Use task entry and recommended next step |
| [Using OpenTLV from Go](../../docs/guides/go.md) | User | None or selected API setup | Use task entry and recommended next step |
| [Using OpenTLV from Lua](../../docs/guides/lua.md) | User | None or selected API setup | Use task entry and recommended next step |
| [Memory ownership and lifetime](../../docs/guides/memory.md) | User | None or selected API setup | Use task entry and recommended next step |
| [Choose a processing API](../../docs/guides/processing.md) | User | None or selected API setup | Use task entry and recommended next step |
| [Using OpenTLV from Python](../../docs/guides/python.md) | User | None or selected API setup | Use task entry and recommended next step |
| [Path queries](../../docs/guides/queries.md) | User | None or selected API setup | Use task entry and recommended next step |
| [Pull-based Reader](../../docs/guides/reader.md) | User | None or selected API setup | Use task entry and recommended next step |
| [Using OpenTLV from Rust](../../docs/guides/rust.md) | User | None or selected API setup | Use task entry and recommended next step |
| [Optional C schemas](../../docs/guides/schemas.md) | User | None or selected API setup | Use task entry and recommended next step |
| [Build only the components you need](../../docs/guides/select-components.md) | User | None or selected API setup | Use task entry and recommended next step |
| [Writer and scoped construction](../../docs/guides/writer.md) | User | None or selected API setup | Use task entry and recommended next step |
| [OpenTLV documentation](../../docs/index.md) | User | None or selected API setup | Use task entry and recommended next step |
| [Playground](../../docs/playground/index.md) | User | None or selected API setup | Use task entry and recommended next step |
| [Reference](../../docs/reference/README.md) | Lookup | Topic-specific | Keep exact contracts/status; link from learning pages |
| [C API reference](../../docs/reference/c-api.md) | Lookup | Topic-specific | Keep exact contracts/status; link from learning pages |
| [Supported compilers](../../docs/reference/compilers.md) | Lookup | Topic-specific | Keep exact contracts/status; link from learning pages |
| [C++ API reference](../../docs/reference/cxx-api.md) | Lookup | Topic-specific | Keep exact contracts/status; link from learning pages |
| [Error codes](../../docs/reference/errors.md) | Lookup | Topic-specific | Keep exact contracts/status; link from learning pages |
| [ASN.1 CER-TLV](../../docs/standards/cer/README.md) | Format user | Reader and matching format | Keep scope and limitations canonical |
| [ASN.1 DER-TLV](../../docs/standards/der/README.md) | Format user | Reader and matching format | Keep scope and limitations canonical |
| [EMV Contact Book 3 support](../../docs/standards/emv/README.md) | Format user | Reader and matching format | Keep scope and limitations canonical |
| [NFC Type 2 validation corpus](../../examples/nfc/type2/README.md) | Example user | Selected API setup | Keep runnable sources canonical |
| [C++ examples](../../examples/tlv++/src/README.md) | Example user | Selected API setup | Keep runnable sources canonical |
| [C examples](../../examples/tlv/src/README.md) | Example user | Selected API setup | Keep runnable sources canonical |
| [Test layout](../../tests/README.md) | User | None or selected API setup | Use task entry and recommended next step |
| [Deterministic property suite](../../tests/property/README.md) | User | None or selected API setup | Use task entry and recommended next step |
