# Changelog

All notable changes to OpenTLV are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- Fixed strict C++11/14 builds of the C++ wrapper by enabling `[[nodiscard]]` only in C++17 and newer. (#60)
- Fixed GCC builds of the C API tests by including `<cstring>` for `std::memcmp` and `std::memset`. (#22)

### Added

- ASN.1 DER-TLV support with canonical tag and length validation, tag class and constructed accessors, bounded nested traversal, byte-offset errors, and deterministic encoding. Universal value decoding and SET ordering remain outside the supported TLV scope. (#59)
- Official Clang 18+ support with compiler warnings, a warnings-as-errors CI job for C99 and C++11/14/17/20/23, and build documentation. (#60)
- EMV Contact Book 3 v4.4 tag dictionary with context-specific length schemas and explicit numeric, enum, date, time, and digit-string value codecs, using generic BER-TLV I/O. (#40)
- Explicit allocation-free helpers to copy values, serialize views, or preserve complete encoded TLV ranges in caller-provided storage, with size queries and destination capacity checks. (#39)
- Generic allocation-free C value codecs with caller-provided storage, zero-copy representation support, encoding size queries, and errors independent of TLV framing. (#38)
- BER-TLV format (`tlv_format_ber`) with multi-byte tags, configurable tag capacity validation, definite short- and long-form lengths, and malformed/truncated-input detection. (#36)
- Explicit big-endian and little-endian helpers for reading and writing 16-bit and 32-bit integer values, independent of host byte order and TLV profile. (#37)
- Allocation-free `tlv_scan()` recovery API to find complete TLV candidates from any buffer offset, with optional schema tag and value-length validation. (#35)
- Optional constant-table TLV schemas with tag lookup and exact or minimum/maximum value-length validation, without runtime registration or allocation. (#34)
- Allocation-free `tlv_walk()` and visitor API for sequential traversal, early stopping, and reader/visitor error reporting without automatic recursion into nested values. (#33)
- Generic `tlv_write()` and `tlv_encoded_size()` APIs for allocation-free encoding into caller-provided buffers, with capacity and size-overflow checks. (#32)
- Zero-copy `tlv_read()` API for parsing one element with a configured format, complete bounds checking, and the consumed encoded size. (#31)
- Fixed 1-byte TLV format (`tlv_format_fixed_1byte`) with one-byte tags and lengths, values up to 255 bytes, and truncated-input detection. (#30)
- Generic `tlv_format_t` callbacks and reader/writer initialization with custom formats, without dynamic allocation. (#29)
- Format-independent core types in `tlv/types.h`: non-owning `tlv_buffer_t`, raw-byte `tlv_tag_t` with configurable `TLV_TAG_MAX_SIZE` (default 8, range 1–255), and `tlv_view_t` with a borrowed value. (#28)
- Runtime version API for checking the version and Git metadata compiled into the loaded OpenTLV library. (#26)
- Public generated `tlv/version.h` header deriving the Semantic Versioning components and optional pre-release identifier from the latest Git tag, and exposing Git revision, tag, commit hash, branch, and repository version metadata. (#26)
- Optional Google Benchmark suite for measuring TLV parsing and encoding throughput. (#14)
- GoogleTest integration and CTest discovery for the C API and C++ wrapper test suites. (#22)
- GitHub Actions workflow that configures, builds, and runs tests on Ubuntu and Windows for pushes and pull requests targeting `main`.
- Configurable `OPENTLV_BUILD_EXAMPLES` option and dedicated CMake targets for the C and C++ examples.
- Dedicated CMake targets for the C and C++ test suites.

### Changed

- Expanded the C usage example to demonstrate single-element and sequential I/O, explicit copies and size queries, BER and custom formats, schemas, walking and scanning, value codecs, endian helpers, runtime version information, and error handling. (#39)
- C reader/writer initializers and C++ constructors now require an explicit format. Reader and writer structs hold a borrowed format pointer; consumers must be updated and rebuilt. (#29)
- Reader results now use `tlv_view_t`, and the writer and C++ codecs use raw-byte `tlv_tag_t` tags. Removed `tlv_entry_t` and `tlv_bytes_t`; the current single-byte writer rejects other tag sizes with `TLV_ERR_INVALID_TAG`. (#28)
- Updated the GitHub Actions checkout to fetch complete Git history and tags for generated version metadata. (#26)
- Lowered the minimum C++ standard for the `tlv++` wrapper to C++11 while using standard-library byte, span, any, and expected types when the selected language standard provides them. (#9)
- Migrated the C API and C++ wrapper tests from custom assertion harnesses to GoogleTest. (#22)
- Changed `tlv_entry_t` to expose both the tag and value as `tlv_bytes_t` zero-copy byte spans.
- Updated the GitHub Actions checkout action to `actions/checkout@v5`.
- Reorganized examples and tests into `tlv` and `tlv++` source directories and moved their build definitions out of the library targets.
- Made the top-level CMake project language-agnostic so the C++ layer, tests, and examples can configure their own language requirements.
- Replaced the C++ codec registry's unordered decoder storage with ordered `std::map` storage.

## [0.0.1] - 2026-09-01

### Added

- Initial OpenTLV library draft, including a dependency-free C core for TLV encoding and decoding.
- Header-only C++ wrapper with reader, writer, codec, and runtime codec registry APIs.
- C and C++ usage examples, plus C core tests.
