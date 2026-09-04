# Changelog

All notable changes to OpenTLV are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- GitHub Actions workflow that configures, builds, and runs tests on Ubuntu and
  Windows for pushes and pull requests targeting `main`.
- Configurable `OPENTLV_BUILD_EXAMPLES` option and dedicated CMake targets for
  the C and C++ examples.
- Dedicated CMake targets for the C and C++ test suites.
- GoogleTest integration and CTest discovery for the C API and C++ wrapper
  test suites.

### Changed

- Changed `tlv_entry_t` to expose both the tag and value as `tlv_bytes_t`
  zero-copy byte spans.
- Updated the GitHub Actions checkout action to `actions/checkout@v5`.
- Reorganized examples and tests into `tlv` and `tlv++` source directories and
  moved their build definitions out of the library targets.
- Made the top-level CMake project language-agnostic so the C++ layer, tests,
  and examples can configure their own language requirements.
- Replaced the C++ codec registry's unordered decoder storage with ordered
  `std::map` storage.
- Migrated the C API and C++ wrapper tests from custom assertion harnesses to
  GoogleTest.

## [0.0.1] - 2026-09-01

### Added

- Initial OpenTLV library draft, including a dependency-free C core for TLV
  encoding and decoding.
- Header-only C++ wrapper with reader, writer, codec, and runtime codec
  registry APIs.
- C and C++ usage examples, plus C core tests.
