# Changelog

All notable changes to OpenTLV are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Configurable `OPENTLV_BUILD_EXAMPLES` option and dedicated CMake targets for
  the C and C++ examples.
- Dedicated CMake targets for the C and C++ test suites.

### Changed

- Reorganized examples and tests into `tlv` and `tlv++` source directories and
  moved their build definitions out of the library targets.
- Made the top-level CMake project language-agnostic so the C++ layer, tests,
  and examples can configure their own language requirements.
- Replaced the C++ codec registry's unordered decoder storage with ordered
  `std::map` storage.

## [0.0.1] - 2026-09-01

### Added

- Initial OpenTLV library draft, including a dependency-free C core for TLV
  encoding and decoding.
- Header-only C++ wrapper with reader, writer, codec, and runtime codec
  registry APIs.
- C and C++ usage examples, plus C core tests.
