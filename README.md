# OpenTLV
Modern, dependency-free TLV encoding/parsing — C core + header-only C++ wrapper.

Supported compilers: GCC, MSVC, and Clang 18+. See [compiler support and build instructions](docs/compilers.md).

See [layered architecture](docs/architecture.md) for module responsibilities, component build options, nested traversal, structural schemas and API migration.

## Reader and writer formats

Raw I/O uses distinct `tlv_reader_format_t` and `tlv_writer_format_t` descriptors.
For the default encoding, pass `&tlv_reader_format_default` to the reader and
`&tlv_writer_format_default` to the writer. Custom formats can implement either
direction independently using the corresponding `tlv_*_format_init` function.
See [format contracts](docs/formats.md#generic-interface) and
[API migration](docs/architecture.md#migration).
