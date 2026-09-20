# C API reference

The C API reference is generated from the public [tlv](../../tlv/include/tlv)
headers with Doxygen and published with this site. Open the
[generated C API reference](api/c-api/html/index.html) for exact signatures,
ownership, lifetime and error contracts. It covers all shipped formats and
profiles, including those disabled in a particular library build.

Each area below pairs the generated reference with the guides and concepts
that explain it.

## Core types and utilities

[Generated reference](api/c-api/html/group__core.html). Read first:
[C core types](../concepts/core-types.md),
[borrowed values](../concepts/value.md),
[logical lengths](../concepts/length.md), [byte order](../concepts/endian.md)
and [memory ownership](../guides/memory.md).

## Reader

[Generated reference](api/c-api/html/group__reader.html). Read first:
[formats](../formats/README.md).

## Writer

[Generated reference](api/c-api/html/group__writer.html). Read first:
[formats](../formats/README.md).

## Traversal and scanning

[Generated reference](api/c-api/html/group__traversal.html). Read first:
[scanning and recovery](../guides/scanner.md).

## Schemas

[Generated reference](api/c-api/html/group__schemas.html). Read first:
[schemas and length validation](../guides/schemas.md).

## Codecs

[Generated reference](api/c-api/html/group__codecs.html). Read first:
[value codecs](../guides/codecs.md).

## Formats

[Generated reference](api/c-api/html/group__formats.html). Read first:
[format overview](../formats/README.md), [BER](../formats/asn1/ber.md),
[DER](../formats/asn1/der.md) and [CER](../formats/asn1/cer.md).

## Profiles

[Generated reference](api/c-api/html/group__profiles.html). Read first:
[DER](../profiles/der/README.md), [CER](../profiles/cer/README.md) and
[EMV](../profiles/emv/README.md).

## Copy utilities

[Generated reference](api/c-api/html/group__copy.html). Read first:
[copy helpers](../guides/copy.md).

## Other entry points

[Files](api/c-api/html/files.html) and
[data structures](api/c-api/html/annotated.html). The C++ wrappers have their
own [C++ API reference](cxx-api.md), which links back to these C declarations.

To build the reference locally, see
[Generate the C API reference](../../CONTRIBUTING.md#generate-the-c-api-reference).
The generated pages exist only in a built site or in the Documentation
workflow artifacts, so the direct links above do not resolve when this page is
read on GitHub.
