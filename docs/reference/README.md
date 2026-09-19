# Reference

Reference documentation is lookup material: exact contracts, limits and
support matrices, as opposed to the task-oriented [guides](../guides/schemas.md)
and the explanatory [concepts](../concepts/architecture.md).

- [Supported compilers and build settings](compilers.md)

The C API reference is generated from the public [tlv](../../tlv/include/tlv)
headers with Doxygen. Follow the [local generation instructions](../../CONTRIBUTING.md#generate-the-c-api-reference)
or download the `c-api-reference` artifact from the Documentation workflow.
It covers types, reader/writer APIs, traversal, schemas, codecs, formats,
profiles and copy utilities, including ownership and error contracts.

The generated C reference is not yet integrated into this site. A dedicated
C++ reference is also separate work; use the public
[tlv++ headers](../../tlv++/include/tlv++) for those API contracts.

Future API manuals, language-binding references and option tables belong in
this section; see [where documentation belongs](../development/documentation-layout.md).
