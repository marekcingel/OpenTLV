# Reference

Reference documentation is lookup material: exact contracts, limits and
support matrices, as opposed to the task-oriented [guides](../guides/schemas.md)
and the explanatory [concepts](../concepts/architecture.md).

- [C API reference](c-api.md): generated from the public `tlv` headers,
  organized by API area with links to the matching guides and concepts.
- [C++ API reference](cxx-api.md): generated from the public `tlv++` headers,
  linked to the C reference for the underlying declarations.
- [Supported compilers and build settings](compilers.md)

Both API references are generated with Doxygen during the documentation build
and published under this section, so guides, concepts and API pages are one
site. To generate them locally, follow the
[C API](../../CONTRIBUTING.md#generate-the-c-api-reference) instructions in
the contributing guide, or download the `c-api-reference` and
`cxx-api-reference` artifacts from the Documentation workflow.

Future API manuals, language-binding references and option tables belong in
this section; see [where documentation belongs](../development/documentation-layout.md).
