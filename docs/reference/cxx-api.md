# C++ API reference

The C++ API reference is generated from the public
[tlv++](../../tlv++/include/tlv++) headers with Doxygen and published with this
site. Open the [generated C++ API reference](api/cxx-api/html/index.html) for
the `tlv` namespace, classes and public headers. Include `tlv++/tlv.hpp` for
the complete header-only wrapper API; using it still requires linking the C
library.

- [Namespace `tlv`](api/cxx-api/html/namespacetlv.html)
- [Class index](api/cxx-api/html/classes.html) and
  [class list](api/cxx-api/html/annotated.html)
- [Public header index](api/cxx-api/html/files.html)

C declarations that the wrappers use link to the [C API reference](c-api.md)
instead of being repeated. For the concepts behind the wrappers, read
[architecture](../concepts/architecture.md),
[memory ownership](../guides/memory.md#custom-descriptors-and-c) and the
[schema guide](../guides/schemas.md); the C++ layer's ownership and error
contracts are stated on each declaration.

To build the reference locally, see the
"Generate the C++ API reference" section of [CONTRIBUTING.md](../../CONTRIBUTING.md).
The generated pages exist only in a built site or in the Documentation
workflow artifacts, so the direct links above do not resolve when this page is
read on GitHub.
