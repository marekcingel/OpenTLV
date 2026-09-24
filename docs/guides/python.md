# Using OpenTLV from Python

The `opentlv` package is an experimental, infrastructure-only Python binding
for OpenTLV: it currently exposes only the linked C library's version, as a
proof that the native extension builds, links and packages correctly. For
layout and build details, see [Python bindings](../development/python.md).

## Setup

Neither package is published to PyPI yet. Install both by path from a
checkout of the repository, in one `pip install` call so the `opentlv`
package's dependency on `opentlv-native` resolves to the local build:

```sh
pip install ./bindings/python/opentlv-native ./bindings/python/opentlv
```

This requires Python 3.11 or newer, CMake 3.26 or newer and a C99 compiler;
see [Build](../development/python.md#build).

```python
import opentlv

print(opentlv.__version__)
```

## Relationship to the C API

`opentlv-native` (imported as `opentlv_native`) is a native extension written
directly against the CPython C API (no pybind11, cffi or Cython) and the
CPython Limited API, declaring and calling the public OpenTLV C API;
`opentlv` wraps it and contains no C API calls of its own, the same split as
the Rust `opentlv-native`/`opentlv` crates. Only `tlv_version_string()` is
called so far. Future work adds the Reader, Writer, Tag and other types from
the [language bindings conceptual model](../concepts/bindings.md), each
calling into the C API the same way the Rust and C++ bindings already do.
