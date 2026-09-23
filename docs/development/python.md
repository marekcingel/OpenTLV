# Python bindings (experimental)

The Python bindings live in `bindings/python/`:

| Path | Purpose |
| --- | --- |
| `src/_opentlv/` | Native extension, written directly against the CPython C API; declares and calls the OpenTLV C API |
| `src/opentlv/` | Pure-Python package built on `_opentlv` |

For setup and usage, see [Using OpenTLV from
Python](../guides/python.md). For the naming and shape this binding follows
and adapts, see the [language bindings conceptual model](../concepts/bindings.md).

All CPython C API interaction is isolated in `_opentlv`; `opentlv` is plain
Python. This is infrastructure only: `_opentlv` exposes just the linked
library's version so far, proving the build, link and packaging pipeline
end to end. Reader, Writer, Tag and the other conceptual-model types are not
bound yet.

## Build

Requirements: Python 3.11 or newer, CMake 3.26 or newer and a C99 compiler.

```sh
pip install ./bindings/python
pip install pytest
pytest bindings/python/tests
```

[scikit-build-core](https://scikit-build-core.readthedocs.io/) drives the
build: it configures and builds the OpenTLV C library with CMake from the
repository root (`bindings/python/pyproject.toml` points
`tool.scikit-build.cmake.source-dir` at it), as a static library, and links
it into the `_opentlv` extension. The C++ layer, CLI, tests and examples are
not built. `_opentlv` is compiled against the CPython Limited API
(`Py_LIMITED_API=0x030B0000`) as an `abi3` extension, so one wheel per
platform works on every Python 3.11 and newer.

## Continuous integration

The [Python Bindings
workflow](https://github.com/marekcingel/OpenTLV/blob/main/.github/workflows/python.yml)
runs on every push and pull request to `main`: it installs the package with
`pip install ./bindings/python` and runs `pytest bindings/python/tests` on
Linux, and additionally on Windows and macOS for release tags.
