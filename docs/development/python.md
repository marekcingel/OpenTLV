# Python bindings (experimental)

The Python bindings live in `bindings/python/`, two separately packaged
distributions:

| Package | Purpose |
| --- | --- |
| `opentlv-native` | Native extension, written directly against the CPython C API; registers the OpenTLV C API as Python callables |
| `opentlv` | Pure-Python package built on `opentlv-native` |

This mirrors the Rust bindings' `opentlv-native`/`opentlv` split (see [Rust
bindings](rust.md)): all CPython C API interaction is isolated in
`opentlv-native`; `opentlv` is plain Python and imports
`opentlv_native` directly (there is no intermediate underscore-prefixed
submodule; `import opentlv_native` resolves straight to the compiled
extension). For setup and usage, see [Using OpenTLV from
Python](../guides/python.md). For the naming and shape this binding follows
and adapts, see the [language bindings conceptual model](../concepts/bindings.md).

This is infrastructure only: `opentlv-native` exposes just the linked
library's version so far, proving the build, link and packaging pipeline
end to end. Reader, Writer, Tag and the other conceptual-model types are not
bound yet.

## Build

Requirements: Python 3.11 or newer, CMake 3.26 or newer and a C99 compiler.

```sh
pip install ./bindings/python/opentlv-native ./bindings/python/opentlv
pip install pytest
pytest bindings/python/tests
```

[scikit-build-core](https://scikit-build-core.readthedocs.io/) drives the
`opentlv-native` build: it configures and builds the OpenTLV C library with
CMake from the repository root
(`bindings/python/opentlv-native/pyproject.toml` points
`tool.scikit-build.cmake.source-dir` at it), as a static library, and links
it into the extension. The C++ layer, CLI, tests and examples are not built.
The extension is compiled against the CPython Limited API
(`Py_LIMITED_API=0x030B0000`) as an `abi3` module, so one wheel per platform
works on every Python 3.11 and newer. `opentlv` is a plain
[hatchling](https://hatch.pypa.io/latest/plugins/builder/wheel/)-built wheel
with no compiled component; it declares `opentlv-native` as a dependency.
Neither package is published anywhere yet, so install both together from a
checkout, as above; when installed in the same `pip install` invocation, pip
resolves `opentlv`'s `opentlv-native` dependency against the local wheel it
just built instead of looking on PyPI.

## Versioning

Each package's own version, declared in its `pyproject.toml`, is independent
of the OpenTLV C library's version and is not derived from the repository's
Git tags; it follows its own release cadence, the same way the Rust crates'
`Cargo.toml` version does (see [Rust bindings](rust.md#versioning)).
`opentlv.__version__` is a separate thing: it calls `tlv_version_string()` at
import time (through `opentlv-native`) and reports the version of the
*linked C library*, not either package's own version. The two can differ,
for example packages at `0.1.0` built against OpenTLV C library `0.6.0`.

## Continuous integration

The [Python Bindings
workflow](https://github.com/marekcingel/OpenTLV/blob/main/.github/workflows/python.yml)
runs on every push and pull request to `main`: it installs both packages with
`pip install ./bindings/python/opentlv-native ./bindings/python/opentlv` and
runs `pytest bindings/python/tests` on Linux, and additionally on Windows and
macOS for release tags.
