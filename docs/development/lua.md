# Lua bindings (experimental)

The Lua bindings live in `bindings/lua/`, split the same way the [Python
bindings](python.md) and [Rust bindings](rust.md) are: `opentlv-native`
(`bindings/lua/src/`), a native extension module written directly against
the Lua C API, and `opentlv` (`bindings/lua/lua/opentlv/init.lua`), a
one-line pure-Lua entry point that `require("opentlv")` resolves to and that
returns `opentlv-native` unchanged. Unlike Python's and Rust's pure layers,
`opentlv` adds no ergonomics of its own beyond the name callers request:
Lua's C API is close enough to the concepts this binding exposes (Reader,
Entry, Tag) that there is nothing a Lua-side wrapper would usefully add
today, so the split exists for naming/packaging consistency across bindings
rather than for a richer pure-Lua layer. `bindings/lua/src/common.h`
documents the ownership, registration and error-handling conventions every
native-side component (Reader today; Writer, Document, Schema, ... later)
follows, and states the rule for what belongs in this binding versus in
`tlv/`: functionality useful outside Lua belongs in the OpenTLV C API, this
binding only adapts what already exists there to Lua's conventions. For
usage, see [Using OpenTLV from Lua](../guides/lua.md). For the naming and
shape this binding follows and adapts, see the [language bindings conceptual
model](../concepts/bindings.md).

It targets Lua 5.1 through 5.4 and LuaJIT (which implements the Lua 5.1 C
API), using only the portable subset of the Lua C API common to all of them;
see `bindings/lua/src/compat.h`. It covers Reader, Entry and Tag, and
preorder tree traversal (`opentlv.walk_tree`, built on `tlv_walk_tree()`/
`tlv_der_walk()`); Writer, Document and Schema are not bound yet.

## Build

Requirements: CMake 3.16 or newer, a C99 compiler, and Lua 5.1, 5.2, 5.3, 5.4
or LuaJIT headers and library.

```sh
cmake -S . -B build-lua -DOPENTLV_BUILD_LUA=ON -DCMAKE_BUILD_TYPE=Release \
    -DOPENTLV_BUILD_CXX=OFF -DOPENTLV_BUILD_CLI=OFF -DOPENTLV_BUILD_TESTS=OFF \
    -DOPENTLV_BUILD_EXAMPLES=OFF
cmake --build build-lua --target opentlv_lua
```

or, from `bindings/lua`, `luarocks make`, which drives the same CMake build
and also installs `lua/opentlv/init.lua` (see
`bindings/lua/opentlv-scm-1.rockspec`). Either way this produces
`opentlv_native.so` (`opentlv_native.dll` on Windows); put it on
`LUA_CPATH` and `bindings/lua/lua/` on `LUA_PATH` (`luarocks make` does the
equivalent by installing into LuaRocks' own tree) so `require("opentlv")`
resolves through `init.lua` to it.

**On Windows**, the module must link against the same shared `lua5x.dll` the
embedding Lua interpreter uses, not a statically linked Lua: two
independently linked copies of the Lua runtime sharing one `lua_State`
corrupt memory under this module's calls back into Lua (`opentlv.walk_tree`'s
callback) and crash. This is generally not a concern on Linux and macOS,
where system Lua packages already ship a shared library. See
`bindings/lua/README.md`.

`OPENTLV_BUILD_LUA=ON` forces `OPENTLV_BUILD_SHARED_LIBS=OFF`, the same as
`OPENTLV_BUILD_WASM` and `OPENTLV_BUILD_PYTHON`: the module links the OpenTLV
C core statically, so `require("opentlv")` carries no separate shared `tlv`
library to locate at load time.

## Versioning

The rockspec's own version (`bindings/lua/opentlv-scm-1.rockspec`) is
independent of the OpenTLV C library's version. `opentlv.version()` (and the
equivalent `opentlv._VERSION` field) calls `tlv_version_string()` and reports
the version of the *linked C library*, not the rockspec's own version,
mirroring the distinction `opentlv.__version__` makes in
[Python bindings](python.md#versioning).

## Continuous integration

The [Lua Bindings
workflow](https://github.com/marekcingel/OpenTLV/blob/main/.github/workflows/lua.yml)
runs on every push and pull request to `main`: it builds the module with
`luarocks make` and runs `busted tests` and every script under `examples/`,
across Lua 5.1, 5.3 and 5.4, on Linux, and additionally on Windows and macOS
for release tags.
