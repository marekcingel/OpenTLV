# opentlv (Lua, experimental)

Lua bindings to the [OpenTLV](https://github.com/marekcingel/OpenTLV) C API:
two pieces, `opentlv-native` (`src/`, built directly against the Lua C API,
binding `Reader`, `Entry`, `Tag` and preorder tree traversal) and `opentlv`
(`lua/opentlv/init.lua`, a one-line pure-Lua entry point on top of it) — the
same native/pure split as the Python `opentlv-native`/`opentlv` and Rust
`opentlv-native`/`opentlv` packages. Targets Lua 5.1 through 5.4 and LuaJIT.
See [Lua bindings](https://marekcingel.github.io/OpenTLV/development/lua/)
and [using OpenTLV from Lua](https://marekcingel.github.io/OpenTLV/guides/lua/).

```lua
local opentlv = require("opentlv")

local data = string.char(0x01, 0x02, 0xAA, 0xBB)
for entry in opentlv.reader(data) do
    print(entry.tag, entry.length, entry.value)
end
```

## Build

Requirements: CMake 3.16 or newer, a C99 compiler, and Lua 5.1, 5.2, 5.3, 5.4
or LuaJIT headers and library (`liblua`, `liblua5.x` or `libluajit`,
whichever CMake's `FindLua` module locates; set `LUA_INCLUDE_DIR` and
`LUA_LIBRARIES` directly if it does not find yours).

```sh
cmake -S . -B build-lua -DOPENTLV_BUILD_LUA=ON -DCMAKE_BUILD_TYPE=Release \
    -DOPENTLV_BUILD_CXX=OFF -DOPENTLV_BUILD_CLI=OFF -DOPENTLV_BUILD_TESTS=OFF \
    -DOPENTLV_BUILD_EXAMPLES=OFF
cmake --build build-lua --target opentlv_lua
```

This produces `opentlv_native.so` (`opentlv_native.dll` on Windows) under
`build-lua/bindings/lua/`; put it on `LUA_CPATH`, and put this directory's
`lua/` on `LUA_PATH` (or copy both next to your script), so
`require("opentlv")` finds `lua/opentlv/init.lua`, which in turn finds the
compiled module.

**On Windows**, link against the same Lua you run this module with, and make
sure it is a *shared* `lua5x.dll`, not a static `liblua*.a`/`.lib`: a Lua
interpreter statically linked against Lua and a module (this one, or any
other) separately statically linked against Lua end up with two independent
copies of the Lua runtime sharing one `lua_State`, which corrupts memory
under the module's calls back into Lua (the ones in `walk.c`) and crashes.
Point `LUA_INCLUDE_DIR`/`LUA_LIBRARY` at your interpreter's own shared
`lua5x.dll`'s headers and import library to avoid this; it is generally not
an issue on Linux and macOS, where system Lua packages already ship a shared
library for this reason.

Alternatively, from this directory:

```sh
luarocks make
```

which installs both `opentlv_native` and `lua/opentlv/init.lua` in one step.

## Test

The test suite uses [busted](https://lunarmodules.github.io/busted/):

```sh
luarocks install busted
LUA_PATH="lua/?.lua;lua/?/init.lua;;" LUA_CPATH="build-lua/bindings/lua/?.so;;" busted tests
```
