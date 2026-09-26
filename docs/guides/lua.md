# Using OpenTLV from Lua

The `opentlv` module is an experimental Lua binding for OpenTLV. It binds a
Reader, tag/length/value `Entry` tables and preorder tree traversal; there is
no Writer, Document or Schema binding yet (see [Lua
bindings](../development/lua.md)).

## Setup

```sh
cmake -S . -B build-lua -DOPENTLV_BUILD_LUA=ON -DCMAKE_BUILD_TYPE=Release \
    -DOPENTLV_BUILD_CXX=OFF -DOPENTLV_BUILD_CLI=OFF -DOPENTLV_BUILD_TESTS=OFF \
    -DOPENTLV_BUILD_EXAMPLES=OFF
cmake --build build-lua --target opentlv_lua
```

This requires CMake 3.16 or newer, a C99 compiler, and Lua 5.1 through 5.4 or
LuaJIT headers and library; see [Build](../development/lua.md#build) for the
`luarocks make` alternative and a Windows-specific linking note.

```lua
local opentlv = require("opentlv")

print(opentlv.version())
```

Runnable version:
[quick_start.lua](https://github.com/marekcingel/OpenTLV/blob/main/bindings/lua/examples/quick_start.lua)
(`lua examples/quick_start.lua` from `bindings/lua`).

## Reading

`opentlv.reader(data, format)` returns a Reader over `data`, a Lua string.
Using the reader directly as a generic-for iterator calls it as its own
iterator function each time, so `for entry in reader do ... end` reads
sequentially with no explicit `next()`/`at_end()` loop:

```lua
local opentlv = require("opentlv")

local data = string.char(0x01, 0x02, 0xAA, 0xBB, 0x02, 0x00)
for entry in opentlv.reader(data) do
    print(entry.tag, entry.length, entry.value)
end
```

Each `entry` is a plain table with `tag`, `length`, `value` (all copied out
of `data`, since Lua strings cannot borrow foreign memory the way a C, C++,
Rust or Python view can) and `offset`, the absolute position of the entry's
tag within `data`. `format` defaults to `opentlv.formats.default`; pass
`opentlv.formats.ber`, `.cer`, `.der`, `.bluetooth_ltv`, or
`opentlv.formats.fixed(tag_size, length_size, byte_order)` (`byte_order` is
`"big"` or `"little"`, equivalent to the C `tlv_fixed_config_t`) for another
wire format. Constructed entries are not expanded automatically; construct a
new reader over `entry.value` to descend, as in the runnable example below.

The explicit method form, `reader:next()` (`nil` at the end) and
`reader:at_end()`, is equivalent and reads the same way; `reader:position()`
and `reader:format()` report the reader's current byte offset and the
format it was constructed with.

Runnable version, parsing a nested BER document and handling truncated
input:
[parse.lua](https://github.com/marekcingel/OpenTLV/blob/main/bindings/lua/examples/parse.lua)
(`lua examples/parse.lua`).

## Tree traversal

`opentlv.walk_tree(data, format, callback, opts)` visits every element of
`data` in preorder, calling `callback(entry, depth)` for each; `entry` has an
additional `constructed` boolean field. Returning `false` from `callback`
stops the walk early:

```lua
opentlv.walk_tree(data, opentlv.formats.ber, function(entry, depth)
    print(string.rep("  ", depth) .. entry.tag)
end)
```

`opts` is an optional table with integer `max_depth` (default 64, the
library's `TLV_WALK_MAX_DEPTH`) and `max_elements` (default 65536); pass an
explicit, tighter `max_elements` when walking untrusted input, since the C
`tlv_walk_tree()` this wraps requires a real bound. `callback` may be omitted
to validate structure and limits only. For `opentlv.formats.der`, traversal
always uses the stricter `tlv_der_walk()` with the library's default DER
limits instead, and `opts` is ignored.

## Error handling

Every reading or traversal failure raises a table (via Lua's `error()`) with
a `code` (the raw `tlv_result_t` value, also available named under
`opentlv.errors`, for example `opentlv.errors.BUFFER_TOO_SHORT`) and a
`message` (the C `tlv_strerror()` text); `tostring()` on it formats both
together. When the C API reports structured diagnostic detail for the
failure, `offset`, `expected`, `actual`, `operation` and `tag` carry it;
fields the failure does not report are absent, so check with `err.offset`
rather than assuming every field is present.

```lua
local ok, err = pcall(function()
    for _ in opentlv.reader(truncated, opentlv.formats.ber) do end
end)
if not ok then
    print(string.format("%s at offset %s (%s)", tostring(err), err.offset, err.operation))
end
```

A callback error inside `opentlv.walk_tree` (a genuine Lua error your
`callback` raises) propagates out of `opentlv.walk_tree` unchanged, so
`pcall` catches whatever your callback raised, not a wrapped copy.
