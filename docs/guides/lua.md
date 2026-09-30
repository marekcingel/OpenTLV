# Using OpenTLV from Lua

The `opentlv` module is an experimental Lua binding for OpenTLV. It binds a
Reader, Writer, Tree Writer, tag/length/value `Element` tables and preorder tree
traversal; there is no Document or Schema binding yet (see [Lua
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
iterator function each time, so `for element in reader do ... end` reads
sequentially with no explicit `next()`/`at_end()` loop:

```lua
local opentlv = require("opentlv")

local data = string.char(0x01, 0x02, 0xAA, 0xBB, 0x02, 0x00)
for element in opentlv.reader(data) do
    print(element.tag, element.length, element.value)
end
```

Each `element` is a plain table with `tag`, `raw_length`, `value` (all copied out
of `data`, since Lua strings cannot borrow foreign memory the way a C, C++,
Rust or Python view can) plus numeric `length` (the value size) and `offset`, the absolute position of the element's
tag within `data`. `format` defaults to `opentlv.formats.ber`; pass
`opentlv.formats.ber`, `.cer`, `.der`, `.bluetooth_ltv`, or
`opentlv.formats.fixed(tag_size, length_size, byte_order)` (`byte_order` is
`"big"` or `"little"`, equivalent to the C `tlv_fixed_format_t`) for another
wire format. Constructed elements are not expanded automatically; construct a
new reader over `element.value` to descend, as in the runnable example below.

The explicit method form, `reader:next()` (`nil` at the end) and
`reader:at_end()`, is equivalent and reads the same way; `reader:position()`
and `reader:format()` report the reader's current byte offset and the
format it was constructed with.

Runnable version, parsing a nested BER document and handling truncated
input:
[parse.lua](https://github.com/marekcingel/OpenTLV/blob/main/bindings/lua/examples/parse.lua)
(`lua examples/parse.lua`).

## Tree traversal

`opentlv.visit_tree(data, format, callback, opts)` visits every element of
`data` in preorder, calling `callback(element, depth)` for each; `element` has an
additional `constructed` boolean field. Returning `false` from `callback`
stops the traversal early:

```lua
opentlv.visit_tree(data, opentlv.formats.ber, function(element, depth)
    print(string.rep("  ", depth) .. element.tag)
end)
```

`opts` is an optional table with integer `max_depth` (default 64, the
library's `TLV_TREE_DEFAULT_DEPTH`) and `max_elements` (default 65536); pass an
explicit, tighter `max_elements` when traversing untrusted input, since the C
`tlv_tree_reader_visit()` this wraps requires a real bound. `callback` may be omitted
to validate structure and limits only. For `opentlv.formats.der`, traversal
always uses the stricter `tlv_der_visit()` with the library's default DER
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

A callback error inside `opentlv.visit_tree` (a genuine Lua error your
`callback` raises) propagates out of `opentlv.visit_tree` unchanged, so
`pcall` catches whatever your callback raised, not a wrapped copy.

## Writing

`opentlv.writer(format, options)` creates a sequential Writer over a buffer
owned by the Lua binding. `format` defaults to BER when enabled; otherwise
it is required. `options.capacity` defaults to 1024 bytes, never grows, and
may be zero. All encoding is performed by the OpenTLV C Writer and Format.

```lua
local tlv = require("opentlv")
local writer = tlv.writer(tlv.formats.ber, { capacity = 1024 })
writer:write(string.char(0x5F, 0x2A), string.char(0x09, 0x78))
writer:write(string.char(0x9F, 0x02), string.char(0, 0, 0, 0, 1, 0))
local encoded = writer:bytes()
```

- `write(tag, value)` appends one element. Both arguments are binary strings,
  including embedded zero bytes; numbers and arbitrary userdata are rejected.
  `nil` Tag represents an absent identifier when the Format permits it.
  An empty Tag string represents an explicit empty identifier.
- `write_element(element)` accepts a Reader-style table with `tag` and `value`.
  Length is derived from `value`; metadata such as `length` and `offset` does
  not override the content.
- `bytes()` returns an independent immutable string containing written bytes.
- `size()` and `remaining()` report written bytes and unused capacity.
- `format()` returns the retained Format object.

Tag strings represent raw byte identity: `"5F2A"` is four ASCII bytes, not
`string.char(0x5F, 0x2A)`. Input strings are borrowed only during a write call.
The binding keeps the Format alive and releases its output buffer at garbage
collection. A failed sequential write does not advance the cursor; as in C,
encoder callback failures may modify unused destination bytes.

### Nested writing

`opentlv.tree_writer(format, options)` wraps the C Tree Writer. It supports
`write`, `write_element`, `format` and `size`, plus `begin(tag)`,
`end_element()` and `finish()`. `finish()` and `bytes()` both check that all
parents are closed and return an independent output string; neither closes
parents implicitly. `size()` reports only the finalized root prefix.

```lua
local tlv = require("opentlv")
local writer = tlv.tree_writer(tlv.formats.ber, { capacity = 1024 })
writer:begin(string.char(0xE1))
writer:write(string.char(0x04), "hello")
writer:end_element()
local encoded = writer:finish()
```

The selected C Format determines whether constructed encoding is supported.
Tree options are `capacity` (1024), `scratch_capacity` and `tag_capacity`
(both default to `capacity`), `frame_capacity` and `max_depth` (both default
to the C `TLV_TREE_DEFAULT_DEPTH`), and `max_elements` (unbounded by default).
Options must be nonnegative native integers. Scratch must hold the largest
closed parent Value; each open parent uses one frame. Maximum item depth
counts roots as zero. Open Tags are copied by the C Tree Writer into bounded
Tag storage, so temporary Lua strings can be collected safely.

### Writer errors

Core failures raise the same structured error-table type as Reader. In addition
to `code` and `message`, diagnostic operations copy `offset`, `operation`,
`tag`, `length`, `required`, `available`, `expected` and `actual` when supplied
by the C core. `required` and `available` describe the failing destination or
workspace, not necessarily the complete final document. Tree offsets refer
to the current provisional buffer. A failed `end_element()` preserves the
open parent and its children, following the C Tree Writer contract.

```lua
local ok, err = pcall(function()
    local writer = require("opentlv").writer(nil, { capacity = 0 })
    writer:write(string.char(0x04), "value")
end)
if not ok then
    print(err.code, err.message, err.required, err.available)
end
```
