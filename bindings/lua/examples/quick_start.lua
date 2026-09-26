--[[
The simplest possible read: one element encoded with the configurable
fixed-width format (one tag byte, one length byte), decoded with a Reader.
This binding covers Reader, Entry and Tag only (see issue #298); there is no
Lua Writer yet, so unlike the C, C++, Rust and Python quick_start examples,
the encoded bytes below are written out by hand instead of with a Writer.
See parse.lua for a nested BER document and error handling.

Run with `lua examples/quick_start.lua` from `bindings/lua`, after building
the native module (see ../README.md or docs/development/lua.md).
]]

local opentlv = require("opentlv")

local function hex(bytes)
    local parts = {}
    for i = 1, #bytes do
        parts[i] = string.format("%02X", string.byte(bytes, i))
    end
    return table.concat(parts, " ")
end

-- tag 0x01, length 0x03, value 0xAA 0xBB 0xCC.
local encoded = string.char(0x01, 0x03, 0xAA, 0xBB, 0xCC)
print(string.format("reading %d bytes: %s", #encoded, hex(encoded)))

local format = opentlv.formats.fixed(1, 1, "big")
local reader = opentlv.reader(encoded, format)
local entry = reader:next()
assert(entry ~= nil)
assert(reader:next() == nil)

assert(entry.tag == string.char(0x01))
assert(entry.value == string.char(0xAA, 0xBB, 0xCC))
print(string.format("read tag %s value %s", hex(entry.tag), hex(entry.value)))
print("opentlv version: " .. opentlv.version())
