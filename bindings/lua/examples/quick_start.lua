-- SPDX-License-Identifier: MIT
-- Copyright (c) 2026 Marek Cingel

--[[
One element encoded with the configurable fixed-width format (one tag byte,
one length byte) using a Writer, then decoded with a Reader.
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
local format = opentlv.formats.fixed(1, 1, "big")
local writer = opentlv.writer(format, { capacity = 64 })
writer:write(string.char(0x01), string.char(0xAA, 0xBB, 0xCC))
local encoded = writer:bytes()
assert(encoded == string.char(0x01, 0x03, 0xAA, 0xBB, 0xCC))
print(string.format("reading %d bytes: %s", #encoded, hex(encoded)))

local reader = opentlv.reader(encoded, format)
local element = reader:next()
assert(element ~= nil)
assert(reader:next() == nil)

assert(element.tag == string.char(0x01))
assert(element.value == string.char(0xAA, 0xBB, 0xCC))
print(string.format("read tag %s value %s", hex(element.tag), hex(element.value)))
print("opentlv version: " .. opentlv.version())
