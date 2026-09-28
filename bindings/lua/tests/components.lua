-- Standalone smoke test: expected availability comes from the CMake build.
local opentlv = require("opentlv")
local names = { "ber", "cer", "der", "bluetooth_ltv", "lldp" }
local wires = {
    string.char(4, 1, 42), string.char(4, 1, 42), string.char(4, 1, 42),
    string.char(2, 4, 42), string.char(8, 1, 42),
}
for i, name in ipairs(names) do
    local format = opentlv.formats[name]
    assert((format ~= nil) == (arg[i] == "1"), name .. " availability mismatch")
    if format then
        assert(tostring(format) == "opentlv.Format<" .. name .. ">")
        local count = 0
        for element in opentlv.reader(wires[i], format) do
            assert(element.tag == string.char(4))
            assert(element.value == string.char(42))
            count = count + 1
        end
        assert(count == 1)
        local visited = opentlv.walk_tree(wires[i], format, function() end)
        assert(visited == 1)
    end
end

local fixed = opentlv.formats.fixed(1, 1, "big")
local count = 0
for element in opentlv.reader(wires[1], fixed) do
    assert(element.value == string.char(42))
    count = count + 1
end
assert(count == 1)
local ok, result = pcall(opentlv.reader, wires[1])
assert(ok == (arg[1] == "1"))
if not ok then
    assert(tostring(result):find("format is required when BER is disabled", 1, true))
end
