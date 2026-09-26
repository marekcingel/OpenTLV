local opentlv = require("opentlv")

-- An FCI Template (6F) holding a DF Name (84) and an FCI Proprietary
-- Template (A5) holding an Application Label (50).
local BER_DATA = string.char(0x6F, 0x0A, 0x84, 0x03, 0x41, 0x42, 0x43, 0xA5, 0x03, 0x50, 0x01, 0x01)

describe("opentlv.walk_tree", function()
    it("visits every element in preorder with depth, offset and constructed", function()
        local seen = {}
        local visited, stopped = opentlv.walk_tree(BER_DATA, opentlv.formats.ber,
            function(entry, depth)
                seen[#seen + 1] = {tag = entry.tag, depth = depth, offset = entry.offset,
                                   constructed = entry.constructed}
            end)
        assert(visited == 4)
        assert(stopped == false)
        assert(#seen == 4)

        assert(seen[1].tag == string.char(0x6F) and seen[1].depth == 0 and seen[1].offset == 0)
        assert(seen[1].constructed == true)
        assert(seen[2].tag == string.char(0x84) and seen[2].depth == 1)
        assert(seen[2].constructed == false)
        assert(seen[3].tag == string.char(0xA5) and seen[3].depth == 1)
        assert(seen[3].constructed == true)
        assert(seen[4].tag == string.char(0x50) and seen[4].depth == 2)
        assert(seen[4].constructed == false)
    end)

    it("stops early when the callback returns false", function()
        local visited, stopped = opentlv.walk_tree(BER_DATA, opentlv.formats.ber,
            function(entry, depth)
                return false
            end)
        assert(visited == 1)
        assert(stopped == true)
    end)

    it("continues when the callback returns nothing or true", function()
        local visited, stopped = opentlv.walk_tree(BER_DATA, opentlv.formats.ber, function() end)
        assert(visited == 4)
        assert(stopped == false)
    end)

    it("propagates a Lua error raised by the callback", function()
        local ok, err = pcall(opentlv.walk_tree, BER_DATA, opentlv.formats.ber, function()
            error("boom")
        end)
        assert(not ok)
        assert(tostring(err):find("boom", 1, true) ~= nil)
    end)

    it("raises a structured error when max_elements is exceeded", function()
        local ok, err = pcall(opentlv.walk_tree, BER_DATA, opentlv.formats.ber, function() end,
            {max_elements = 1})
        assert(not ok)
        assert(err.code == opentlv.errors.LIMIT)
    end)

    it("raises a structured error when max_depth is exceeded", function()
        local ok, err = pcall(opentlv.walk_tree, BER_DATA, opentlv.formats.ber, function() end,
            {max_depth = 0})
        assert(not ok)
        assert(err.code == opentlv.errors.LIMIT)
    end)

    it("validates structure only when the callback is omitted", function()
        local visited, stopped = opentlv.walk_tree(BER_DATA, opentlv.formats.ber, nil)
        assert(visited == 0)
        assert(stopped == false)
    end)

    it("uses tlv_der_walk() and its default limits for opentlv.formats.der", function()
        local visited = opentlv.walk_tree(BER_DATA, opentlv.formats.der, function() end)
        assert(visited == 4)
    end)
end)
