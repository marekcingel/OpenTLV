local tlv = require("opentlv")
local describe = describe or function(_, run) run() end
local it = it or function(_, run) run() end
local b = string.char
local fixed = tlv.formats.fixed(1, 1, "big")
local data = b(1, 1, 65, 2, 0, 1, 1, 66)
local function failure(run, code)
    local ok, err = pcall(run)
    assert(not ok, "expected failure")
    if code then assert(type(err) == "table" and err.code == code, tostring(err)) end
    return err
end

describe("Lua Query", function()
    it("compiles native paths and returns copied matches in source order", function()
        local q = tlv.query("01")
        assert(q:steps()[1] == b(1))
        assert(tlv.query("9f02/00"):steps()[2] == b(0))
        local matches = q:evaluate(data, fixed)
        assert(#matches == 2 and matches[1].value == "A" and matches[2].value == "B")
        assert(matches[1].offset == 0 and matches[2].offset == 5)
        assert(matches[1].depth == 0 and not matches[1].constructed)
        assert(#q:evaluate("", fixed) == 0)
        assert(#tlv.query("03"):evaluate(data, fixed) == 0)
        assert(#tlv.query(q):evaluate(data, fixed) == 2)
    end)
    it("reports query syntax and resource diagnostics without accepting NUL suffixes", function()
        for _, text in ipairs({"", "1", "/01", "01/", "01//02", "xx", "01 02"}) do
            local err = failure(function() tlv.query(text) end, tlv.errors.INVALID_ARG)
            assert(type(err.offset) == "number")
        end
        assert(failure(function() tlv.query("01\0/02") end, tlv.errors.INVALID_ARG).offset == 2)
        failure(function() tlv.query(string.rep("01/", 65) .. "01") end, tlv.errors.LIMIT)
        failure(function() tlv.query(string.rep("01", 513)) end, tlv.errors.LIMIT)
        failure(function() tlv.query("01"):evaluate(data, fixed, {max_elements = 1}) end,
                tlv.errors.LIMIT)
        for _, value in ipairs({-1, 0.5, math.huge, "2"}) do
            failure(function() tlv.query("01"):evaluate(data, fixed, {max_depth = value}) end)
        end
        local err = failure(function() tlv.query("01"):evaluate(b(1, 2, 0), fixed) end,
                            tlv.errors.BUFFER_TOO_SHORT)
        assert(type(err.offset) == "number")
    end)
end)

if arg and arg[1] == "--allocator" then
    local inject = require("opentlv_test_allocator")
    for budget = 0, 50 do
        inject(function() tlv.query("01"):evaluate(data, fixed) end, budget)
        collectgarbage("collect")
    end
end

if not tlv.document then
    assert(tlv.query("01"):evaluate(data, fixed)[1].value == "A")
    return
end

describe("Lua Document", function()
    it("creates, parses, finds, changes and serializes native documents", function()
        local doc = tlv.document(data, fixed)
        assert(type(doc) == "userdata" and doc:count() == 3)
        assert(doc:serialize() == data and doc:find("03") == nil)
        local a = doc:find(tlv.query("01"))
        assert(type(a) == "userdata" and a:tag() == b(1) and a:value() == "A")
        assert(a:parent() == nil and a:first_child() == nil and not a:is_constructed())
        assert(a:next_same_tag():value() == "B")
        assert(#doc:query("01") == 2 and #doc:query("03") == 0)
        assert(doc:set("01", "C") and a:value() == "C")
        assert(not doc:set("03", "X") and not doc:erase("03"))
        local inserted = doc:insert(b(3), "X", nil, a)
        assert(doc:first():tag() == b(3) and a:value() == "C")
        assert(inserted:serialize() == b(3, 1) .. "X")
        assert(doc:erase(inserted))
        failure(function() inserted:value() end)
        local alias = doc:find("01")
        a:erase()
        failure(function() alias:tag() end)
        assert(doc:find("01"):value() == "B" and doc:count() == 2)
        local empty = tlv.document(nil, fixed)
        assert(empty:count() == 0 and empty:serialize() == "" and empty:first() == nil)
        empty:insert(b(0), "")
        assert(empty:find("00"):value() == "")
        assert(empty:serialize(tlv.formats.fixed(1, 2, "big")) == b(0, 0, 0))
    end)
    it("rejects foreign nodes and preserves handles and bytes after failed edits", function()
        local doc = tlv.document(data, fixed)
        local other = tlv.document(data, fixed):first()
        failure(function() doc:set(other, "X") end)
        failure(function() doc:erase(other) end)
        failure(function() doc:insert(b(1), "X", other) end)
        failure(function() doc:insert(b(1), "X", nil, other) end)
        failure(function() doc:insert(b(1), "X", "99") end)
        failure(function() doc:insert(b(1), "X", doc:first()) end, tlv.errors.INVALID_ARG)
        assert(doc:serialize() == data and other:value() == "A")
        local limited = tlv.document(data, fixed, {max_elements = 3})
        local first = limited:first()
        failure(function() limited:insert(b(3), "") end, tlv.errors.LIMIT)
        assert(first:value() == "A" and limited:serialize() == data)
        failure(function() tlv.document(data, fixed, {max_elements = 1}) end, tlv.errors.LIMIT)
        assert(type(failure(function() tlv.document(b(1, 2), fixed) end,
                            tlv.errors.BUFFER_TOO_SHORT).offset) == "number")
    end)
    it("keeps the native document and configured format alive through node handles", function()
        local weak = setmetatable({}, {__mode = "v"})
        local node
        do
            local format = tlv.formats.fixed(1, 1, "big")
            local doc = tlv.document(data, format)
            weak[1], weak[2] = doc, format
            node = doc:first()
        end
        collectgarbage("collect")
        assert(weak[1] and weak[2] and node:value() == "A")
        node = nil
        for _ = 1, 4 do collectgarbage("collect") end
        assert(weak[1] == nil and weak[2] == nil)
    end)
    if tlv.formats.ber then
        it("matches repeated paths and invalidates only removed descendants", function()
            local nested = b(0xE1, 0, 0xE1, 6, 1, 1, 65, 1, 1, 66, 2, 0)
            local doc = tlv.document(nested, tlv.formats.ber)
            local q = tlv.query("E1/01")
            assert(doc:find(q):value() == "A")
            local matches = doc:query(q)
            assert(#matches == 2 and matches[2]:value() == "B")
            local entries = q:evaluate(nested, tlv.formats.ber)
            assert(#entries == 2 and entries[1].depth == 1 and entries[1].offset == 4)
            failure(function() q:evaluate(nested, tlv.formats.ber, {max_depth = 0}) end,
                    tlv.errors.LIMIT)
            failure(function() tlv.document(nested, tlv.formats.ber, {max_depth = 0}) end,
                    tlv.errors.LIMIT)
            local parent = matches[1]:parent()
            local sibling = doc:find("02")
            assert(parent:is_constructed() and parent:value() == nil)
            failure(function() parent:set(b(1, 4, 0)) end, tlv.errors.BUFFER_TOO_SHORT)
            assert(matches[1]:value() == "A" and doc:serialize() == nested)
            assert(parent:set(b(1, 1, 67)))
            failure(function() matches[1]:value() end)
            failure(function() matches[2]:value() end)
            assert(parent:first_child():value() == "C" and sibling:value() == "")
            local child = parent:first_child()
            parent:erase()
            failure(function() child:serialize() end)
            assert(sibling:value() == "" and doc:count() == 2)
        end)
    end
end)

if arg and arg[1] == "--allocator" then
    local inject = require("opentlv_test_allocator")
    for budget = 0, 100 do
        inject(function()
            local doc = tlv.document(data, tlv.formats.fixed(1, 1, "big"))
            doc:query("01")
            doc:insert(b(3), "C")
            doc:serialize()
            tlv.query("01"):evaluate(data, fixed)
        end, budget)
        for _ = 1, 3 do collectgarbage("collect") end
    end
    assert(tlv.document(data, fixed):serialize() == data)
end
