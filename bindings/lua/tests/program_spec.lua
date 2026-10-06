-- SPDX-License-Identifier: MIT
-- Copyright (c) 2026 Marek Cingel
local tlv = require("opentlv")
local b = string.char
local f = tlv.formats.ber or tlv.formats.fixed(1, 1, "big")
local function fails(run, code)
    local ok, err = pcall(run)
    assert(not ok, "expected failure")
    if code then assert(type(err) == "table" and err.code == code, tostring(err)) end
    return err
end
local options = {variables = {min = "integer"}, optimize = true}
local calls = {}
local providers = {num = {id = 101, decode = function(value, metadata)
    calls[#calls + 1] = metadata
    return string.byte(value) * 10
end}}
local custom = tlv.query_program("num(//5A)", f, {providers = providers})
providers.num = nil
collectgarbage("collect")
local ce = custom:execution()
ce:set_input(b(0x5a, 1, 3))
ce:visit(function() end)
assert(ce:result() == 30 and calls[#calls].offset == 0)
local loaded_custom = tlv.query_program_load(custom:image(), f, {providers = {
    num = {id = 101, decode = function(value) return string.byte(value) * 10 end}
}})
local le = loaded_custom:execution()
le:set_input(b(0x5a, 1, 4))
le:visit(function() end)
assert(le:result() == 40)
fails(function() tlv.query_program_load(custom:image(), f) end, 10)
local tp = tlv.query_program("text(//5A)", f, {providers = {
    text = {id = 102, max_result_bytes = 3, decode = function() return "a\0b" end}
}})
local te = tp:execution()
te:set_input(b(0x5a, 0)); te:visit(function() end)
assert(te:result() == "a\0b")
local failing = tlv.query_program("num(//5A)", f, {providers = {
    num = {id = 103, decode = function() error("provider failed") end}
}}):execution()
failing:set_input(b(0x5a, 0))
assert(tostring(fails(function() failing:visit(function() end) end)):find("provider failed", 1, true))
failing:reset()
local reentry
reentry = tlv.query_program("num(//5A)", f, {providers = {
    num = {id = 104, decode = function() reentry:reset(); return 1 end}
}}):execution()
reentry:set_input(b(0x5a, 0))
fails(function() reentry:visit(function() end) end, 10)
reentry:reset()
local feed_program = tlv.query_program("//5A", f)
local feeding = feed_program:execution({retained = false})
local selected = feeding:feed({kind = "element", tag = b(0x5a), value = b(1), offset = 7})
assert(selected.offset == 7)
fails(function() feeding:set_input(b(0x5a, 0)) end, 10)
feeding:finish()
assert(feeding:info().full_validation == 1)
feeding:reset()
fails(function() feeding:feed({kind = "end"}) end, 10)
assert(feeding:info().invalid == 1)
feeding:reset(); feeding:close(); feeding:close()
local retained_feed = feed_program:execution()
assert(retained_feed:feed({kind = "element", tag = b(0x5a), offset = 7}) == nil)
retained_feed:finish()
assert(retained_feed:next().offset == 7 and retained_feed:next() == nil)
retained_feed:close()
local p = tlv.query_program("count(//5A[@len >= $min])", f, options)
assert(p:info().variable_slots == 1 and p:variables().min == 2)
assert(#p:format() > 0 and #p:explain() > 0)
local loaded = tlv.query_program_load(p:image(), f, options)
fails(function() tlv.query_program_load(p:image():sub(1,-2), f, options) end)
local q = loaded:execution()
q:bind("min", "integer", 2)
q:set_input(b(0x5a,1,9,0x5a,2,8,7))
q:visit(function() error("scalar emitted node") end)
assert(q:result() == 1)
q:close()
fails(function() q:result() end, tlv.errors.INVALID_ARG)

local streaming = tlv.query_program("//5A", f):execution({retained = false})
streaming:set_input(b(0x5a,1,9),0,false)
local first = streaming:next()
assert(first.value == b(9) and first.offset == 0)
fails(function() streaming:next() end, tlv.errors.NEED_MORE_DATA)
collectgarbage("collect")
streaming:set_input(b(0x5a,1,9,0x5a,1,8),0,true)
streaming:visit(function(match)
    assert(match.offset == 3)
    fails(function() streaming:reset() end, tlv.errors.INVALID_ARG)
    fails(function() streaming:close() end, tlv.errors.INVALID_ARG)
    return false
end)
assert(streaming:next() == nil)
streaming:reset()
assert(first.value == b(9))
streaming:set_input(b(0x5a,0))
assert(fails(function() streaming:visit(function() error("callback failure") end) end):match("callback failure"))
fails(function() streaming:next() end, tlv.errors.INVALID_ARG)
streaming:reset()
streaming:set_input(b(0x5a,0,0x5a))
assert(streaming:exists(true))
assert(streaming:info().full_validation == 0)
streaming:reset()
streaming:set_input(b(0x5a,0,0x5a))
fails(function() streaming:exists(false) end, tlv.errors.BUFFER_TOO_SHORT)

local names = tlv.query_program("count(//fixture:leaf)",f,{names={["fixture:leaf"]=b(0x5a)}}):execution()
names:set_input(b(0x5a,0));names:visit(function() end);assert(names:result()==1)
local diagnostic = fails(function() tlv.query_program("//5A[", f) end)
assert(type(diagnostic.query) == "table" and type(diagnostic.query.begin)=="number")
if tlv.document and tlv.formats.ber then
    local edit_doc = tlv.document(b(0x70,6,0x5a,1,1,0x5a,1,2,0x5a,1,3),f)
    local old_node = edit_doc:first()
    local editing = tlv.query_program("//5A",f):execution()
    editing:evaluate_document(edit_doc)
    local short = fails(function() editing:edit_document("replace",nil,b(9),2) end,1)
    assert(short.applied == 0)
    assert(editing:edit_document("replace",nil,b(9),3) == 3)
    fails(function() old_node:tag() end)
    fails(function() editing:next() end,10)
    editing:reset(); editing:evaluate_document(edit_doc)
    assert(editing:edit_document("insert_after",b(0x5b),b(4),3) == 3)
    local ancestors = tlv.query_program("//70 | //5A",f):execution()
    ancestors:evaluate_document(edit_doc)
    assert(ancestors:edit_document("remove") == 2)
    assert(edit_doc:serialize() == b(0x5b,1,4))
    local doc = tlv.document(b(0x70,6,0x5a,1,1,0x5a,1,2),f)
    local selected = tlv.query_program("//5A/preceding-sibling::*",f):execution()
    selected:evaluate_document(doc)
    local node = selected:next()
    assert(node:value()==b(1) and node:identity()>0)
    node:set(b(7))
    fails(function() selected:next() end,tlv.errors.INVALID_ARG)
    selected:reset();selected:evaluate_document(doc)
    assert(selected:next():value()==b(7))
    selected:close()
    local scalar = tlv.query_program("value((//5A)[1])",f):execution()
    scalar:evaluate_document(doc)
    assert(scalar:result()==b(7))
end
if tlv.formats.ber then
    local good, bad = b(0x70,3,0x5a,1,1), b(0x70,3,0x5a,1,2)
    local rules = {{context = tlv.query_program("//5A", f),
                    assertion = tlv.query_program("num(.) = 1", f), name = "one"}}
    tlv.query_schema_validate(rules, good)
    tlv.query_schema_validate({{context = tlv.query_program("//5B", f),
        assertion = tlv.query_program("1 = 0", f)}}, bad)
    local failed = fails(function() tlv.query_schema_validate(rules, bad) end, tlv.errors.SCHEMA)
    assert(failed.rule == 0 and failed.schema.kind == "assertion")
    assert(failed.schema.tag == b(0x5a) and failed.schema.path[1] == b(0x70))
    assert(failed.schema.offset == 2 and failed.schema.field == "one")
    assert(failed.schema.expected == "contextual Query assertion true")
    local bounded = fails(function() tlv.query_schema_validate(rules, good, {max_contexts=0}) end, tlv.errors.LIMIT)
    assert(bounded.query.limit == "schema-contexts")
    fails(function() tlv.query_schema_validate(rules, good, {max_work=1}) end, tlv.errors.LIMIT)
    fails(function() tlv.query_schema_validate({{context=rules[1].context,
        assertion=tlv.query_program("count(.)", f)}}, good) end, tlv.errors.INVALID_ARG)
    if tlv.document then
        local empty_root = tlv.query_program("value(//70)", f):execution({max_depth=0})
        empty_root:evaluate_document(tlv.document(b(0x70,0), f))
        assert(empty_root:result() == "")
        empty_root:close()
        local reverse = {{context=tlv.query_program("//5A[2]", f),
                          assertion=tlv.query_program("exists(preceding::5A)", f)}}
        local siblings = b(0x70,6,0x5a,1,1,0x5a,1,2)
        fails(function() tlv.query_schema_validate(reverse, siblings) end, tlv.errors.UNSUPPORTED_TYPE)
        tlv.query_schema_validate(reverse, tlv.document(siblings, f))
        local doc = tlv.document(good, f)
        tlv.query_schema_validate(rules, doc)
        local broken = tlv.document(bad, f)
        local from_document = fails(function() tlv.query_schema_validate(rules, broken) end, tlv.errors.SCHEMA)
        broken:close()
        assert(from_document.schema.offset == nil and from_document.schema.path[1] == b(0x70))
        local root = doc:first()
        local provider_rules
        local calls = 0
        local predicate = tlv.query_program("num(.) = 1", f, {providers={num={id=201,
            decode=function(value, metadata)
                calls = calls + 1
                assert(metadata.tag == b(0x5a))
                fails(function() doc:close() end)
                fails(function() root:erase() end)
                fails(function() tlv.query_schema_validate(provider_rules, doc) end, tlv.errors.INVALID_ARG)
                provider_rules[1] = nil
                collectgarbage("collect")
                return string.byte(value)
            end}}})
        provider_rules = {{context=tlv.query_program("//5A", f), assertion=predicate}}
        predicate = nil
        tlv.query_schema_validate(provider_rules, doc)
        assert(calls == 1 and doc:serialize() == good)
        local marker = {}
        local throwing = {{context=rules[1].context, assertion=tlv.query_program("num(.) = 1", f,
            {providers={num={id=202, decode=function() error(marker) end}}})}}
        assert(fails(function() tlv.query_schema_validate(throwing, doc) end) == marker)
        doc:close()
        if debug and debug.sethook then
            local guarded = tlv.document(good, f)
            local finalized, blocked, returned = false, false, false
            local gc_predicate = tlv.query_program("num(.) = 1", f, {providers={num={id=203,
                decode=function()
                    collectgarbage("stop")
                    local function finalize()
                        finalized = true
                        local ok, err = pcall(guarded.close, guarded)
                        blocked = not ok and type(err) == "table" and err.code == tlv.errors.INVALID_ARG
                    end
                    local pending
                    if newproxy then
                        pending = newproxy(true)
                        getmetatable(pending).__gc = finalize
                    else
                        pending = setmetatable({}, {__gc=finalize})
                    end
                    pending = nil
                    -- The next C call is protected diagnostic projection. Collect
                    -- before its first allocation to exercise a closing finalizer.
                    debug.sethook(function()
                        if returned then
                            debug.sethook()
                            collectgarbage("collect")
                        end
                    end, "c")
                    returned = true
                    return 0
                end}}})
            local ok, diagnostic = pcall(tlv.query_schema_validate,
                {{context=rules[1].context, assertion=gc_predicate}}, guarded)
            debug.sethook()
            collectgarbage("restart")
            assert(not ok and diagnostic.code == tlv.errors.SCHEMA)
            assert(finalized and blocked, "Document guard ended before diagnostic projection")
            assert(diagnostic.schema.path[1] == b(0x70))
            guarded:close()
        end
    end
    rules, bad = nil, nil
    collectgarbage("collect")
    assert(failed.schema.tag == b(0x5a) and failed.schema.field == "one")
end
print("Lua compiled Query lifetime, continuation, callbacks, Document and Schema tests passed")
