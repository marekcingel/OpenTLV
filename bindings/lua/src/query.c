// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "query.h"
#include "common.h"
#include "error.h"
#include "format.h"

#include <string.h>
#include <limits.h>

#define QUERY_MT "opentlv.Query"

const tlv_query_t* opentlv_lua_check_query(lua_State* L, int arg, tlv_query_t* scratch) {
    if (lua_type(L, arg) == LUA_TUSERDATA)
        return (const tlv_query_t*)luaL_checkudata(L, arg, QUERY_MT);
    size_t       length;
    const char*  text = luaL_checklstring(L, arg, &length);
    size_t       offset = 0;
    tlv_result_t code = tlv_query_parse_n(text, length, scratch, &offset);
    if (code != TLV_OK) opentlv_lua_raise(L, code, 1, offset);
    return scratch;
}

size_t opentlv_lua_query_limit(lua_State* L, int arg, const char* name, size_t fallback) {
    if (lua_isnoneornil(L, arg)) return fallback;
    luaL_checktype(L, arg, LUA_TTABLE);
    lua_getfield(L, arg, name);
    if (lua_isnil(L, -1)) {
        lua_pop(L, 1);
        return fallback;
    }
    luaL_checktype(L, -1, LUA_TNUMBER);
#if LUA_VERSION_NUM >= 503
    if (lua_isinteger(L, -1)) {
        lua_Integer value = lua_tointeger(L, -1);
        if (value < 0 || (uintmax_t)value > SIZE_MAX)
            luaL_error(L, "%s must be a nonnegative native integer", name);
        lua_pop(L, 1);
        return (size_t)value;
    }
#endif
    lua_Number value = lua_tonumber(L, -1);
    if (!(value >= 0 && value < (lua_Number)SIZE_MAX))
        luaL_error(L, "%s must be a nonnegative native integer", name);
    size_t result = (size_t)value;
    if ((lua_Number)result != value) luaL_error(L, "%s must be an integer", name);
    lua_pop(L, 1);
    return result;
}

static int query_new(lua_State* L) {
    tlv_query_t        scratch;
    const tlv_query_t* query = opentlv_lua_check_query(L, 1, &scratch);
    tlv_query_t*       self = (tlv_query_t*)lua_newuserdata(L, sizeof(*self));
    *self = *query;
    luaL_getmetatable(L, QUERY_MT);
    lua_setmetatable(L, -2);
    return 1;
}

static int query_steps(lua_State* L) {
    const tlv_query_t* self = (const tlv_query_t*)luaL_checkudata(L, 1, QUERY_MT);
    lua_newtable(L);
    size_t count = tlv_query_count(self);
    for (size_t i = 0; i < count; ++i) {
        tlv_tag_t tag = tlv_query_step(self, i);
        lua_pushlstring(L, (const char*)tag.data, tag.size);
        lua_rawseti(L, -2, (int)i + 1);
    }
    return 1;
}

/* Pull between Lua allocations: no Lua error can unwind a native callback.
 * Frames are Lua-owned scratch, so even allocation failures release them. */
static int query_evaluate(lua_State* L) {
    const tlv_query_t* self = (const tlv_query_t*)luaL_checkudata(L, 1, QUERY_MT);
    size_t             length;
    const uint8_t*     data = (const uint8_t*)luaL_checklstring(L, 2, &length);
    lua_settop(L, 4);
    if (lua_isnil(L, 3)) {
        lua_getfield(L, LUA_REGISTRYINDEX, OPENTLV_LUA_DEFAULT_FORMAT_KEY);
        lua_replace(L, 3);
    }
    tlv_lua_format_t* format = opentlv_lua_check_format(L, 3);
    size_t            depth = opentlv_lua_query_limit(L, 4, "max_depth", TLV_TREE_DEFAULT_DEPTH);
    size_t            elements = opentlv_lua_query_limit(L, 4, "max_elements", 65536);
    size_t            capacity = depth < length ? depth : length;
    if (capacity > SIZE_MAX / sizeof(tlv_tree_frame_t))
        return opentlv_lua_raise(L, TLV_ERR_LIMIT, 0, 0);
    tlv_tree_frame_t*   frames = (tlv_tree_frame_t*)lua_newuserdata(L, capacity * sizeof(*frames));
    tlv_tree_reader_t   reader;
    tlv_query_matcher_t matcher;
    tlv_result_t        code = tlv_query_matcher_init(&matcher, self);
    if (code == TLV_OK)
        code = tlv_tree_reader_init(&reader, data, length, &format->format, frames, capacity, depth,
                                    elements);
    if (code != TLV_OK) return opentlv_lua_raise(L, code, 0, 0);
    lua_newtable(L);
    int count = 0;
    for (;;) {
        tlv_tree_item_t         item;
        tlv_reader_diagnostic_t diagnostic;
        tlv_reader_diagnostic_init(&diagnostic);
        code = tlv_tree_reader_next_diag(&reader, &item, &diagnostic);
        if (code == TLV_ERR_END_OF_BUFFER) break;
        if (code != TLV_OK) return opentlv_lua_raise_reader_error(L, code, &diagnostic);
        if (!tlv_query_matcher_visit(&matcher, &item.element.tag, item.depth)) continue;
        if (count == INT_MAX) return opentlv_lua_raise(L, TLV_ERR_LIMIT, 0, 0);
        code = (tlv_result_t)opentlv_lua_push_element(L, &item.element, item.offset);
        if (code != TLV_OK) return opentlv_lua_raise(L, code, 1, item.offset);
        lua_pushinteger(L, (lua_Integer)item.depth);
        lua_setfield(L, -2, "depth");
        lua_pushboolean(L, item.constructed);
        lua_setfield(L, -2, "constructed");
        lua_rawseti(L, -2, ++count);
    }
    return 1;
}

void opentlv_lua_open_query(lua_State* L, int module_index) {
    static const opentlv_lua_method_t methods[] = {
        {"steps", query_steps}, {"evaluate", query_evaluate}, {NULL, NULL}};
    opentlv_lua_new_type(L, QUERY_MT, methods, NULL, NULL, NULL);
    lua_pushcfunction(L, query_new);
    lua_setfield(L, module_index, "query");
}
