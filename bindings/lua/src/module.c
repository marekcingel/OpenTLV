/*
 * luaopen_opentlv_native(): the entry point require("opentlv_native") loads.
 * Ties together the format (format.c), reader (reader.c), tree traversal
 * (walk.c), error (error.c) and shared (common.c) pieces into the module
 * table Lua sees; the OpenTLV C reader itself (tlv/reader/) does the actual
 * parsing, exactly as for every other OpenTLV binding (see
 * docs/concepts/bindings.md).
 *
 * This is the native module, not the one callers require: `require("opentlv")`
 * resolves to lua/opentlv/init.lua, a one-line pure-Lua file that returns
 * this module unchanged, the same native/pure split Python's
 * opentlv-native/opentlv and Rust's opentlv-native/opentlv already use.
 *
 * Rule for what belongs here versus in tlv/: functionality that would be
 * useful outside Lua belongs in the OpenTLV C API, not in this binding.
 * This module (and every other file under bindings/lua/src/) only adapts
 * the existing public C API to Lua's calling conventions, ownership model
 * and error handling; it does not implement TLV parsing, encoding or
 * validation logic of its own. When a Lua-binding change would require new
 * decoding/encoding behavior, that behavior is added to tlv/ first, and this
 * binding calls it, the same way format.c, reader.c and walk.c call
 * tlv_reader_init(), tlv_reader_next_diag() and tlv_walk_tree() rather than
 * re-implementing any part of what those functions do.
 */
#include "common.h"
#include "compat.h"
#include "error.h"
#include "format.h"
#include "reader.h"
#include "walk.h"

#include <tlv/error.h>
#include <tlv/version.h>

static int l_version(lua_State* L) {
    lua_pushstring(L, tlv_version_string());
    return 1;
}

static int l_strerror(lua_State* L) {
    lua_Integer code = luaL_checkinteger(L, 1);
    lua_pushstring(L, tlv_strerror((tlv_result_t)code));
    return 1;
}

int luaopen_opentlv_native(lua_State* L) {
    lua_newtable(L);
    int module_index = lua_gettop(L);

    opentlv_lua_open_error(L);
    opentlv_lua_register_error_codes(L, module_index);
    opentlv_lua_open_format(L, module_index);
    opentlv_lua_open_reader(L, module_index);
    opentlv_lua_open_walk(L, module_index);

    lua_pushcfunction(L, l_version);
    lua_setfield(L, module_index, "version");
    lua_pushcfunction(L, l_strerror);
    lua_setfield(L, module_index, "strerror");

    /* Reports the linked C library's version, independent of this binding's
     * own rockspec version, the same distinction docs/development/python.md
     * documents for opentlv.__version__. */
    lua_pushstring(L, tlv_version_string());
    lua_setfield(L, module_index, "_VERSION");

    return 1;
}
