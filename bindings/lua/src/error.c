#include "error.h"

#include <stdio.h>

const char* opentlv_lua_reader_operation_name(tlv_reader_operation_t operation) {
    switch (operation) {
        case TLV_READER_OP_TAG: return "tag";
        case TLV_READER_OP_LENGTH: return "length";
        case TLV_READER_OP_VALUE: return "value";
        case TLV_READER_OP_TRAILER: return "trailer";
        default: return NULL;
    }
}

static int error_tostring(lua_State* L) {
    /* Error objects are plain tables with this metatable attached (see
     * opentlv_lua_push_error()), not userdata, so this is reached only as
     * the __tostring metamethod itself; no argument check is needed. */
    luaL_checktype(L, 1, LUA_TTABLE);

    lua_getfield(L, 1, "message");
    const char* message = lua_tostring(L, -1);
    lua_getfield(L, 1, "code");
    lua_Integer code = lua_tointeger(L, -1);
    lua_getfield(L, 1, "offset");
    int         has_offset = !lua_isnil(L, -1);
    lua_Integer offset = has_offset ? lua_tointeger(L, -1) : 0;

    char buffer[128];
    if (has_offset) {
        snprintf(buffer, sizeof buffer, "opentlv: %s (code %lld, offset %lld)",
                 message != NULL ? message : "unknown error", (long long)code, (long long)offset);
    } else {
        snprintf(buffer, sizeof buffer, "opentlv: %s (code %lld)",
                 message != NULL ? message : "unknown error", (long long)code);
    }
    lua_pop(L, 3);
    lua_pushstring(L, buffer);
    return 1;
}

void opentlv_lua_open_error(lua_State* L) {
    luaL_newmetatable(L, OPENTLV_LUA_ERROR_MT);
    lua_pushcfunction(L, error_tostring);
    lua_setfield(L, -2, "__tostring");
    lua_pop(L, 1);
}

void opentlv_lua_register_error_codes(lua_State* L, int module_table_index) {
    lua_newtable(L);
    lua_pushinteger(L, TLV_OK);
    lua_setfield(L, -2, "OK");
    lua_pushinteger(L, TLV_ERR_BUFFER_TOO_SHORT);
    lua_setfield(L, -2, "BUFFER_TOO_SHORT");
    lua_pushinteger(L, TLV_ERR_INVALID_LENGTH);
    lua_setfield(L, -2, "INVALID_LENGTH");
    lua_pushinteger(L, TLV_ERR_NULL_ARG);
    lua_setfield(L, -2, "NULL_ARG");
    lua_pushinteger(L, TLV_ERR_OUT_OF_MEMORY);
    lua_setfield(L, -2, "OUT_OF_MEMORY");
    lua_pushinteger(L, TLV_ERR_END_OF_BUFFER);
    lua_setfield(L, -2, "END_OF_BUFFER");
    lua_pushinteger(L, TLV_ERR_INVALID_TAG);
    lua_setfield(L, -2, "INVALID_TAG");
    lua_pushinteger(L, TLV_ERR_VISITOR);
    lua_setfield(L, -2, "VISITOR");
    lua_pushinteger(L, TLV_ERR_LIMIT);
    lua_setfield(L, -2, "LIMIT");
    lua_pushinteger(L, TLV_ERR_SCHEMA);
    lua_setfield(L, -2, "SCHEMA");
    lua_pushinteger(L, TLV_ERR_INVALID_ARG);
    lua_setfield(L, -2, "INVALID_ARG");
    lua_pushinteger(L, TLV_ERR_INVALID_TAG_SIZE);
    lua_setfield(L, -2, "INVALID_TAG_SIZE");
    lua_pushinteger(L, TLV_ERR_INVALID_BYTE_ORDER);
    lua_setfield(L, -2, "INVALID_BYTE_ORDER");
    lua_pushinteger(L, TLV_ERR_OVERFLOW);
    lua_setfield(L, -2, "OVERFLOW");
    lua_pushinteger(L, TLV_ERR_INVALID_VALUE);
    lua_setfield(L, -2, "INVALID_VALUE");
    lua_pushinteger(L, TLV_ERR_UNSUPPORTED_TYPE);
    lua_setfield(L, -2, "UNSUPPORTED_TYPE");
    lua_pushinteger(L, TLV_ERR_SCHEMA_MISSING);
    lua_setfield(L, -2, "SCHEMA_MISSING");
    lua_setfield(L, module_table_index, "errors");
}

void opentlv_lua_push_error(lua_State* L, tlv_result_t code, int has_offset, size_t offset) {
    lua_newtable(L);
    lua_pushinteger(L, (lua_Integer)code);
    lua_setfield(L, -2, "code");
    lua_pushstring(L, tlv_strerror(code));
    lua_setfield(L, -2, "message");
    if (has_offset) {
        lua_pushinteger(L, (lua_Integer)offset);
        lua_setfield(L, -2, "offset");
    }
    luaL_getmetatable(L, OPENTLV_LUA_ERROR_MT);
    lua_setmetatable(L, -2);
}

void opentlv_lua_push_reader_error(lua_State* L, tlv_result_t code,
                                   const tlv_reader_diagnostic_t* diag) {
    int    has_offset = diag != NULL && diag->diagnostic.has_offset;
    size_t offset = has_offset ? diag->diagnostic.offset : 0;
    opentlv_lua_push_error(L, code, has_offset, offset);

    if (diag == NULL) {
        return;
    }
    if (diag->diagnostic.expected != NULL) {
        lua_pushstring(L, diag->diagnostic.expected);
        lua_setfield(L, -2, "expected");
    }
    if (diag->diagnostic.actual != NULL) {
        lua_pushstring(L, diag->diagnostic.actual);
        lua_setfield(L, -2, "actual");
    }
    const char* operation = opentlv_lua_reader_operation_name(diag->operation);
    if (operation != NULL) {
        lua_pushstring(L, operation);
        lua_setfield(L, -2, "operation");
    }
    if (diag->has_tag) {
        lua_pushlstring(L, (const char*)diag->tag.data, diag->tag.size);
        lua_setfield(L, -2, "tag");
    }
}

int opentlv_lua_raise(lua_State* L, tlv_result_t code, int has_offset, size_t offset) {
    opentlv_lua_push_error(L, code, has_offset, offset);
    return lua_error(L);
}

int opentlv_lua_raise_reader_error(lua_State* L, tlv_result_t code,
                                   const tlv_reader_diagnostic_t* diag) {
    opentlv_lua_push_reader_error(L, code, diag);
    return lua_error(L);
}
