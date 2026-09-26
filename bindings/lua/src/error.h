#ifndef OPENTLV_LUA_ERROR_H
#define OPENTLV_LUA_ERROR_H

#include "compat.h"

#include <tlv/error.h>
#include <tlv/reader/reader.h>

/* Metatable name for every error table this binding raises. */
#define OPENTLV_LUA_ERROR_MT "opentlv.Error"

/* Registers the "opentlv.Error" metatable (__tostring only). Call once from
 * luaopen_opentlv_native(). */
void opentlv_lua_open_error(lua_State* L);

/* Sets module_table["errors"] = { OK = 0, BUFFER_TOO_SHORT = 1, ... }, one
 * entry per tlv_result_t value. module_table must be on top of the stack;
 * the stack is unchanged on return. */
void opentlv_lua_register_error_codes(lua_State* L, int module_table_index);

/* "tag", "length", "value" or "trailer"; NULL for an unset operation. */
const char* opentlv_lua_reader_operation_name(tlv_reader_operation_t operation);

/* Pushes a table describing `code`, with the "opentlv.Error" metatable set:
 * always "code" and "message" (tlv_strerror(code)); "offset" only if
 * has_offset. Does not raise; the caller decides whether to return it,
 * stash it (see walk.c), or raise it with lua_error(). */
void opentlv_lua_push_error(lua_State* L, tlv_result_t code, int has_offset, size_t offset);

/* Like opentlv_lua_push_error(), additionally filling "expected", "actual",
 * "operation" and "tag" from a reader diagnostic when it reports them.
 * `diag` may be NULL, equivalent to opentlv_lua_push_error() with has_offset
 * false. */
void opentlv_lua_push_reader_error(lua_State* L, tlv_result_t code,
                                   const tlv_reader_diagnostic_t* diag);

/* Raises the table built by opentlv_lua_push_error()/opentlv_lua_push_reader_error()
 * via lua_error(). Safe to call directly from any function Lua calls
 * directly; never call these from inside a callback invoked by a C library
 * function such as tlv_walk_tree()/tlv_der_walk() (see walk.c). Both never
 * return; the int result mirrors lua_error()'s so callers can write
 * `return opentlv_lua_raise(...)`. */
int opentlv_lua_raise(lua_State* L, tlv_result_t code, int has_offset, size_t offset);
int opentlv_lua_raise_reader_error(lua_State* L, tlv_result_t code,
                                   const tlv_reader_diagnostic_t* diag);

#endif /* OPENTLV_LUA_ERROR_H */
