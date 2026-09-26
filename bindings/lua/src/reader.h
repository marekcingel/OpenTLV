#ifndef OPENTLV_LUA_READER_H
#define OPENTLV_LUA_READER_H

#include "compat.h"

/* Registers the "opentlv.Reader" metatable and module_table["reader"], the
 * opentlv.reader(data, format) constructor function. module_table must be
 * on top of the stack; the stack is unchanged on return. Call once from
 * luaopen_opentlv_native(), after opentlv_lua_open_format(). */
void opentlv_lua_open_reader(lua_State* L, int module_table_index);

#endif /* OPENTLV_LUA_READER_H */
