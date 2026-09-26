#ifndef OPENTLV_LUA_WALK_H
#define OPENTLV_LUA_WALK_H

#include "compat.h"

/* Registers module_table["walk_tree"], the opentlv.walk_tree(data, format,
 * callback, opts) preorder tree traversal built on tlv_walk_tree()/
 * tlv_der_walk(); `callback` may be omitted to validate structure and
 * limits only. module_table must be on top of the stack; the stack is
 * unchanged on return. Call once from luaopen_opentlv_native(). */
void opentlv_lua_open_walk(lua_State* L, int module_table_index);

#endif /* OPENTLV_LUA_WALK_H */
