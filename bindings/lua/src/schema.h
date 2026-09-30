#ifndef OPENTLV_LUA_SCHEMA_H
#define OPENTLV_LUA_SCHEMA_H

#include "compat.h"

/* Registers the Schema userdata and module.schema constructor. */
void opentlv_lua_open_schema(lua_State* L, int module_table_index);

#endif /* OPENTLV_LUA_SCHEMA_H */
