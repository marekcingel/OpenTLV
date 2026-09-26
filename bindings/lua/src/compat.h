/* Portability shims for building against Lua 5.1 through 5.4 and LuaJIT
 * (which implements the Lua 5.1 C API) with the same source. Every other
 * Lua C API call used by this binding (lua_newuserdata, luaL_checkudata,
 * luaL_ref/luaL_unref, lua_pcall, ...) is already identical across all of
 * these; only LUA_OK needs a fallback here, since Lua 5.1 predates it. */
#ifndef OPENTLV_LUA_COMPAT_H
#define OPENTLV_LUA_COMPAT_H

#include <lua.h>
#include <lauxlib.h>

#ifndef LUA_OK
#define LUA_OK 0
#endif

#endif /* OPENTLV_LUA_COMPAT_H */
