#ifndef OPENTLV_LUA_FORMAT_H
#define OPENTLV_LUA_FORMAT_H

#include "compat.h"

#include <tlv/builtins/fixed/fixed.h>
#include <tlv/format.h>

/* Metatable name for opentlv.formats.default/ber/cer/der/bluetooth_ltv and
 * every table returned by opentlv.formats.fixed(). */
#define OPENTLV_LUA_FORMAT_MT "opentlv.Format"

/* Registry key under which opentlv.formats.default is stashed, so
 * opentlv.reader() can fall back to it when its format argument is omitted
 * without having to reach back into the module table. */
#define OPENTLV_LUA_DEFAULT_FORMAT_KEY "opentlv.default_format"

/* A reader format bound to Lua: the reader_format callbacks used by every
 * generic C entry point (tlv_reader_next(), tlv_walk_tree(), ...), the
 * matching is_constructed predicate (NULL for flat formats), whether tree
 * traversal should dispatch to the stricter tlv_der_walk() instead of the
 * generic tlv_walk_tree(), and a name for diagnostics.
 *
 * For the built-in presets (default/ber/cer/der/bluetooth_ltv) reader_format
 * is a copy of the corresponding extern const global; for opentlv.formats.fixed()
 * it is initialized by tlv_fixed_reader_format_init() with `fixed_config`
 * (embedded in this same userdata, so its address stays valid for exactly as
 * long as the format object itself does) as its context. */
typedef struct tlv_lua_format {
    tlv_reader_format_t   reader_format;
    tlv_fixed_config_t    fixed_config;
    tlv_is_constructed_fn is_constructed;
    int                   use_der_walker;
    const char*           name;
} tlv_lua_format_t;

/* Registers the "opentlv.Format" metatable, builds module_table["formats"]
 * and stashes the default format under OPENTLV_LUA_DEFAULT_FORMAT_KEY.
 * module_table must be on top of the stack; the stack is unchanged on
 * return. Call once from luaopen_opentlv_native(). */
void opentlv_lua_open_format(lua_State* L, int module_table_index);

/* Checks that the value at `arg` is an opentlv.Format, raising a Lua
 * argument error otherwise. */
tlv_lua_format_t* opentlv_lua_check_format(lua_State* L, int arg);

#endif /* OPENTLV_LUA_FORMAT_H */
