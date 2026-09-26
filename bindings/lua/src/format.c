#include "format.h"
#include "common.h"
#include "error.h"

#include <string.h>

#include <tlv/builtins/asn1/ber.h>
#include <tlv/builtins/asn1/cer.h>
#include <tlv/builtins/asn1/der.h>
#include <tlv/builtins/bluetooth/bluetooth_ltv.h>
#include <tlv/builtins/fixed/default.h>

tlv_lua_format_t* opentlv_lua_check_format(lua_State* L, int arg) {
    return (tlv_lua_format_t*)luaL_checkudata(L, arg, OPENTLV_LUA_FORMAT_MT);
}

static int format_tostring(lua_State* L) {
    tlv_lua_format_t* format = opentlv_lua_check_format(L, 1);
    lua_pushfstring(L, "opentlv.Format<%s>", format->name);
    return 1;
}

/* Pushes a new format userdata backed by a copy of a stateless, global
 * reader format (default/ber/cer/der/bluetooth_ltv); leaves it on top of
 * the stack. */
static void push_builtin_format(lua_State* L, tlv_reader_format_t reader_format,
                                tlv_is_constructed_fn is_constructed, int use_der_walker,
                                const char* name) {
    tlv_lua_format_t* format = (tlv_lua_format_t*)lua_newuserdata(L, sizeof(tlv_lua_format_t));
    format->reader_format = reader_format;
    format->is_constructed = is_constructed;
    format->use_der_walker = use_der_walker;
    format->name = name;
    luaL_getmetatable(L, OPENTLV_LUA_FORMAT_MT);
    lua_setmetatable(L, -2);
}

/* opentlv.formats.fixed(tag_size, length_size, byte_order) -> Format
 *
 * byte_order is "big" or "little", matching tlv_byte_order_t. */
static int l_format_fixed(lua_State* L) {
    lua_Integer tag_size = luaL_checkinteger(L, 1);
    lua_Integer length_size = luaL_checkinteger(L, 2);
    const char* order_name = luaL_checkstring(L, 3);

    if (tag_size <= 0) {
        return luaL_argerror(L, 1, "tag_size must be positive");
    }
    if (length_size <= 0) {
        return luaL_argerror(L, 2, "length_size must be positive");
    }
    tlv_byte_order_t order;
    if (strcmp(order_name, "big") == 0) {
        order = TLV_BYTE_ORDER_BIG_ENDIAN;
    } else if (strcmp(order_name, "little") == 0) {
        order = TLV_BYTE_ORDER_LITTLE_ENDIAN;
    } else {
        return luaL_argerror(L, 3, "expected \"big\" or \"little\"");
    }

    tlv_lua_format_t* format = (tlv_lua_format_t*)lua_newuserdata(L, sizeof(tlv_lua_format_t));
    format->fixed_config.tag_size = (size_t)tag_size;
    format->fixed_config.length_size = (size_t)length_size;
    format->fixed_config.order = order;
    format->is_constructed = NULL;
    format->use_der_walker = 0;
    format->name = "fixed";

    tlv_result_t code = tlv_fixed_reader_format_init(&format->reader_format, &format->fixed_config);
    if (code != TLV_OK) {
        return opentlv_lua_raise(L, code, 0, 0);
    }

    luaL_getmetatable(L, OPENTLV_LUA_FORMAT_MT);
    lua_setmetatable(L, -2);
    return 1;
}

void opentlv_lua_open_format(lua_State* L, int module_table_index) {
    opentlv_lua_new_type(L, OPENTLV_LUA_FORMAT_MT, NULL, NULL, format_tostring, NULL);

    lua_newtable(L); /* formats */

    push_builtin_format(L, tlv_reader_format_default, NULL, 0, "default");
    lua_setfield(L, -2, "default");
    push_builtin_format(L, tlv_reader_format_ber, tlv_ber_is_constructed, 0, "ber");
    lua_setfield(L, -2, "ber");
    push_builtin_format(L, tlv_reader_format_cer, tlv_cer_is_constructed, 0, "cer");
    lua_setfield(L, -2, "cer");
    push_builtin_format(L, tlv_reader_format_der, tlv_der_is_constructed, 1, "der");
    lua_setfield(L, -2, "der");
    push_builtin_format(L, tlv_reader_format_bluetooth_ltv, NULL, 0, "bluetooth_ltv");
    lua_setfield(L, -2, "bluetooth_ltv");
    lua_pushcfunction(L, l_format_fixed);
    lua_setfield(L, -2, "fixed");

    lua_getfield(L, -1, "default");
    lua_setfield(L, LUA_REGISTRYINDEX, OPENTLV_LUA_DEFAULT_FORMAT_KEY);

    lua_setfield(L, module_table_index, "formats");
}
