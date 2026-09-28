#include "../format.h"
#include <tlv/builtins/lldp/lldp.h>

void opentlv_lua_register_lldp(lua_State* L) {
    opentlv_lua_register_builtin(L, tlv_format_lldp, 0, "lldp");
}
