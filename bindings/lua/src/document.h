// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_LUA_DOCUMENT_H
#define OPENTLV_LUA_DOCUMENT_H

#include "compat.h"
#include <tlv/config.h>

#if OPENTLV_DOCUMENT
void opentlv_lua_open_document(lua_State* L, int module_index);
#endif

#endif
