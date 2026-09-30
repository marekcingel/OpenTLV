#include <stdlib.h>
#include "visitor.h"
#include "common.h"
#include "error.h"
#include "format.h"

#if OPENTLV_FORMAT_DER
#include <tlv/builtins/asn1/der_validation.h>
#endif
#include <tlv/reader/visitor.h>

/* tlv_tree_reader_visit() requires a real max_elements bound (zero permits only
 * empty input); this is the bound opentlv.visit_tree() applies when its
 * `opts.max_elements` is omitted. Callers traversing untrusted input should
 * pass an explicit, tighter bound instead of relying on this default. */
#define OPENTLV_LUA_DEFAULT_MAX_ELEMENTS ((size_t)65536)

typedef struct {
    lua_State*            L;
    int                   callback_ref;
    const void*           format_context;
    tlv_is_constructed_fn is_constructed;
    /* A Lua error raised by the callback, or a push_entry narrowing failure,
     * is stashed here rather than raised with lua_error(): this trampoline
     * runs inside tlv_tree_reader_visit()'s/tlv_der_visit()'s own C call frames, and
     * those plain C functions are not written to have their stack unwound
     * by a longjmp (which is how Lua errors propagate) part-way through.
     * l_visit_tree() re-raises it after the traversal function has returned,
     * which is a safe boundary since it was called directly by Lua. */
    int          error_ref;
    tlv_result_t push_failed_code;
    size_t       visited;
    int          stopped;
} visitor_ctx_t;

static tlv_visit_result_t visitor_trampoline(const tlv_element_t* element, size_t depth,
                                             size_t offset, void* context) {
    visitor_ctx_t* ctx = (visitor_ctx_t*)context;
    lua_State*     L = ctx->L;

    lua_rawgeti(L, LUA_REGISTRYINDEX, ctx->callback_ref);
    int narrow_code = opentlv_lua_push_element(L, element, offset);
    if (narrow_code != TLV_OK) {
        lua_pop(L, 1); /* the callback pushed above */
        ctx->push_failed_code = (tlv_result_t)narrow_code;
        return TLV_VISIT_ERROR;
    }
    int constructed =
        ctx->is_constructed != NULL && ctx->is_constructed(ctx->format_context, &element->tag) != 0;
    lua_pushboolean(L, constructed);
    lua_setfield(L, -2, "constructed");
    lua_pushinteger(L, (lua_Integer)depth);

    if (lua_pcall(L, 2, 1, 0) != LUA_OK) {
        ctx->error_ref = luaL_ref(L, LUA_REGISTRYINDEX);
        return TLV_VISIT_ERROR;
    }
    ctx->visited++;
    int stopped = lua_isboolean(L, -1) && !lua_toboolean(L, -1);
    lua_pop(L, 1);
    if (stopped) {
        ctx->stopped = 1;
        return TLV_VISIT_STOP;
    }
    return TLV_VISIT_CONTINUE;
}

/* opentlv.visit_tree(data, format, callback, opts) -> visited, stopped
 *
 * Visits every element of `data` in preorder, calling
 * `callback(element, depth)` for each; `element` additionally has a
 * `constructed` boolean field alongside tag/length/value/offset. Returning
 * `false` from `callback` stops the traversal early (`stopped` is then true).
 * `callback` may be omitted (nil) to validate structure and limits only,
 * without the per-element call overhead; `visited` is then always 0, since
 * it counts callback invocations, not elements. `opts` is an optional table
 * with integer `max_depth` (default TLV_TREE_DEFAULT_DEPTH, 64) and
 * `max_elements` (default OPENTLV_LUA_DEFAULT_MAX_ELEMENTS); for
 * opentlv.formats.der, tree traversal always uses tlv_der_visit() with the
 * library's default limits instead, and `opts` is ignored, matching the
 * WebAssembly binding's choice for DER. */
static int l_visit_tree(lua_State* L) {
    size_t            data_len;
    const char*       data = luaL_checklstring(L, 1, &data_len);
    tlv_lua_format_t* format = opentlv_lua_check_format(L, 2);
    int               has_callback = !lua_isnoneornil(L, 3);
    if (has_callback) {
        luaL_checktype(L, 3, LUA_TFUNCTION);
    }

    size_t max_depth = TLV_TREE_DEFAULT_DEPTH;
    size_t max_elements = OPENTLV_LUA_DEFAULT_MAX_ELEMENTS;
    if (!lua_isnoneornil(L, 4)) {
        luaL_checktype(L, 4, LUA_TTABLE);
        lua_getfield(L, 4, "max_depth");
        if (!lua_isnil(L, -1)) {
            lua_Integer requested = luaL_checkinteger(L, -1);
            luaL_argcheck(L, requested >= 0, 4, "max_depth must be nonnegative");
            max_depth = (size_t)requested;
        }
        lua_pop(L, 1);
        lua_getfield(L, 4, "max_elements");
        if (!lua_isnil(L, -1)) {
            max_elements = (size_t)luaL_checkinteger(L, -1);
        }
        lua_pop(L, 1);
    }

    visitor_ctx_t ctx;
    ctx.L = L;
    if (has_callback) {
        lua_pushvalue(L, 3);
        ctx.callback_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    } else {
        ctx.callback_ref = LUA_NOREF;
    }
    ctx.format_context = format->format.context;
    ctx.is_constructed = format->format.is_constructed;
    ctx.error_ref = LUA_NOREF;
    ctx.push_failed_code = TLV_OK;
    ctx.visited = 0;
    ctx.stopped = 0;

    tlv_tree_visitor_t visitor = has_callback ? visitor_trampoline : NULL;
    size_t             error_offset = 0;
    tlv_result_t       code;
#if OPENTLV_FORMAT_DER
    if (format->use_der_validation) {
        code = tlv_der_visit((const uint8_t*)data, data_len, NULL, visitor, &ctx, &error_offset);
    } else
#endif
    {
        tlv_tree_reader_t reader;
        size_t            capacity = max_depth < data_len ? max_depth : data_len;
        tlv_tree_frame_t* frames = NULL;
        if (capacity > SIZE_MAX / sizeof(*frames)) {
            code = TLV_ERR_OUT_OF_MEMORY;
        } else {
            if (capacity) frames = (tlv_tree_frame_t*)malloc(capacity * sizeof(*frames));
            code = capacity && !frames ? TLV_ERR_OUT_OF_MEMORY
                                       : tlv_tree_reader_init(&reader, (const uint8_t*)data,
                                                              data_len, &format->format, frames,
                                                              capacity, max_depth, max_elements);
            if (code == TLV_OK) code = tlv_tree_reader_visit(&reader, visitor, &ctx, &error_offset);
            free(frames);
        }
    }

    if (has_callback) {
        luaL_unref(L, LUA_REGISTRYINDEX, ctx.callback_ref);
    }

    if (code == TLV_ERR_VISITOR) {
        if (ctx.error_ref != LUA_NOREF) {
            lua_rawgeti(L, LUA_REGISTRYINDEX, ctx.error_ref);
            luaL_unref(L, LUA_REGISTRYINDEX, ctx.error_ref);
            return lua_error(L);
        }
        return opentlv_lua_raise(L, ctx.push_failed_code, 1, error_offset);
    }
    if (code != TLV_OK) {
        return opentlv_lua_raise(L, code, 1, error_offset);
    }

    lua_pushinteger(L, (lua_Integer)ctx.visited);
    lua_pushboolean(L, ctx.stopped);
    return 2;
}

void opentlv_lua_open_visitor(lua_State* L, int module_table_index) {
    lua_pushcfunction(L, l_visit_tree);
    lua_setfield(L, module_table_index, "visit_tree");
}
