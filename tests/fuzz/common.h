#ifndef OPENTLV_FUZZ_COMMON_H
#define OPENTLV_FUZZ_COMMON_H

#include "tlv/config.h"
#include "tlv/reader/reader.h"
#include "tlv/reader/walker.h"
#include "tlv/writer/writer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Unlike assert(), contract checks must survive Release/NDEBUG builds. */
#define FUZZ_CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition); \
        abort(); \
    } \
} while (0)

static inline void fuzz_view_bounds(const tlv_view_t* view,
                                    const uint8_t* data, size_t size) {
    uintptr_t base = (uintptr_t)data, value = (uintptr_t)view->value.data;
    FUZZ_CHECK(view->tag.size > 0 && view->tag.size <= TLV_TAG_MAX_SIZE);
    /* Integer comparisons avoid undefined pointer subtraction on a bad view. */
    FUZZ_CHECK(value >= base && value - base <= size);
    FUZZ_CHECK(view->value.length <= size - (size_t)(value - base));
}

static inline tlv_view_t fuzz_sentinel(const uint8_t* data) {
    tlv_view_t view;
    memset(&view, 0, sizeof(view));
    memset(view.tag.data, 0xa5, sizeof(view.tag.data));
    view.tag.size = 1;
    view.value.data = data;
    view.value.length = SIZE_MAX;
    return view;
}

static inline void fuzz_unchanged(const tlv_view_t* view, const tlv_view_t* before) {
    FUZZ_CHECK(view->tag.size == before->tag.size);
    FUZZ_CHECK(memcmp(view->tag.data, before->tag.data, TLV_TAG_MAX_SIZE) == 0);
    FUZZ_CHECK(view->value.data == before->value.data);
    FUZZ_CHECK(view->value.length == before->value.length);
}

typedef struct fuzz_visit_context {
    const uint8_t* data;
    size_t size, max_depth, max_elements, max_value_size;
    size_t count, previous_offset, previous_depth;
    size_t value_ends[TLV_WALK_MAX_DEPTH + 1];
    size_t stop_at;
    tlv_visit_result_t action;
} fuzz_visit_context;

static inline tlv_visit_result_t fuzz_visit(const tlv_view_t* view, size_t depth,
                                           size_t offset, void* opaque) {
    fuzz_visit_context* ctx = (fuzz_visit_context*)opaque;
    FUZZ_CHECK(ctx->count < ctx->max_elements);
    FUZZ_CHECK(depth <= ctx->max_depth && depth <= TLV_WALK_MAX_DEPTH);
    FUZZ_CHECK(offset < ctx->size);
    FUZZ_CHECK(ctx->count ? offset > ctx->previous_offset : depth == 0);
    FUZZ_CHECK(!ctx->count || depth <= ctx->previous_depth + 1);
    fuzz_view_bounds(view, ctx->data + offset, ctx->size - offset);
    FUZZ_CHECK(view->value.length <= ctx->max_value_size);
    ctx->value_ends[depth] = (size_t)((uintptr_t)view->value.data -
                                    (uintptr_t)ctx->data) + view->value.length;
    if (depth) FUZZ_CHECK(ctx->value_ends[depth] <= ctx->value_ends[depth - 1]);
    ctx->previous_offset = offset;
    ctx->previous_depth = depth;
    ++ctx->count;
    FUZZ_CHECK(!ctx->stop_at || ctx->count <= ctx->stop_at);
    return ctx->stop_at == ctx->count ? ctx->action : TLV_VISIT_CONTINUE;
}

#endif
