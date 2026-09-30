#ifndef OPENTLV_FUZZ_COMMON_H
#define OPENTLV_FUZZ_COMMON_H

#include "tlv/config.h"
#include "tlv/size.h"
#include "tlv/reader/reader.h"
#include "tlv/reader/visitor.h"
#include "tlv/writer/writer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Unlike assert(), contract checks must survive Release/NDEBUG builds. */
#define FUZZ_CHECK(condition)                                                                      \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition);                        \
            abort();                                                                               \
        }                                                                                          \
    } while (0)

static inline void fuzz_element_bounds(const tlv_element_t* element, const uint8_t* data,
                                       size_t size) {
    uintptr_t base = (uintptr_t)data, value = (uintptr_t)element->value.data;
    uintptr_t tag = (uintptr_t)element->tag.data;
    /* The tag borrows the input, so its bytes must lie inside it. */
    FUZZ_CHECK(element->tag.size > 0);
    FUZZ_CHECK(tag >= base && tag - base <= size);
    FUZZ_CHECK(element->tag.size <= size - (size_t)(tag - base));
    /* Integer comparisons avoid undefined pointer subtraction on a bad element. */
    FUZZ_CHECK(value >= base && value - base <= size);
    FUZZ_CHECK(element->value.size <= size - (size_t)(value - base));
}

static inline tlv_element_t fuzz_sentinel(const uint8_t* data) {
    static const uint8_t sentinel_tag[] = {0xa5};
    tlv_element_t        element;
    memset(&element, 0, sizeof(element));
    element.tag = tlv_tag(sentinel_tag, sizeof(sentinel_tag));
    element.value.data = data;
    element.value.size = SIZE_MAX;
    return element;
}

static inline void fuzz_unchanged(const tlv_element_t* element, const tlv_element_t* before) {
    FUZZ_CHECK(element->tag.size == before->tag.size);
    FUZZ_CHECK(element->tag.data == before->tag.data);
    FUZZ_CHECK(element->value.data == before->value.data);
    FUZZ_CHECK(element->value.size == before->value.size);
}

typedef struct fuzz_visit_context {
    const uint8_t*     data;
    size_t             size, max_depth, max_elements, max_value_size;
    size_t             count, previous_offset, previous_depth;
    size_t             value_ends[TLV_TREE_DEFAULT_DEPTH + 1];
    size_t             stop_at;
    tlv_visit_result_t action;
} fuzz_visit_context;

static inline tlv_visit_result_t fuzz_visit(const tlv_element_t* element, size_t depth,
                                            size_t offset, void* opaque) {
    fuzz_visit_context* ctx = (fuzz_visit_context*)opaque;
    size_t              value_length;
    FUZZ_CHECK(ctx->count < ctx->max_elements);
    FUZZ_CHECK(depth <= ctx->max_depth && depth <= TLV_TREE_DEFAULT_DEPTH);
    FUZZ_CHECK(offset < ctx->size);
    FUZZ_CHECK(ctx->count ? offset > ctx->previous_offset : depth == 0);
    FUZZ_CHECK(!ctx->count || depth <= ctx->previous_depth + 1);
    fuzz_element_bounds(element, ctx->data + offset, ctx->size - offset);
    FUZZ_CHECK(element->value.size <= ctx->max_value_size);
    FUZZ_CHECK(tlv_size_to_native(element->value.size, &value_length) == TLV_OK);
    ctx->value_ends[depth] =
        (size_t)((uintptr_t)element->value.data - (uintptr_t)ctx->data) + value_length;
    if (depth) FUZZ_CHECK(ctx->value_ends[depth] <= ctx->value_ends[depth - 1]);
    ctx->previous_offset = offset;
    ctx->previous_depth = depth;
    ++ctx->count;
    FUZZ_CHECK(!ctx->stop_at || ctx->count <= ctx->stop_at);
    return ctx->stop_at == ctx->count ? ctx->action : TLV_VISIT_CONTINUE;
}

#endif
