#include "formats.h"

static void check_walk(const uint8_t* data, size_t size, size_t format,
                       size_t depth, size_t elements, size_t stop_at,
                       tlv_visit_result_t action) {
    fuzz_visit_context ctx = {0};
    size_t error = SIZE_MAX;
    ctx.data = data; ctx.size = size;
    ctx.max_depth = depth; ctx.max_elements = elements; ctx.max_value_size = size;
    ctx.stop_at = stop_at; ctx.action = action;
    tlv_result_t rc = tlv_walk_tree(data, size, fuzz_formats[format].reader,
        fuzz_formats[format].constructed, depth, elements, fuzz_visit, &ctx, &error);
    if (rc == TLV_OK) FUZZ_CHECK(error == SIZE_MAX);
    else FUZZ_CHECK(error <= size);
    if (stop_at && ctx.count == stop_at) {
        FUZZ_CHECK(rc == (action == TLV_VISIT_STOP ? TLV_OK : TLV_ERR_VISITOR));
    }
    if (!stop_at) {
        size_t other_error = SIZE_MAX;
        FUZZ_CHECK(rc == tlv_walk_tree(data, size, fuzz_formats[format].reader,
            fuzz_formats[format].constructed, depth, elements, NULL, NULL, &other_error));
        FUZZ_CHECK(error == other_error);
    }
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    size_t depth = size ? data[0] % (TLV_WALK_MAX_DEPTH + 2) : 0;
    size_t elements = size > 1 ? data[1] : 0;
    for (size_t i = 0; fuzz_formats[i].reader; ++i) {
        check_walk(data, size, i, TLV_WALK_MAX_DEPTH, SIZE_MAX, 0, TLV_VISIT_CONTINUE);
        check_walk(data, size, i, depth, elements, 0, TLV_VISIT_CONTINUE);
        check_walk(data, size, i, 0, SIZE_MAX, 0, TLV_VISIT_CONTINUE);
        check_walk(data, size, i, TLV_WALK_MAX_DEPTH, 0, 0, TLV_VISIT_CONTINUE);
        check_walk(data, size, i, TLV_WALK_MAX_DEPTH, SIZE_MAX, 1, TLV_VISIT_STOP);
        check_walk(data, size, i, TLV_WALK_MAX_DEPTH, SIZE_MAX, 1, TLV_VISIT_ERROR);
    }
    return 0;
}
