// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "formats.h"

static void check_failure(tlv_result_t rc, const tlv_reader_diagnostic_t* error, size_t size) {
    if (rc == TLV_OK) return; /* Successful calls need not preserve diagnostic storage. */
    FUZZ_CHECK(error->diagnostic.code == rc);
    const tlv_location_t* location = &error->diagnostic.location;
    if (location->kind == TLV_LOCATION_UNKNOWN) return;
    FUZZ_CHECK(location->domain == TLV_LOCATION_INPUT);
    FUZZ_CHECK(location->kind >= TLV_LOCATION_POINT && location->kind <= TLV_LOCATION_INSERTION);
    FUZZ_CHECK(location->begin <= location->end && location->end <= size);
    FUZZ_CHECK(location->kind == TLV_LOCATION_SPAN || location->begin == location->end);
}

static void check_visit(const uint8_t* data, size_t size, size_t format, size_t depth,
                        size_t elements, size_t stop_at, tlv_visit_result_t action) {
    fuzz_visit_context      ctx = {0};
    tlv_reader_diagnostic_t error = {0};
    ctx.data = data;
    ctx.size = size;
    ctx.max_depth = depth;
    ctx.max_elements = elements;
    ctx.max_value_size = size;
    ctx.stop_at = stop_at;
    ctx.action = action;
    tlv_tree_reader_t reader;
    tlv_tree_frame_t  frames[TLV_TREE_DEFAULT_DEPTH];
    tlv_result_t rc = tlv_tree_reader_init(&reader, data, size, fuzz_formats[format].format, frames,
                                           TLV_TREE_DEFAULT_DEPTH, depth, elements);
    FUZZ_CHECK(rc == TLV_OK);
    rc = tlv_tree_reader_visit(&reader, fuzz_visit, &ctx, &error);
    check_failure(rc, &error, size);
    if (stop_at && ctx.count == stop_at) {
        FUZZ_CHECK(rc == (action == TLV_VISIT_STOP ? TLV_OK : TLV_ERR_VISITOR));
    }
    if (!stop_at) {
        tlv_reader_diagnostic_t other_error = {0};
        FUZZ_CHECK(tlv_tree_reader_init(&reader, data, size, fuzz_formats[format].format, frames,
                                        TLV_TREE_DEFAULT_DEPTH, depth, elements) == TLV_OK);
        FUZZ_CHECK(rc == tlv_tree_reader_visit(&reader, NULL, NULL, &other_error));
        check_failure(rc, &other_error, size);
        if (rc != TLV_OK) {
            const tlv_location_t* location = &error.diagnostic.location;
            const tlv_location_t* other = &other_error.diagnostic.location;
            FUZZ_CHECK(location->kind == other->kind);
            if (location->kind != TLV_LOCATION_UNKNOWN) {
                FUZZ_CHECK(location->domain == other->domain);
                FUZZ_CHECK(location->begin == other->begin && location->end == other->end);
            }
        }
    }
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    size_t depth = size ? data[0] % (TLV_TREE_DEFAULT_DEPTH + 2) : 0;
    size_t elements = size > 1 ? data[1] : 0;
    for (size_t i = 0; fuzz_formats[i].format; ++i) {
        check_visit(data, size, i, TLV_TREE_DEFAULT_DEPTH, SIZE_MAX, 0, TLV_VISIT_CONTINUE);
        check_visit(data, size, i, depth, elements, 0, TLV_VISIT_CONTINUE);
        check_visit(data, size, i, 0, SIZE_MAX, 0, TLV_VISIT_CONTINUE);
        check_visit(data, size, i, TLV_TREE_DEFAULT_DEPTH, 0, 0, TLV_VISIT_CONTINUE);
        check_visit(data, size, i, TLV_TREE_DEFAULT_DEPTH, SIZE_MAX, 1, TLV_VISIT_STOP);
        check_visit(data, size, i, TLV_TREE_DEFAULT_DEPTH, SIZE_MAX, 1, TLV_VISIT_ERROR);
    }
    return 0;
}
