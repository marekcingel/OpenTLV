// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

/* Deliberately invalid callback results must be produced in C, not C++. */
#include "raw_result.h"

tlv_result_t tlv_test_raw_decode(const void* context, const uint8_t* data, size_t size, void* value,
                                 size_t capacity, tlv_codec_diagnostic_t* diagnostic) {
    (void)data;
    (void)size;
    (void)value;
    (void)capacity;
    (void)diagnostic;
    return (tlv_result_t) * (const int32_t*)context;
}

tlv_result_t tlv_test_raw_encode(const void* context, const void* value, size_t size, uint8_t* data,
                                 size_t capacity, size_t* written,
                                 tlv_codec_diagnostic_t* diagnostic) {
    (void)value;
    (void)size;
    (void)data;
    (void)capacity;
    (void)diagnostic;
    *written = 0;
    return (tlv_result_t) * (const int32_t*)context;
}

#if OPENTLV_QUERY
tlv_result_t tlv_test_raw_query(const void* context, const tlv_tree_event_t* event,
                                const uint8_t* data, size_t size, void* scratch,
                                size_t scratch_size, tlv_query_result_t* result,
                                tlv_codec_diagnostic_t* diagnostic) {
    (void)event;
    (void)result;
    return tlv_test_raw_decode(context, data, size, scratch, scratch_size, diagnostic);
}
#endif
