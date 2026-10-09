// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "common.h"
#include "tlv/builtins/asn1/der_validation.h"

static void check_der(const uint8_t* data, size_t size, const tlv_der_limits_t* limits) {
    const tlv_der_limits_t* actual = limits ? limits : &tlv_der_default_limits;
    tlv_element_t           element = fuzz_sentinel(data), before = element;
    size_t                  consumed = SIZE_MAX;
    tlv_diagnostic_t        error = {0};
    error.location.begin = SIZE_MAX;
    tlv_result_t rc = tlv_der_read(data, size, limits, &element, &consumed, &error);
    if (rc == TLV_OK) {
        FUZZ_CHECK(consumed > 0 && consumed <= size);
        fuzz_element_bounds(&element, data, consumed);
        FUZZ_CHECK(size <= actual->max_input_size);
        FUZZ_CHECK(element.value.size <= actual->max_value_size);
        FUZZ_CHECK(error.location.begin == SIZE_MAX);
        /* A successful single-element validation must also traverse its prefix. */
        FUZZ_CHECK(tlv_der_visit(data, consumed, limits, NULL, NULL, NULL) == TLV_OK);
    } else {
        fuzz_unchanged(&element, &before);
        FUZZ_CHECK(consumed == SIZE_MAX && error.location.begin <= size);
    }
    for (unsigned mode = 0; mode < 3; ++mode) {
        fuzz_visit_context ctx = {0};
        ctx.data = data;
        ctx.size = size;
        ctx.max_depth = actual->max_depth;
        ctx.max_elements = actual->max_elements;
        ctx.max_value_size = actual->max_value_size;
        ctx.stop_at = mode ? 1 : 0;
        ctx.action = mode == 1 ? TLV_VISIT_STOP : TLV_VISIT_ERROR;
        error.location.begin = SIZE_MAX;
        rc = tlv_der_visit(data, size, limits, fuzz_visit, &ctx, &error);
        if (rc == TLV_OK) {
            FUZZ_CHECK(error.location.begin == SIZE_MAX && size <= actual->max_input_size);
        } else
            FUZZ_CHECK(error.location.begin <= size);
        if (mode && ctx.count) {
            FUZZ_CHECK(rc == (mode == 1 ? TLV_OK : TLV_ERR_VISITOR));
        }
        if (!mode) {
            tlv_diagnostic_t other_error = {0};
            other_error.location.begin = SIZE_MAX;
            FUZZ_CHECK(rc == tlv_der_visit(data, size, limits, NULL, NULL, &other_error));
            FUZZ_CHECK(error.location.begin == other_error.location.begin);
        }
    }
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    tlv_der_limits_t limits = {TLV_DER_MAX_DEPTH, SIZE_MAX, SIZE_MAX, SIZE_MAX};
    check_der(data, size, NULL);
    check_der(data, size, &limits);
    /* Vary each limit independently so one early rejection cannot mask the
     * others (in particular, max_input_size must not hide depth checks). */
    limits.max_depth = size ? data[0] % (TLV_DER_MAX_DEPTH + 2) : 0;
    check_der(data, size, &limits);
    limits.max_depth = TLV_DER_MAX_DEPTH;
    limits.max_elements = size > 1 ? data[1] : 0;
    check_der(data, size, &limits);
    limits.max_elements = SIZE_MAX;
    limits.max_value_size = size > 2 ? data[2] : 0;
    check_der(data, size, &limits);
    limits.max_value_size = SIZE_MAX;
    limits.max_input_size = size > 3 ? data[3] : 0;
    check_der(data, size, &limits);
    return 0;
}
