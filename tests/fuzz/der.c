#include "common.h"
#include "tlv/profiles/der.h"

static void check_der(const uint8_t* data, size_t size, const tlv_der_limits_t* limits) {
    const tlv_der_limits_t* actual = limits ? limits : &tlv_der_default_limits;
    tlv_view_t view = fuzz_sentinel(data), before = view;
    size_t consumed = SIZE_MAX, error = SIZE_MAX;
    tlv_result_t rc = tlv_der_read(data, size, limits, &view, &consumed, &error);
    if (rc == TLV_OK) {
        FUZZ_CHECK(consumed > 0 && consumed <= size);
        fuzz_view_bounds(&view, data, consumed);
        FUZZ_CHECK(size <= actual->max_input_size);
        FUZZ_CHECK(view.value.length <= actual->max_value_size);
        FUZZ_CHECK(error == SIZE_MAX);
        /* A successful single-element validation must also walk its prefix. */
        FUZZ_CHECK(tlv_der_walk(data, consumed, limits, NULL, NULL, NULL) == TLV_OK);
    } else {
        fuzz_unchanged(&view, &before);
        FUZZ_CHECK(consumed == SIZE_MAX && error <= size);
    }
    for (unsigned mode = 0; mode < 3; ++mode) {
        fuzz_visit_context ctx = {0};
        ctx.data = data; ctx.size = size;
        ctx.max_depth = actual->max_depth; ctx.max_elements = actual->max_elements;
        ctx.max_value_size = actual->max_value_size;
        ctx.stop_at = mode ? 1 : 0;
        ctx.action = mode == 1 ? TLV_VISIT_STOP : TLV_VISIT_ERROR;
        error = SIZE_MAX;
        rc = tlv_der_walk(data, size, limits, fuzz_visit, &ctx, &error);
        if (rc == TLV_OK) {
            FUZZ_CHECK(error == SIZE_MAX && size <= actual->max_input_size);
        } else FUZZ_CHECK(error <= size);
        if (mode && ctx.count) {
            FUZZ_CHECK(rc == (mode == 1 ? TLV_OK : TLV_ERR_VISITOR));
        }
        if (!mode) {
            size_t other_error = SIZE_MAX;
            FUZZ_CHECK(rc == tlv_der_walk(data, size, limits, NULL, NULL, &other_error));
            FUZZ_CHECK(error == other_error);
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
