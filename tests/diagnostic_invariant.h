// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#ifndef OPENTLV_TEST_DIAGNOSTIC_INVARIANT_H
#define OPENTLV_TEST_DIAGNOSTIC_INVARIANT_H
#include "tlv/diagnostic.h"
#include "tlv/query/program.h"
static inline int test_diagnostic_matches(tlv_result_t rc, const tlv_diagnostic_t* diagnostic) {
    return rc == TLV_OK || diagnostic->code == rc;
}
static inline int test_query_diagnostic_matches(tlv_result_t                  rc,
                                                const tlv_query_diagnostic_t* diagnostic) {
    return rc == TLV_OK ||
           (diagnostic->kind != TLV_QUERY_ERROR_NONE &&
            (rc != TLV_ERR_INVALID_STATE || diagnostic->kind == TLV_QUERY_ERROR_STATE) &&
            (diagnostic->kind != TLV_QUERY_ERROR_READER ||
             test_diagnostic_matches(rc, &diagnostic->reader.diagnostic)) &&
            (diagnostic->kind != TLV_QUERY_ERROR_CODEC || diagnostic->codec != TLV_CODEC_OK));
}
#endif
