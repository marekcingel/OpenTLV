// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#ifndef OPENTLV_TEST_DIAGNOSTIC_ASSERTIONS_H
#define OPENTLV_TEST_DIAGNOSTIC_ASSERTIONS_H

#include "diagnostic_invariant.h"
#include "tlv/query/program.h"
#include "tlv/schema/query.h"
#include <gtest/gtest.h>

namespace diagnostic_test {
inline tlv_result_t result(tlv_result_t rc, const tlv_diagnostic_t& diagnostic) {
    if (rc != TLV_OK)
        EXPECT_TRUE(test_diagnostic_matches(rc, &diagnostic))
            << "result=" << rc << " diagnostic=" << diagnostic.code;
    return rc;
}
inline tlv_result_t result(tlv_result_t rc, const tlv_query_diagnostic_t& diagnostic) {
    if (rc != TLV_OK) {
        EXPECT_TRUE(test_query_diagnostic_matches(rc, &diagnostic))
            << "result=" << rc << " kind=" << diagnostic.kind;
        if (diagnostic.kind == TLV_QUERY_ERROR_READER) EXPECT_TRUE(diagnostic.has_reader);
        if (diagnostic.kind == TLV_QUERY_ERROR_CODEC) EXPECT_NE(TLV_CODEC_OK, diagnostic.codec);
    }
    return rc;
}
inline tlv_result_t result(tlv_result_t rc, const tlv_schema_query_diagnostic_t& diagnostic) {
    if (rc != TLV_OK) {
        if (diagnostic.schema.diagnostic.code != TLV_OK)
            result(rc, diagnostic.schema.diagnostic);
        else
            result(rc, diagnostic.query);
    }
    return rc;
}
template <typename Diagnostic> tlv_result_t result(tlv_result_t rc, const Diagnostic& diagnostic) {
    return result(rc, diagnostic.diagnostic);
}
} // namespace diagnostic_test

// Evaluate the operation exactly once before examining its diagnostic. Success
// need not clear a reused diagnostic. Preflight/alias and rejected continuation
// tests assert unchanged storage separately instead of using this
// post-initialization helper (including INVALID_STATE => STATE).
#define TLV_DIAGNOSTIC_RESULT(diagnostic, expression)                                              \
    ([&]() {                                                                                       \
        const auto diagnostic_result = (expression);                                               \
        return diagnostic_test::result(diagnostic_result, (diagnostic));                           \
    }())

#endif
