// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#ifndef OPENTLV_TLVPP_EMV_QUERY_HPP
#define OPENTLV_TLVPP_EMV_QUERY_HPP
#include "tlv++/query/options.hpp"
#include "tlv/builtins/emv/query.h"
/** @file
 * @brief Explicit EMV Query name resolution.
 */
namespace tlv {
namespace emv {
/** @brief Select canonical EMV symbolic name resolution during compilation.
 * @param options Compiler configuration, modified before compilation only.
 * @note Does not allocate or add tag interpretation to the generic engine.
 */
inline void configure_query(query_options& options) {
    detail::query_options_access::resolver(options, tlv_emv_query_resolve);
}
} // namespace emv
} // namespace tlv
#endif
