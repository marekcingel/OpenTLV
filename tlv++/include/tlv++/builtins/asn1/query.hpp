// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#ifndef OPENTLV_TLVPP_ASN1_QUERY_HPP
#define OPENTLV_TLVPP_ASN1_QUERY_HPP
#include "tlv++/query/options.hpp"
#include "tlv/builtins/asn1/query.h"
/** @file
 * @brief Explicit ASN.1 Query capability composition.
 */
namespace tlv {
namespace asn1 {
/** @brief Add ASN.1 tag classification and DATE conversion before compilation.
 * @param environment Stationary environment, not yet borrowed by a program.
 * @note Adds a provider record and may allocate. Call once per environment.
 */
inline void configure_query(query_environment& environment) {
    detail::query_options_access::tags(environment, &tlv_asn1_query_tags);
    detail::query_options_access::hook(environment, tlv_asn1_query_date);
}
} // namespace asn1
} // namespace tlv
#endif
