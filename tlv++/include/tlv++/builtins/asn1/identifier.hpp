// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#ifndef OPENTLV_TLVPP_ASN1_IDENTIFIER_HPP
#define OPENTLV_TLVPP_ASN1_IDENTIFIER_HPP
#include "tlv/builtins/asn1/identifier.h"
#include <cstddef>
/** @file
 * @brief ASN.1 identifier representation limits.
 */
namespace tlv {
namespace asn1 {
/** @brief Largest ASN.1 identifier representation accepted by the canonical engine. */
constexpr std::size_t max_tag_size = TLV_ASN1_TAG_MAX_SIZE;
} // namespace asn1
} // namespace tlv
#endif
