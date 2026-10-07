// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_TLVPP_FORMATS_OPTIONS_HPP
#define OPENTLV_TLVPP_FORMATS_OPTIONS_HPP

#include "tlv/endian.h"
#include "tlv/formats/compose.h"

/** @file
 * @brief Strong configuration values shared by C++ wire Formats.
 */
namespace tlv {
/** @brief Byte order of numeric wire fields; identifiers retain byte identity. */
enum class byte_order {
    big_endian = TLV_BYTE_ORDER_BIG_ENDIAN,      /**< Most significant byte first. */
    little_endian = TLV_BYTE_ORDER_LITTLE_ENDIAN /**< Least significant byte first. */
};
/** @brief Order of the identifier and length fields on wire. */
enum class element_order {
    tlv = TLV_ELEMENT_ORDER_TLV, /**< Identifier, length, value. */
    ltv = TLV_ELEMENT_ORDER_LTV  /**< Length, identifier, value. */
};
/** @brief Logical quantity counted by the encoded length. */
enum class length_scope {
    value = TLV_LENGTH_SCOPE_VALUE,                /**< Value bytes only. */
    tag_and_value = TLV_LENGTH_SCOPE_TAG_AND_VALUE /**< Identifier and value bytes. */
};
} // namespace tlv
#endif
