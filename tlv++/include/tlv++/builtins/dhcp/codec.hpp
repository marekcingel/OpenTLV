// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_TLVPP_BUILTINS_DHCP_CODEC_HPP
#define OPENTLV_TLVPP_BUILTINS_DHCP_CODEC_HPP

/** @file
 * @brief C++ DHCPv4 Message Type codec and field.
 *
 * Codecs interpret Value only, delegate validation to the canonical C engine,
 * and implement the generic typed-field contract. Successful operations allocate
 * nothing. Borrowed results require immutable input to outlive every retained copy.
 * Encode storage must be disjoint from all borrowed input; nullptr/0 validates
 * and measures. Codec errors are propagated unchanged.
 */
#include "tlv/builtins/dhcp/codec.h"
#include "tlv++/codec/typed.hpp"

namespace tlv {
/** @brief DHCPv4 option Value semantics. */
namespace dhcp {
/** @brief Message Type byte codec; preserves unassigned values without exchange validation. */
using message_type_codec = tlv::uint8_codec;
/** @brief DHCPv4 Message Type option (53). */
using message_type_field =
    tlv::field<tlv::tag_constant<0x35>, message_type_codec::value_type, message_type_codec>;
} // namespace dhcp
} // namespace tlv
#endif
