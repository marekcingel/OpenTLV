// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_TLVPP_BUILTINS_LLDP_CODEC_HPP
#define OPENTLV_TLVPP_BUILTINS_LLDP_CODEC_HPP

/** @file
 * @brief C++ LLDP Value codecs and base fields.
 *
 * Codecs interpret Value only, delegate validation to the canonical C engine,
 * and implement the generic typed-field contract. Successful operations allocate
 * nothing. Borrowed results require immutable input to outlive every retained copy.
 * Encode storage must be disjoint from all borrowed input; nullptr/0 validates
 * and measures. Codec errors are propagated unchanged.
 */
#include <array>
#include "tlv/builtins/lldp/codec.h"
#include "tlv++/detail/builtin_codec.hpp"

namespace tlv {
/** @brief LLDP base information-string semantics. */
namespace lldp {
/** @brief Self-contained capability bitmaps; see #tlv_lldp_capabilities_t. */
using capabilities = tlv_lldp_capabilities_t;
/** @brief LLDP id; borrowed octets retain input lifetime. */
struct id {
    /** @brief Identifier subtype, 1..7. */
    uint8_t subtype;
    /** @brief Borrowed identifier octets, including family for network addresses. */
    value_view identifier;
};
/** @brief LLDP management address; borrowed octets retain input lifetime. */
struct management_address {
    /** @brief Nonzero address-family number. */
    uint8_t address_subtype;
    /** @brief Borrowed address, excluding subtype. */
    value_view address;
    /** @brief Numbering scheme: 1, 2 or 3. */
    uint8_t interface_subtype;
    /** @brief Interface number. */
    uint32_t interface_number;
    /** @brief Borrowed opaque OID octets. */
    value_view oid;
};
/** @brief LLDP organisation; borrowed octets retain input lifetime. */
struct organisation {
    /** @brief OUI octets in wire order. */
    std::array<uint8_t, 3> oui;
    /** @brief Organisation-defined subtype. */
    uint8_t subtype;
    /** @brief Borrowed opaque organisation payload. */
    value_view payload;
};
} // namespace lldp
/// @cond INTERNAL
namespace detail {
struct lldp_id_conversion {
    static tlv::lldp::id from_native(const tlv_lldp_id_t& value) {
        return {value.subtype, detail::semantic_access::borrow(value.identifier)};
    }
    static tlv_lldp_id_t to_native(const tlv::lldp::id& value) {
        return {value.subtype, detail::semantic_access::get(value.identifier)};
    }
};
struct lldp_management_address_conversion {
    static tlv::lldp::management_address from_native(const tlv_lldp_management_address_t& value) {
        return {value.address_subtype, detail::semantic_access::borrow(value.address),
                value.interface_subtype, value.interface_number,
                detail::semantic_access::borrow(value.oid)};
    }
    static tlv_lldp_management_address_t to_native(const tlv::lldp::management_address& value) {
        return {value.address_subtype, detail::semantic_access::get(value.address),
                value.interface_subtype, value.interface_number,
                detail::semantic_access::get(value.oid)};
    }
};
struct lldp_organisation_conversion {
    static tlv::lldp::organisation from_native(const tlv_lldp_organisation_t& value) {
        return {{{value.oui[0], value.oui[1], value.oui[2]}},
                value.subtype,
                detail::semantic_access::borrow(value.payload)};
    }
    static tlv_lldp_organisation_t to_native(const tlv::lldp::organisation& value) {
        return {{value.oui[0], value.oui[1], value.oui[2]},
                value.subtype,
                detail::semantic_access::get(value.payload)};
    }
};
} // namespace detail
/// @endcond
namespace lldp {
/** @brief Value codec; see #tlv_lldp_codec_chassis_id. */
using chassis_id_codec = detail::builtin_codec<id, tlv_lldp_id_t, &tlv_lldp_codec_chassis_id,
                                               detail::lldp_id_conversion>;
/** @brief Value codec; see #tlv_lldp_codec_port_id. */
using port_id_codec =
    detail::builtin_codec<id, tlv_lldp_id_t, &tlv_lldp_codec_port_id, detail::lldp_id_conversion>;
/** @brief Value codec; see #tlv_lldp_codec_management_address. */
using management_address_codec =
    detail::builtin_codec<management_address, tlv_lldp_management_address_t,
                          &tlv_lldp_codec_management_address,
                          detail::lldp_management_address_conversion>;
/** @brief Value codec; see #tlv_lldp_codec_organisation. */
using organisation_codec =
    detail::builtin_codec<organisation, tlv_lldp_organisation_t, &tlv_lldp_codec_organisation,
                          detail::lldp_organisation_conversion>;
/** @brief Capability codec; see #tlv_lldp_codec_capabilities. */
using capabilities_codec = tlv::detail::codec_adapter<capabilities, &tlv_lldp_codec_capabilities>;
/** @brief TTL codec, including zero; exchange and sequence policy remain separate. */
using ttl_codec = tlv::uint16_be_codec;
/** @brief Borrowed opaque text octets; no character conversion or terminator. */
using text_codec = tlv::codec<value_view>;
/** @brief LLDP field using the canonical identifier octet, independent of packed wire header. */
using chassis_id_field =
    tlv::field<tlv::tag_constant<0x01>, chassis_id_codec::value_type, chassis_id_codec>;
/** @brief LLDP field using the canonical identifier octet, independent of packed wire header. */
using port_id_field = tlv::field<tlv::tag_constant<0x02>, port_id_codec::value_type, port_id_codec>;
/** @brief LLDP field using the canonical identifier octet, independent of packed wire header. */
using ttl_field = tlv::field<tlv::tag_constant<0x03>, ttl_codec::value_type, ttl_codec>;
/** @brief LLDP field using the canonical identifier octet, independent of packed wire header. */
using port_description_field =
    tlv::field<tlv::tag_constant<0x04>, text_codec::value_type, text_codec>;
/** @brief LLDP field using the canonical identifier octet, independent of packed wire header. */
using system_name_field = tlv::field<tlv::tag_constant<0x05>, text_codec::value_type, text_codec>;
/** @brief LLDP field using the canonical identifier octet, independent of packed wire header. */
using system_description_field =
    tlv::field<tlv::tag_constant<0x06>, text_codec::value_type, text_codec>;
/** @brief LLDP field using the canonical identifier octet, independent of packed wire header. */
using capabilities_field =
    tlv::field<tlv::tag_constant<0x07>, capabilities_codec::value_type, capabilities_codec>;
/** @brief LLDP field using the canonical identifier octet, independent of packed wire header. */
using management_address_field =
    tlv::field<tlv::tag_constant<0x08>, management_address_codec::value_type,
               management_address_codec>;
/** @brief LLDP field using the canonical identifier octet, independent of packed wire header. */
using organisation_field =
    tlv::field<tlv::tag_constant<0x7F>, organisation_codec::value_type, organisation_codec>;
} // namespace lldp
} // namespace tlv
#endif
