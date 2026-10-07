// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_TLVPP_BUILTINS_ASN1_CODEC_HPP
#define OPENTLV_TLVPP_BUILTINS_ASN1_CODEC_HPP

/** @file
 * @brief C++ ASN.1 Value codecs and primitive universal fields.
 *
 * Codecs interpret Value only, delegate validation to the canonical C engine,
 * and implement the generic typed-field contract. Successful operations allocate
 * nothing. Borrowed results require immutable input to outlive every retained copy.
 * Encode storage must be disjoint from all borrowed input; nullptr/0 validates
 * and measures. Codec errors are propagated unchanged.
 */
#include <array>
#include "tlv/builtins/asn1/asn1_codec.h"
#include "tlv++/detail/builtin_codec.hpp"

namespace tlv {
/** @brief Shared ASN.1 Value semantics for BER, CER and DER. */
namespace asn1 {
/** @brief Self-contained ASN.1 oid representation; see #tlv_asn1_oid_t. */
using oid = tlv_asn1_oid_t;
/** @brief Self-contained ASN.1 utc time representation; see #tlv_asn1_utc_time_t. */
using utc_time = tlv_asn1_utc_time_t;
/** @brief Self-contained ASN.1 date representation; see #tlv_asn1_date_t. */
using date = tlv_asn1_date_t;
/** @brief Self-contained ASN.1 time of day representation; see #tlv_asn1_time_of_day_t. */
using time_of_day = tlv_asn1_time_of_day_t;
/** @brief Self-contained ASN.1 date time representation; see #tlv_asn1_date_time_t. */
using date_time = tlv_asn1_date_time_t;
/** @brief Borrowed ASN.1 BIT STRING. */
struct bit_string {
    /** @brief Unused low-order bits in the final octet, 0..7. */
    uint8_t unused_bits;
    /** @brief Borrowed content excluding the unused-bit octet. */
    value_view data;
};
/** @brief ASN.1 GeneralizedTime with borrowed fractional digits; C range checks apply. */
struct generalized_time {
    /** @brief Four-digit year, 0..9999. */
    int32_t year;
    /** @brief Month, 1..12. */
    uint8_t month;
    /** @brief Day, 1..31. */
    uint8_t day;
    /** @brief Hour, 0..23. */
    uint8_t hour;
    /** @brief Minute, 0..59. */
    uint8_t minute;
    /** @brief Second, 0..59. */
    uint8_t second;
    /** @brief Borrowed fractional decimal digits; use an empty default view when absent. */
    value_view fraction_digits;
};
/** @brief OID-IRI labels borrowing immutable input. */
struct iri {
    /** @brief Borrowed UTF-8 arc labels, without separators. */
    std::array<value_view, TLV_ASN1_IRI_MAX_ARCS> arcs;
    /** @brief Number of populated arcs; at most TLV_ASN1_IRI_MAX_ARCS. */
    size_t count;
};
} // namespace asn1
/// @cond INTERNAL
namespace detail {
struct asn1_bit_string_conversion {
    static tlv::asn1::bit_string from_native(const tlv_asn1_bit_string_t& value) {
        return {value.unused_bits,
                value_view(bytes(reinterpret_cast<const byte*>(value.data), value.length))};
    }
    static tlv_asn1_bit_string_t to_native(const tlv::asn1::bit_string& value) {
        return {value.unused_bits, reinterpret_cast<const uint8_t*>(value.data.data()),
                value.data.size()};
    }
};
struct asn1_generalized_time_conversion {
    static tlv::asn1::generalized_time from_native(const tlv_asn1_generalized_time_t& value) {
        return {value.year,
                value.month,
                value.day,
                value.hour,
                value.minute,
                value.second,
                value_view(bytes(reinterpret_cast<const byte*>(value.fraction_digits),
                                 value.fraction_digits_length))};
    }
    static tlv_asn1_generalized_time_t to_native(const tlv::asn1::generalized_time& value) {
        return {value.year,
                value.month,
                value.day,
                value.hour,
                value.minute,
                value.second,
                reinterpret_cast<const uint8_t*>(value.fraction_digits.data()),
                value.fraction_digits.size()};
    }
};
struct asn1_iri_conversion {
    static tlv::asn1::iri from_native(const tlv_asn1_iri_t& value) {
        tlv::asn1::iri result{};
        result.count = value.count;
        for (size_t i = 0; i < value.count; ++i)
            result.arcs[i] = value_view(
                bytes(reinterpret_cast<const byte*>(value.arcs[i].data), value.arcs[i].length));
        return result;
    }
    static tlv_asn1_iri_t to_native(const tlv::asn1::iri& value) {
        tlv_asn1_iri_t result{};
        result.count = value.count;
        for (size_t i = 0; i < value.count && i < TLV_ASN1_IRI_MAX_ARCS; ++i)
            result.arcs[i] = {reinterpret_cast<const uint8_t*>(value.arcs[i].data()),
                              value.arcs[i].size()};
        return result;
    }
};
} // namespace detail
/// @endcond
namespace asn1 {
/** @brief Canonical Value codec; see #tlv_asn1_codec_boolean. */
using boolean_codec = tlv::detail::codec_adapter<bool, &tlv_asn1_codec_boolean>;
/** @brief Canonical Value codec; see #tlv_asn1_codec_integer. */
using integer_codec = tlv::detail::codec_adapter<int64_t, &tlv_asn1_codec_integer>;
/** @brief Canonical Value codec; see #tlv_asn1_codec_enumerated. */
using enumerated_codec = tlv::detail::codec_adapter<int64_t, &tlv_asn1_codec_enumerated>;
/** @brief Canonical Value codec; see #tlv_asn1_codec_bit_string. */
using bit_string_codec =
    detail::builtin_codec<bit_string, tlv_asn1_bit_string_t, &tlv_asn1_codec_bit_string,
                          detail::asn1_bit_string_conversion>;
/** @brief Canonical Value codec; see #tlv_asn1_codec_octet_string. */
using octet_string_codec =
    detail::builtin_string_codec<tlv_asn1_octet_string_t, &tlv_asn1_codec_octet_string, 1>;
/** @brief ASN.1 NULL semantic value, with no content bytes. */
struct null_value {};
/** @brief Canonical Value codec; see #tlv_asn1_codec_null. */
using null_codec = tlv::detail::codec_adapter<null_value, &tlv_asn1_codec_null>;
/** @brief Canonical Value codec; see #tlv_asn1_codec_oid. */
using oid_codec = tlv::detail::codec_adapter<oid, &tlv_asn1_codec_oid>;
/** @brief Canonical Value codec; see #tlv_asn1_codec_relative_oid. */
using relative_oid_codec = tlv::detail::codec_adapter<oid, &tlv_asn1_codec_relative_oid>;
/** @brief Canonical Value codec; see #tlv_asn1_codec_utf8_string. */
using utf8_string_codec =
    detail::builtin_string_codec<tlv_asn1_string_t, &tlv_asn1_codec_utf8_string, 1>;
/** @brief Canonical Value codec; see #tlv_asn1_codec_numeric_string. */
using numeric_string_codec =
    detail::builtin_string_codec<tlv_asn1_string_t, &tlv_asn1_codec_numeric_string, 1>;
/** @brief Canonical Value codec; see #tlv_asn1_codec_printable_string. */
using printable_string_codec =
    detail::builtin_string_codec<tlv_asn1_string_t, &tlv_asn1_codec_printable_string, 1>;
/** @brief Canonical Value codec; see #tlv_asn1_codec_ia5_string. */
using ia5_string_codec =
    detail::builtin_string_codec<tlv_asn1_string_t, &tlv_asn1_codec_ia5_string, 1>;
/** @brief Canonical Value codec; see #tlv_asn1_codec_visible_string. */
using visible_string_codec =
    detail::builtin_string_codec<tlv_asn1_string_t, &tlv_asn1_codec_visible_string, 1>;
/** @brief Canonical Value codec; see #tlv_asn1_codec_bmp_string. */
using bmp_string_codec =
    detail::builtin_string_codec<tlv_asn1_bmp_string_t, &tlv_asn1_codec_bmp_string, 2>;
/** @brief Canonical Value codec; see #tlv_asn1_codec_universal_string. */
using universal_string_codec =
    detail::builtin_string_codec<tlv_asn1_universal_string_t, &tlv_asn1_codec_universal_string, 4>;
/** @brief Canonical Value codec; see #tlv_asn1_codec_utc_time. */
using utc_time_codec = tlv::detail::codec_adapter<utc_time, &tlv_asn1_codec_utc_time>;
/** @brief Canonical Value codec; see #tlv_asn1_codec_generalized_time. */
using generalized_time_codec = detail::builtin_codec<generalized_time, tlv_asn1_generalized_time_t,
                                                     &tlv_asn1_codec_generalized_time,
                                                     detail::asn1_generalized_time_conversion>;
/** @brief Canonical Value codec; see #tlv_asn1_codec_object_descriptor. */
using object_descriptor_codec =
    detail::builtin_string_codec<tlv_asn1_octet_string_t, &tlv_asn1_codec_object_descriptor, 1>;
/** @brief Canonical Value codec; see #tlv_asn1_codec_teletex_string. */
using teletex_string_codec =
    detail::builtin_string_codec<tlv_asn1_octet_string_t, &tlv_asn1_codec_teletex_string, 1>;
/** @brief Canonical Value codec; see #tlv_asn1_codec_videotex_string. */
using videotex_string_codec =
    detail::builtin_string_codec<tlv_asn1_octet_string_t, &tlv_asn1_codec_videotex_string, 1>;
/** @brief Canonical Value codec; see #tlv_asn1_codec_graphic_string. */
using graphic_string_codec =
    detail::builtin_string_codec<tlv_asn1_octet_string_t, &tlv_asn1_codec_graphic_string, 1>;
/** @brief Canonical Value codec; see #tlv_asn1_codec_general_string. */
using general_string_codec =
    detail::builtin_string_codec<tlv_asn1_octet_string_t, &tlv_asn1_codec_general_string, 1>;
/** @brief Canonical Value codec; see #tlv_asn1_codec_time. */
using time_codec = detail::builtin_string_codec<tlv_asn1_string_t, &tlv_asn1_codec_time, 1>;
/** @brief Canonical Value codec; see #tlv_asn1_codec_date. */
using date_codec = tlv::detail::codec_adapter<date, &tlv_asn1_codec_date>;
/** @brief Canonical Value codec; see #tlv_asn1_codec_time_of_day. */
using time_of_day_codec = tlv::detail::codec_adapter<time_of_day, &tlv_asn1_codec_time_of_day>;
/** @brief Canonical Value codec; see #tlv_asn1_codec_date_time. */
using date_time_codec = tlv::detail::codec_adapter<date_time, &tlv_asn1_codec_date_time>;
/** @brief Canonical Value codec; see #tlv_asn1_codec_duration. */
using duration_codec = detail::builtin_string_codec<tlv_asn1_string_t, &tlv_asn1_codec_duration, 1>;
/** @brief Canonical Value codec; see #tlv_asn1_codec_oid_iri. */
using oid_iri_codec = detail::builtin_codec<iri, tlv_asn1_iri_t, &tlv_asn1_codec_oid_iri,
                                            detail::asn1_iri_conversion>;
/** @brief Canonical Value codec; see #tlv_asn1_codec_relative_oid_iri. */
using relative_oid_iri_codec =
    detail::builtin_codec<iri, tlv_asn1_iri_t, &tlv_asn1_codec_relative_oid_iri,
                          detail::asn1_iri_conversion>;
/** @brief Primitive universal field; constructed/string fragmentation requires separate handling.
 */
using boolean_field = tlv::field<tlv::tag_constant<0x01>, boolean_codec::value_type, boolean_codec>;
/** @brief Primitive universal field; constructed/string fragmentation requires separate handling.
 */
using integer_field = tlv::field<tlv::tag_constant<0x02>, integer_codec::value_type, integer_codec>;
/** @brief Primitive universal field; constructed/string fragmentation requires separate handling.
 */
using bit_string_field =
    tlv::field<tlv::tag_constant<0x03>, bit_string_codec::value_type, bit_string_codec>;
/** @brief Primitive universal field; constructed/string fragmentation requires separate handling.
 */
using octet_string_field =
    tlv::field<tlv::tag_constant<0x04>, octet_string_codec::value_type, octet_string_codec>;
/** @brief Primitive universal field; constructed/string fragmentation requires separate handling.
 */
using null_field = tlv::field<tlv::tag_constant<0x05>, null_codec::value_type, null_codec>;
/** @brief Primitive universal field; constructed/string fragmentation requires separate handling.
 */
using oid_field = tlv::field<tlv::tag_constant<0x06>, oid_codec::value_type, oid_codec>;
/** @brief Primitive universal field; constructed/string fragmentation requires separate handling.
 */
using object_descriptor_field =
    tlv::field<tlv::tag_constant<0x07>, object_descriptor_codec::value_type,
               object_descriptor_codec>;
/** @brief Primitive universal field; constructed/string fragmentation requires separate handling.
 */
using enumerated_field =
    tlv::field<tlv::tag_constant<0x0A>, enumerated_codec::value_type, enumerated_codec>;
/** @brief Primitive universal field; constructed/string fragmentation requires separate handling.
 */
using utf8_string_field =
    tlv::field<tlv::tag_constant<0x0C>, utf8_string_codec::value_type, utf8_string_codec>;
/** @brief Primitive universal field; constructed/string fragmentation requires separate handling.
 */
using relative_oid_field =
    tlv::field<tlv::tag_constant<0x0D>, relative_oid_codec::value_type, relative_oid_codec>;
/** @brief Primitive universal field; constructed/string fragmentation requires separate handling.
 */
using time_field = tlv::field<tlv::tag_constant<0x0E>, time_codec::value_type, time_codec>;
/** @brief Primitive universal field; constructed/string fragmentation requires separate handling.
 */
using numeric_string_field =
    tlv::field<tlv::tag_constant<0x12>, numeric_string_codec::value_type, numeric_string_codec>;
/** @brief Primitive universal field; constructed/string fragmentation requires separate handling.
 */
using printable_string_field =
    tlv::field<tlv::tag_constant<0x13>, printable_string_codec::value_type, printable_string_codec>;
/** @brief Primitive universal field; constructed/string fragmentation requires separate handling.
 */
using teletex_string_field =
    tlv::field<tlv::tag_constant<0x14>, teletex_string_codec::value_type, teletex_string_codec>;
/** @brief Primitive universal field; constructed/string fragmentation requires separate handling.
 */
using videotex_string_field =
    tlv::field<tlv::tag_constant<0x15>, videotex_string_codec::value_type, videotex_string_codec>;
/** @brief Primitive universal field; constructed/string fragmentation requires separate handling.
 */
using ia5_string_field =
    tlv::field<tlv::tag_constant<0x16>, ia5_string_codec::value_type, ia5_string_codec>;
/** @brief Primitive universal field; constructed/string fragmentation requires separate handling.
 */
using utc_time_field =
    tlv::field<tlv::tag_constant<0x17>, utc_time_codec::value_type, utc_time_codec>;
/** @brief Primitive universal field; constructed/string fragmentation requires separate handling.
 */
using generalized_time_field =
    tlv::field<tlv::tag_constant<0x18>, generalized_time_codec::value_type, generalized_time_codec>;
/** @brief Primitive universal field; constructed/string fragmentation requires separate handling.
 */
using graphic_string_field =
    tlv::field<tlv::tag_constant<0x19>, graphic_string_codec::value_type, graphic_string_codec>;
/** @brief Primitive universal field; constructed/string fragmentation requires separate handling.
 */
using visible_string_field =
    tlv::field<tlv::tag_constant<0x1A>, visible_string_codec::value_type, visible_string_codec>;
/** @brief Primitive universal field; constructed/string fragmentation requires separate handling.
 */
using general_string_field =
    tlv::field<tlv::tag_constant<0x1B>, general_string_codec::value_type, general_string_codec>;
/** @brief Primitive universal field; constructed/string fragmentation requires separate handling.
 */
using universal_string_field =
    tlv::field<tlv::tag_constant<0x1C>, universal_string_codec::value_type, universal_string_codec>;
/** @brief Primitive universal field; constructed/string fragmentation requires separate handling.
 */
using bmp_string_field =
    tlv::field<tlv::tag_constant<0x1E>, bmp_string_codec::value_type, bmp_string_codec>;
/** @brief Primitive universal field; constructed/string fragmentation requires separate handling.
 */
using date_field = tlv::field<tlv::tag_constant<0x1F, 0x1F>, date_codec::value_type, date_codec>;
/** @brief Primitive universal field; constructed/string fragmentation requires separate handling.
 */
using time_of_day_field =
    tlv::field<tlv::tag_constant<0x1F, 0x20>, time_of_day_codec::value_type, time_of_day_codec>;
/** @brief Primitive universal field; constructed/string fragmentation requires separate handling.
 */
using date_time_field =
    tlv::field<tlv::tag_constant<0x1F, 0x21>, date_time_codec::value_type, date_time_codec>;
/** @brief Primitive universal field; constructed/string fragmentation requires separate handling.
 */
using duration_field =
    tlv::field<tlv::tag_constant<0x1F, 0x22>, duration_codec::value_type, duration_codec>;
/** @brief Primitive universal field; constructed/string fragmentation requires separate handling.
 */
using oid_iri_field =
    tlv::field<tlv::tag_constant<0x1F, 0x23>, oid_iri_codec::value_type, oid_iri_codec>;
/** @brief Primitive universal field; constructed/string fragmentation requires separate handling.
 */
using relative_oid_iri_field =
    tlv::field<tlv::tag_constant<0x1F, 0x24>, relative_oid_iri_codec::value_type,
               relative_oid_iri_codec>;
} // namespace asn1
} // namespace tlv

#endif
