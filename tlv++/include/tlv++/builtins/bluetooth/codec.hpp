#ifndef OPENTLV_TLVPP_BUILTINS_BLUETOOTH_CODEC_HPP
#define OPENTLV_TLVPP_BUILTINS_BLUETOOTH_CODEC_HPP

/** @file
 * @brief C++ Bluetooth codecs and Advertising Data fields.
 *
 * Codecs interpret Value only, delegate validation to the canonical C engine,
 * and implement the generic typed-field contract. Successful operations allocate
 * nothing. Borrowed results require immutable input to outlive every retained copy.
 * Encode storage must be disjoint from all borrowed input; nullptr/0 validates
 * and measures. Codec errors are propagated unchanged.
 */
#include "tlv/builtins/bluetooth/ad_codec.h"
#include "tlv/builtins/bluetooth/uuid.h"
#include "tlv/builtins/bluetooth/service_data.h"
#include "tlv/builtins/bluetooth/manufacturer_data.h"
#include "tlv++/detail/builtin_codec.hpp"

namespace tlv {
/** @brief Bluetooth Advertising Data Value semantics. */
namespace bluetooth {
/** @brief Self-contained UUID in printed byte order; see #tlv_bluetooth_uuid128_t. */
using uuid128 = tlv_bluetooth_uuid128_t;
/** @brief Bluetooth uuid list; immutable input must outlive borrowed views. */
struct uuid_list {
    /** @brief Borrowed UUID octets in wire order. */
    value_view raw;
    /** @brief UUID width: 2, 4 or 16 bytes. */
    size_t uuid_size;
};
/** @brief Bluetooth service data16; immutable input must outlive borrowed views. */
struct service_data16 {
    /** @brief Numeric service UUID. */
    uint16_t uuid;
    /** @brief Borrowed opaque service payload. */
    value_view payload;
    /** @brief Borrowed original Value; ignored when encoding. */
    value_view raw;
};
/** @brief Bluetooth service data32; immutable input must outlive borrowed views. */
struct service_data32 {
    /** @brief Numeric service UUID. */
    uint32_t uuid;
    /** @brief Borrowed opaque service payload. */
    value_view payload;
    /** @brief Borrowed original Value; ignored when encoding. */
    value_view raw;
};
/** @brief Bluetooth service data128; immutable input must outlive borrowed views. */
struct service_data128 {
    /** @brief Service UUID in printed byte order. */
    uuid128 uuid;
    /** @brief Borrowed opaque service payload. */
    value_view payload;
    /** @brief Borrowed original Value; ignored when encoding. */
    value_view raw;
};
/** @brief Bluetooth manufacturer data; immutable input must outlive borrowed views. */
struct manufacturer_data {
    /** @brief Numeric Company Identifier; all values accepted. */
    uint16_t company_id;
    /** @brief Borrowed opaque manufacturer payload. */
    value_view payload;
    /** @brief Borrowed original Value; ignored when encoding. */
    value_view raw;
};
} // namespace bluetooth
/// @cond INTERNAL
namespace detail {
struct bluetooth_uuid_list_conversion {
    static tlv::bluetooth::uuid_list from_native(const tlv_bluetooth_uuid_list_t& value) {
        return {detail::semantic_access::borrow(value.raw), value.uuid_size};
    }
    static tlv_bluetooth_uuid_list_t to_native(const tlv::bluetooth::uuid_list& value) {
        return {detail::semantic_access::get(value.raw), value.uuid_size};
    }
};
struct bluetooth_service_data16_conversion {
    static tlv::bluetooth::service_data16 from_native(const tlv_bluetooth_service_data16_t& value) {
        return {value.uuid, detail::semantic_access::borrow(value.payload),
                detail::semantic_access::borrow(value.raw)};
    }
    static tlv_bluetooth_service_data16_t to_native(const tlv::bluetooth::service_data16& value) {
        return {value.uuid, detail::semantic_access::get(value.payload),
                detail::semantic_access::get(value.raw)};
    }
};
struct bluetooth_service_data32_conversion {
    static tlv::bluetooth::service_data32 from_native(const tlv_bluetooth_service_data32_t& value) {
        return {value.uuid, detail::semantic_access::borrow(value.payload),
                detail::semantic_access::borrow(value.raw)};
    }
    static tlv_bluetooth_service_data32_t to_native(const tlv::bluetooth::service_data32& value) {
        return {value.uuid, detail::semantic_access::get(value.payload),
                detail::semantic_access::get(value.raw)};
    }
};
struct bluetooth_service_data128_conversion {
    static tlv::bluetooth::service_data128
    from_native(const tlv_bluetooth_service_data128_t& value) {
        return {value.uuid, detail::semantic_access::borrow(value.payload),
                detail::semantic_access::borrow(value.raw)};
    }
    static tlv_bluetooth_service_data128_t to_native(const tlv::bluetooth::service_data128& value) {
        return {value.uuid, detail::semantic_access::get(value.payload),
                detail::semantic_access::get(value.raw)};
    }
};
struct bluetooth_manufacturer_data_conversion {
    static tlv::bluetooth::manufacturer_data
    from_native(const tlv_bluetooth_manufacturer_data_t& value) {
        return {value.company_id, detail::semantic_access::borrow(value.payload),
                detail::semantic_access::borrow(value.raw)};
    }
    static tlv_bluetooth_manufacturer_data_t
    to_native(const tlv::bluetooth::manufacturer_data& value) {
        return {value.company_id, detail::semantic_access::get(value.payload),
                detail::semantic_access::get(value.raw)};
    }
};
} // namespace detail
/// @endcond
namespace bluetooth {
/** @brief Value codec; see #tlv_bluetooth_codec_uuid16. */
using uuid16_codec = tlv::codec_adapter<uint16_t, &tlv_bluetooth_codec_uuid16>;
/** @brief Value codec; see #tlv_bluetooth_codec_uuid32. */
using uuid32_codec = tlv::codec_adapter<uint32_t, &tlv_bluetooth_codec_uuid32>;
/** @brief Value codec; see #tlv_bluetooth_codec_uuid128. */
using uuid128_codec = tlv::codec_adapter<uuid128, &tlv_bluetooth_codec_uuid128>;
/** @brief Value codec; see #tlv_bluetooth_ad_codec_tx_power. */
using tx_power_codec = tlv::codec_adapter<int8_t, &tlv_bluetooth_ad_codec_tx_power>;
/** @brief Borrowed Value codec; see #tlv_bluetooth_ad_codec_flags. */
using flags_codec = detail::builtin_codec<value_view, tlv_value_t, &tlv_bluetooth_ad_codec_flags,
                                          detail::borrowed_value_conversion>;
/** @brief Borrowed Value codec; see #tlv_bluetooth_ad_codec_local_name. */
using local_name_codec =
    detail::builtin_codec<value_view, tlv_value_t, &tlv_bluetooth_ad_codec_local_name,
                          detail::borrowed_value_conversion>;
/** @brief Value codec; see #tlv_bluetooth_codec_uuid16_list. */
using uuid16_list_codec =
    detail::builtin_codec<uuid_list, tlv_bluetooth_uuid_list_t, &tlv_bluetooth_codec_uuid16_list,
                          detail::bluetooth_uuid_list_conversion>;
/** @brief Value codec; see #tlv_bluetooth_codec_uuid32_list. */
using uuid32_list_codec =
    detail::builtin_codec<uuid_list, tlv_bluetooth_uuid_list_t, &tlv_bluetooth_codec_uuid32_list,
                          detail::bluetooth_uuid_list_conversion>;
/** @brief Value codec; see #tlv_bluetooth_codec_uuid128_list. */
using uuid128_list_codec =
    detail::builtin_codec<uuid_list, tlv_bluetooth_uuid_list_t, &tlv_bluetooth_codec_uuid128_list,
                          detail::bluetooth_uuid_list_conversion>;
/** @brief Value codec; see #tlv_bluetooth_codec_service_data16. */
using service_data16_codec = detail::builtin_codec<service_data16, tlv_bluetooth_service_data16_t,
                                                   &tlv_bluetooth_codec_service_data16,
                                                   detail::bluetooth_service_data16_conversion>;
/** @brief Value codec; see #tlv_bluetooth_codec_service_data32. */
using service_data32_codec = detail::builtin_codec<service_data32, tlv_bluetooth_service_data32_t,
                                                   &tlv_bluetooth_codec_service_data32,
                                                   detail::bluetooth_service_data32_conversion>;
/** @brief Value codec; see #tlv_bluetooth_codec_service_data128. */
using service_data128_codec =
    detail::builtin_codec<service_data128, tlv_bluetooth_service_data128_t,
                          &tlv_bluetooth_codec_service_data128,
                          detail::bluetooth_service_data128_conversion>;
/** @brief Value codec; see #tlv_bluetooth_codec_manufacturer_data. */
using manufacturer_data_codec =
    detail::builtin_codec<manufacturer_data, tlv_bluetooth_manufacturer_data_t,
                          &tlv_bluetooth_codec_manufacturer_data,
                          detail::bluetooth_manufacturer_data_conversion>;
/** @brief Advertising Data field; Schema owns contextual length constraints. */
using flags_field = tlv::field<tlv::tag_constant<0x01>, flags_codec::value_type, flags_codec>;
/** @brief Advertising Data field; Schema owns contextual length constraints. */
using incomplete_uuid16_list_field =
    tlv::field<tlv::tag_constant<0x02>, uuid16_list_codec::value_type, uuid16_list_codec>;
/** @brief Advertising Data field; Schema owns contextual length constraints. */
using complete_uuid16_list_field =
    tlv::field<tlv::tag_constant<0x03>, uuid16_list_codec::value_type, uuid16_list_codec>;
/** @brief Advertising Data field; Schema owns contextual length constraints. */
using incomplete_uuid32_list_field =
    tlv::field<tlv::tag_constant<0x04>, uuid32_list_codec::value_type, uuid32_list_codec>;
/** @brief Advertising Data field; Schema owns contextual length constraints. */
using complete_uuid32_list_field =
    tlv::field<tlv::tag_constant<0x05>, uuid32_list_codec::value_type, uuid32_list_codec>;
/** @brief Advertising Data field; Schema owns contextual length constraints. */
using incomplete_uuid128_list_field =
    tlv::field<tlv::tag_constant<0x06>, uuid128_list_codec::value_type, uuid128_list_codec>;
/** @brief Advertising Data field; Schema owns contextual length constraints. */
using complete_uuid128_list_field =
    tlv::field<tlv::tag_constant<0x07>, uuid128_list_codec::value_type, uuid128_list_codec>;
/** @brief Advertising Data field; Schema owns contextual length constraints. */
using shortened_local_name_field =
    tlv::field<tlv::tag_constant<0x08>, local_name_codec::value_type, local_name_codec>;
/** @brief Advertising Data field; Schema owns contextual length constraints. */
using complete_local_name_field =
    tlv::field<tlv::tag_constant<0x09>, local_name_codec::value_type, local_name_codec>;
/** @brief Advertising Data field; Schema owns contextual length constraints. */
using tx_power_field =
    tlv::field<tlv::tag_constant<0x0A>, tx_power_codec::value_type, tx_power_codec>;
/** @brief Advertising Data field; Schema owns contextual length constraints. */
using service_data16_field =
    tlv::field<tlv::tag_constant<0x16>, service_data16_codec::value_type, service_data16_codec>;
/** @brief Advertising Data field; Schema owns contextual length constraints. */
using service_data32_field =
    tlv::field<tlv::tag_constant<0x20>, service_data32_codec::value_type, service_data32_codec>;
/** @brief Advertising Data field; Schema owns contextual length constraints. */
using service_data128_field =
    tlv::field<tlv::tag_constant<0x21>, service_data128_codec::value_type, service_data128_codec>;
/** @brief Advertising Data field; Schema owns contextual length constraints. */
using manufacturer_data_field =
    tlv::field<tlv::tag_constant<0xFF>, manufacturer_data_codec::value_type,
               manufacturer_data_codec>;
} // namespace bluetooth
} // namespace tlv
#endif
