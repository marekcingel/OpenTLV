#include "bluetooth.hpp"
#include "tlv++/types.hpp"
#include <cstring>
#include <iomanip>
#include <sstream>
#include "commands/support.hpp"
#include "tlv/config.h"
#if OPENTLV_BLUETOOTH
#include "tlv/builtins/bluetooth/ad_types.h"
#include "tlv/builtins/bluetooth/ad_codec.h"
#include "tlv/builtins/bluetooth/uuid.h"
#include "tlv/builtins/bluetooth/service_data.h"
#include "tlv/builtins/bluetooth/manufacturer_data.h"
#include "tlv/builtins/bluetooth/company_ids.h"
#endif
namespace cli {
bool bluetooth_module(const options& o) {
    return o.module && !std::strcmp(o.module, "bluetooth");
}
const char* bluetooth_name(const tlv_element_t* element) {
#if OPENTLV_BLUETOOTH
    const auto* definition = tlv_definition_find(&tlv_bluetooth_ad_types, &element->tag);
    if (definition) return definition->name;
#else
    (void)element;
#endif
    return "Unknown AD Type";
}
#if OPENTLV_BLUETOOTH
namespace {
std::string hex_value(tlv_value_t value) {
    return hex_string(value.data, tlv::as_bytes(value)->size());
}
std::string uuid_text(uint32_t value, unsigned width) {
    std::ostringstream out;
    out << "0x" << std::uppercase << std::hex << std::setfill('0') << std::setw(width) << value;
    return out.str();
}
std::string uuid_text(const tlv_bluetooth_uuid128_t& uuid, unsigned) {
    const auto h = hex_string(uuid.bytes, sizeof(uuid.bytes));
    return h.substr(0, 8) + "-" + h.substr(8, 4) + "-" + h.substr(12, 4) + "-" + h.substr(16, 4) +
           "-" + h.substr(20);
}
template <class T, class Render>
decode_result decode(const tlv_codec_t& codec, const tlv_element_t* element, Render render) {
    T          value{};
    const auto rc = tlv_codec_decode(&codec, element->value.data, cli_element_value_size(element),
                                     &value, sizeof(value));
    decode_result result;
    result.status = rc == TLV_CODEC_OK ? decode_status::ok : decode_status::error;
    result.text = rc == TLV_CODEC_OK ? render(value) : tlv_codec_strerror(rc);
    return result;
}
template <class T> std::string service(const T& value, unsigned width) {
    return "UUID=" + uuid_text(value.uuid, width) + " payload=" + hex_value(value.payload);
}
} // namespace
#endif
decode_result decode_bluetooth_value(const tlv_element_t* element) {
#if OPENTLV_BLUETOOTH
    if (element->tag.size != 1) return {};
    const unsigned type = element->tag.data[0];
    switch (type) {
        case 0x01:
            return decode<tlv_value_t>(
                tlv_bluetooth_ad_codec_flags, element,
                [](tlv_value_t value) { return value.size ? "0x" + hex_value(value) : "0x00"; });
        case 0x08:
        case 0x09:
            return decode<tlv_value_t>(
                tlv_bluetooth_ad_codec_local_name, element, [](tlv_value_t value) {
                    const auto bytes = *tlv::as_bytes(value);
                    return bytes.empty() ? std::string()
                                         : std::string(reinterpret_cast<const char*>(bytes.data()),
                                                       bytes.size());
                });
        case 0x0A:
            return decode<int8_t>(tlv_bluetooth_ad_codec_tx_power, element, [](int8_t value) {
                return std::to_string(static_cast<int>(value)) + " dBm";
            });
        case 0x02:
        case 0x03:
        case 0x04:
        case 0x05:
        case 0x06:
        case 0x07: {
            const tlv_codec_t& codec = type <= 3   ? tlv_bluetooth_codec_uuid16_list
                                       : type <= 5 ? tlv_bluetooth_codec_uuid32_list
                                                   : tlv_bluetooth_codec_uuid128_list;
            return decode<tlv_bluetooth_uuid_list_t>(
                codec, element, [](const tlv_bluetooth_uuid_list_t& list) {
                    std::string out = "[";
                    const auto  count = tlv::as_bytes(list.raw)->size() / list.uuid_size;
                    for (size_t i = 0; i < count; ++i) {
                        if (i) out += ", ";
                        if (list.uuid_size == 2) {
                            uint16_t value = 0;
                            tlv_bluetooth_uuid_list_at(&list, i, &value, sizeof(value));
                            out += uuid_text(value, 4);
                        } else if (list.uuid_size == 4) {
                            uint32_t value = 0;
                            tlv_bluetooth_uuid_list_at(&list, i, &value, sizeof(value));
                            out += uuid_text(value, 8);
                        } else {
                            tlv_bluetooth_uuid128_t value{};
                            tlv_bluetooth_uuid_list_at(&list, i, &value, sizeof(value));
                            out += uuid_text(value, 0);
                        }
                    }
                    return out + "]";
                });
        }
        case 0x16:
            return decode<tlv_bluetooth_service_data16_t>(
                tlv_bluetooth_codec_service_data16, element,
                [](const tlv_bluetooth_service_data16_t& value) { return service(value, 4); });
        case 0x20:
            return decode<tlv_bluetooth_service_data32_t>(
                tlv_bluetooth_codec_service_data32, element,
                [](const tlv_bluetooth_service_data32_t& value) { return service(value, 8); });
        case 0x21:
            return decode<tlv_bluetooth_service_data128_t>(
                tlv_bluetooth_codec_service_data128, element,
                [](const tlv_bluetooth_service_data128_t& value) { return service(value, 0); });
        case 0xFF:
            return decode<tlv_bluetooth_manufacturer_data_t>(
                tlv_bluetooth_codec_manufacturer_data, element,
                [](const tlv_bluetooth_manufacturer_data_t& value) {
                    const tlv_tag_t key = {value.raw.data, 2};
                    const auto* definition = tlv_definition_find(&tlv_bluetooth_company_ids, &key);
                    return "company=" + uuid_text(value.company_id, 4) + " (" +
                           (definition ? definition->name : "Unknown Company Identifier") +
                           ") payload=" + hex_value(value.payload);
                });
        default: break;
    }
#else
    (void)element;
#endif
    return {};
}
} // namespace cli
