#include "commands/support.hpp"
#include <cstring>
#include <iomanip>
#include <ios>
#include <iostream>
#include "console_color.hpp"
#include "tlv/config.h"
#include "tlv++/reader/walker.hpp"
#if OPENTLV_FORMAT_DEFAULT
#include "tlv/builtins/fixed/default.h"
#endif
#if OPENTLV_FORMAT_FIXED
#include "tlv/formats/fixed.h"
#endif
#if OPENTLV_FORMAT_BLUETOOTH_LTV
#include "tlv/builtins/bluetooth/bluetooth_ltv.h"
#endif
#if OPENTLV_FORMAT_BER
#include "tlv/builtins/asn1/ber.h"
#endif
#if OPENTLV_FORMAT_DER
#include "tlv/builtins/asn1/der.h"
#include "tlv/builtins/asn1/der_profile.h"
#endif

namespace cli {

bool is_json(const options& o) {
    return !strcmp(o.output, "json");
}

const tlv_format_t* select_format(const options& o) {
    const char* name = o.format;
#if OPENTLV_FORMAT_DEFAULT
    if (!strcmp(name, "default")) return &tlv_format_default;
#endif
#if OPENTLV_FORMAT_FIXED
    // Configured by --fixed-tag-size/--fixed-length-size/--fixed-byte-order,
    // one tag byte/one length byte/big-endian by default.
    if (!strcmp(name, "fixed")) {
        static tlv_fixed_format_t config;
        static tlv_format_t       format;
        config.tag_size = o.fixed_tag_size;
        config.length_size = o.fixed_length_size;
        config.order = !strcmp(o.fixed_byte_order, "little") ? TLV_BYTE_ORDER_LITTLE_ENDIAN
                                                             : TLV_BYTE_ORDER_BIG_ENDIAN;
        if (tlv_fixed_format_init(&format, &config) != TLV_OK) return NULL;
        return &format;
    }
#endif
#if OPENTLV_FORMAT_BER
    if (!strcmp(name, "ber")) return &tlv_format_ber;
#endif
#if OPENTLV_FORMAT_DER
    if (!strcmp(name, "der")) return &tlv_format_der;
#endif
#if OPENTLV_FORMAT_BLUETOOTH_LTV
    if (!strcmp(name, "bluetooth-ltv")) return &tlv_format_bluetooth_ltv;
#endif
    (void)name;
    return NULL;
}

void print_hex(const uint8_t* data, std::size_t length) {
    const std::ios::fmtflags saved = std::cout.flags();
    const char               fill = std::cout.fill('0');
    std::cout << std::hex << std::uppercase;
    for (std::size_t i = 0; i < length; ++i) std::cout << std::setw(2) << (unsigned)data[i];
    std::cout.fill(fill);
    std::cout.flags(saved);
}

void print_tag(const tlv_tag_t& tag, bool color) {
    console_color scope(std::cout, color);
    print_hex(tag.data, tag.size);
}

std::string hex_string(const uint8_t* data, std::size_t length) {
    static const char digits[] = "0123456789ABCDEF";
    std::string       result(length * 2, '0');
    for (std::size_t i = 0; i < length; ++i) {
        result[i * 2] = digits[data[i] >> 4];
        result[i * 2 + 1] = digits[data[i] & 0xF];
    }
    return result;
}

tlv_result_t walk_slice(const walk_env& env, const uint8_t* slice, std::size_t slice_size,
                        std::size_t base, std::size_t max_elements, tlv_tree_visitor_t visitor,
                        void* context, std::size_t* error_offset) {
    const options& o = *env.options;
    std::size_t    relative = 0;
    tlv_result_t   result;
#if OPENTLV_FORMAT_DER
    if (env.is_der) {
        tlv_der_limits_t limits = {o.max_depth, o.max_input, o.max_input, max_elements};
        result = tlv_der_walk(slice, slice_size, &limits, visitor, context, &relative);
    } else
#endif
    {
        // The C++ walker owns the callback adapter and exposes borrowed entries.
        const auto walked = tlv::walk_tree(
            tlv::bytes(reinterpret_cast<const tlv::byte*>(slice), slice_size), *env.format,
            o.max_depth, max_elements,
            [visitor, context](const tlv::entry& entry, size_t depth, size_t offset) {
                if (!visitor) return TLV_VISIT_CONTINUE;
                // Presentation shares this view adapter with the unwrapped DER API.
                const tlv_view_t raw = {entry.tag,
                                        {reinterpret_cast<const uint8_t*>(entry.value.data()),
                                         static_cast<tlv_length_t>(entry.value.size())}};
                return visitor(&raw, depth, offset, context);
            },
            &relative);
        result = walked ? TLV_OK : walked.error().code;
    }
    if (result != TLV_OK) *error_offset = base + relative;
    return result;
}

} // namespace cli
