#include "commands/support.hpp"
#include <cstring>
#include <iomanip>
#include <ios>
#include <iostream>
#include "console_color.hpp"
#include "tlv/config.h"
#include "tlv++/reader/walker.hpp"
#if OPENTLV_FORMAT_DER
#include "tlv/builtins/asn1/der_profile.h"
#endif

namespace cli {

bool is_json(const options& o) {
    return !strcmp(o.output, "json");
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
            env.predicate, o.max_depth, max_elements,
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
