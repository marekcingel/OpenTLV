// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include <vector>
#include <algorithm>
#include "commands/support.hpp"
#include <cstring>
#include <iomanip>
#include <ios>
#include <iostream>
#include "console_color.hpp"
#include "tlv/config.h"
#include "tlv/formats/fixed.h"
#if OPENTLV_NFC
#include "tlv++/builtins/nfc/type2.hpp"
#endif
#if OPENTLV_EMV
#include "tlv++/builtins/emv/format.hpp"
#endif
#if OPENTLV_BLUETOOTH
#include "tlv++/builtins/bluetooth/ltv.hpp"
#endif
#if OPENTLV_FORMAT_BER
#include "tlv++/builtins/asn1/ber.hpp"
#endif
#if OPENTLV_FORMAT_DER
#include "tlv++/builtins/asn1/der.hpp"
#include "tlv/builtins/asn1/der_validation.h"
#endif

namespace cli {

bool is_json(const options& o) {
    return !strcmp(o.output, "json");
}

format_selection::format_selection(const options& o) : name_(o.format) {
    if (!name_ || strcmp(name_, "fixed")) return;
    fixed_.identifier.size = o.fixed_tag_size;
    fixed_.length.size = o.fixed_length_size;
    fixed_.length.byte_order = !strcmp(o.fixed_byte_order, "little") ? TLV_BYTE_ORDER_LITTLE_ENDIAN
                                                                     : TLV_BYTE_ORDER_BIG_ENDIAN;
    fixed_.element_order = TLV_ELEMENT_ORDER_TLV;
    fixed_.length_scope = TLV_LENGTH_SCOPE_VALUE;
    result_ = tlv_fixed_format_init(&descriptor_, &fixed_);
}

tlv::expected<tlv::format, tlv::error> format_selection::get() const {
    if (result_ != TLV_OK) return tlv::unexpected<tlv::error>(tlv::error::from_c(result_));
    if (name_) {
        if (!strcmp(name_, "fixed")) return tlv::native::borrow_format(descriptor_);
#if OPENTLV_EMV
        if (!strcmp(name_, "emv")) return tlv::emv::format{};
#endif
#if OPENTLV_FORMAT_BER
        if (!strcmp(name_, "ber")) return tlv::ber::format{};
#endif
#if OPENTLV_FORMAT_DER
        if (!strcmp(name_, "der")) return tlv::der::format{};
#endif
#if OPENTLV_BLUETOOTH
        if (!strcmp(name_, "bluetooth-ltv")) return tlv::bluetooth::format{};
#endif
#if OPENTLV_NFC
        if (!strcmp(name_, "nfc-type2")) return tlv::nfc::format{};
#endif
    }
    return tlv::unexpected<tlv::error>(tlv::error::from_c(TLV_ERR_INVALID_ARG));
}

void print_hex(const uint8_t* data, std::size_t length) {
    const std::ios::fmtflags saved = std::cout.flags();
    const char               fill = std::cout.fill('0');
    std::cout << std::hex << std::uppercase;
    for (std::size_t i = 0; i < length; ++i) std::cout << std::setw(2) << (unsigned)data[i];
    std::cout.fill(fill);
    std::cout.flags(saved);
}

void print_hex(tlv::bytes bytes) {
    print_hex(reinterpret_cast<const uint8_t*>(bytes.data()), bytes.size());
}

void print_tag(tlv::tag tag, bool color) {
    console_color scope(std::cout, color);
    print_hex(tag.as_bytes());
}

std::string hex_string(tlv::bytes bytes) {
    return hex_string(reinterpret_cast<const uint8_t*>(bytes.data()), bytes.size());
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

tlv_result_t visit_slice(const traversal_env& env, const uint8_t* slice, std::size_t slice_size,
                         std::size_t base, std::size_t max_elements, tlv_tree_visitor_t visitor,
                         void* context, std::size_t* error_offset,
                         tlv_reader_diagnostic_t* diagnostic) {
    const options& o = *env.options;
    std::size_t    relative = 0;
    tlv_result_t   result;
#if OPENTLV_FORMAT_DER
    if (env.is_der) {
        tlv_der_limits_t limits = {o.max_depth, o.max_input, o.max_input, max_elements};
        result = tlv_der_visit(slice, slice_size, &limits, visitor, context, &relative);
    } else
#endif
    {
        std::vector<tlv::tree_frame> frames(std::min(o.max_depth, slice_size));
        tlv::tree_reader reader({reinterpret_cast<const tlv::byte*>(slice), slice_size},
                                tlv::native::borrow_format(*env.format),
                                {frames.data(), frames.size()}, o.max_depth, max_elements);
        // Native adapters are confined to the existing protocol/rendering boundary.
        auto status = visitor
                          ? reader.visit(
                                [&](const tlv::element_view& element, size_t depth, size_t offset) {
                                    const auto native = tlv::native::descriptor(element);
                                    return visitor(&native, depth, offset, context);
                                },
                                &relative, diagnostic)
                          : reader.validate(&relative, diagnostic);
        result = status ? TLV_OK : status.error().code;
        if (result != TLV_OK && diagnostic && diagnostic->diagnostic.code != TLV_OK) {
            if (diagnostic->diagnostic.has_offset) diagnostic->diagnostic.offset += base;
            if (diagnostic->has_tag_offset) diagnostic->tag_offset += base;
            if (diagnostic->has_length_offset) diagnostic->length_offset += base;
            if (diagnostic->has_value_offset) diagnostic->value_offset += base;
            if (diagnostic->has_enclosing_end) diagnostic->enclosing_end += base;
        }
    }
    if (result != TLV_OK) *error_offset = base + relative;
    return result;
}

} // namespace cli
