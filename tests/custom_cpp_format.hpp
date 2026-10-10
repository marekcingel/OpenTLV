// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_TEST_CUSTOM_CPP_FORMAT_HPP
#define OPENTLV_TEST_CUSTOM_CPP_FORMAT_HPP
#include "tlv++/format.hpp"
#include <cstring>

// Independent application Format: one-byte Tag/Length and a required trailer.
// High-bit Tags contain elements using the same Format. No C descriptor or
// built-in framing callback is used by this implementation.
struct custom_cpp_format {
    unsigned char                                    trailer = 0xA5;
    tlv::expected<tlv::decoded, tlv::format_failure> decode(tlv::bytes data) const noexcept {
        if (data.size() < 2)
            return failure(tlv::errc::truncated, tlv::wire_region::header, data.size(), 2);
        const size_t length = static_cast<unsigned char>(data[1]);
        const size_t total = length + 3;
        if (data.size() < total)
            return failure(tlv::errc::truncated, tlv::wire_region::trailer, data.size(), total);
        if (static_cast<unsigned char>(data[total - 1]) != trailer)
            return failure(tlv::errc::invalid_value, tlv::wire_region::trailer, total - 1, total);
        tlv::source source{};
        source.size = total;
        source.header = {0, 2, 1};
        source.tag = {0, 1, 1};
        source.length = {1, 1, 1};
        source.value = {2, length, 1};
        source.trailer = {2 + length, 1, 1};
        return tlv::decoded{tlv::element_view(tlv::tag(tlv::bytes(data.data(), 1)),
                                              tlv::value_view(tlv::bytes(data.data() + 2, length))),
                            source};
    }
    tlv::expected<tlv::encoding, tlv::format_failure>
    measure(const tlv::measure_request& value) const noexcept {
        if (value.identifier.size() != 1)
            return tlv::unexpected<tlv::format_failure>(
                tlv::format_failure(tlv::errc::invalid_tag_size));
        if (value.value_size > 255)
            return tlv::unexpected<tlv::format_failure>(
                tlv::format_failure(tlv::errc::invalid_length));
        const auto size = value.value_size;
        return tlv::encoding{2, size, 1, size + 3};
    }
    tlv::expected<size_t, tlv::format_failure> encode(const tlv::element_view& value,
                                                      tlv::span<tlv::byte> data) const noexcept {
        auto size = measure(
            tlv::measure_request{value.tag(), value.value().size(), value.value().as_bytes()});
        if (!size) return tlv::unexpected<tlv::format_failure>(size.error());
        if (data.size() < size->total)
            return tlv::unexpected<tlv::format_failure>(
                tlv::format_failure(tlv::errc::buffer_too_short));
        data[0] = value.tag()[0];
        data[1] = static_cast<tlv::byte>(value.value().size());
        if (!value.value().empty())
            std::memcpy(data.data() + 2, value.value().data(), value.value().size());
        data[2 + value.value().size()] = static_cast<tlv::byte>(trailer);
        return value.value().size() + 3;
    }
    bool is_constructed(tlv::tag id) const noexcept {
        return id.size() == 1 && (static_cast<unsigned char>(id[0]) & 0x80) != 0;
    }

private:
    static tlv::unexpected<tlv::format_failure> failure(tlv::errc code, tlv::wire_region region,
                                                        size_t offset, size_t required) noexcept {
        return tlv::unexpected<tlv::format_failure>(
            tlv::format_failure(code).at(region, offset, required));
    }
};
#endif
