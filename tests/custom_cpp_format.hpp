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
            return failure(TLV_ERR_BUFFER_TOO_SHORT, TLV_REGION_HEADER, data.size(), 2);
        const size_t length = static_cast<unsigned char>(data[1]);
        const size_t total = length + 3;
        if (data.size() < total)
            return failure(TLV_ERR_BUFFER_TOO_SHORT, TLV_REGION_TRAILER, data.size(), total);
        if (static_cast<unsigned char>(data[total - 1]) != trailer)
            return failure(TLV_ERR_INVALID_VALUE, TLV_REGION_TRAILER, total - 1, total);
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
                tlv::format_failure(TLV_ERR_INVALID_TAG_SIZE));
        if (value.value_size > 255)
            return tlv::unexpected<tlv::format_failure>(
                tlv::format_failure(TLV_ERR_INVALID_LENGTH));
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
                tlv::format_failure(TLV_ERR_BUFFER_TOO_SHORT));
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
    static tlv::unexpected<tlv::format_failure> failure(tlv_result_t code, tlv_region_t region,
                                                        size_t offset, size_t required) noexcept {
        tlv_format_error_t detail{};
        detail.region = region;
        detail.offset = offset;
        detail.has_offset = 1;
        detail.required = required;
        detail.has_required = 1;
        return tlv::unexpected<tlv::format_failure>(tlv::format_failure(code, detail));
    }
};
#endif
