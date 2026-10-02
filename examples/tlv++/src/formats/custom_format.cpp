// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv++/tlv.hpp"
#include <cstring>

// Application framing: one-byte Tag, two-byte little-endian Length, opaque Value.
struct my_format {
    tlv::expected<tlv::decoded, tlv::format_failure> decode(tlv::bytes data) const noexcept {
        if (data.size() < 3) return fail(TLV_ERR_BUFFER_TOO_SHORT);
        const size_t length = static_cast<unsigned char>(data[1]) |
                              (static_cast<size_t>(static_cast<unsigned char>(data[2])) << 8);
        if (length > data.size() - 3) return fail(TLV_ERR_BUFFER_TOO_SHORT);
        tlv::source source{};
        source.size = length + 3;
        source.header = {0, 3, 1};
        source.tag = {0, 1, 1};
        source.length = {1, 2, 1};
        source.value = {3, length, 1};
        source.trailer = {3 + length, 0, 1};
        return tlv::decoded{tlv::element_view(tlv::tag(tlv::bytes(data.data(), 1)),
                                              tlv::value_view(tlv::bytes(data.data() + 3, length))),
                            source};
    }
    tlv::expected<tlv::encoding, tlv::format_failure>
    measure(const tlv::measure_request& value) const noexcept {
        if (value.identifier.size() != 1) return fail(TLV_ERR_INVALID_TAG_SIZE);
        if (value.value_size > 65535) return fail(TLV_ERR_INVALID_LENGTH);
        return tlv::encoding{3, value.value_size, 0, value.value_size + 3};
    }
    tlv::expected<size_t, tlv::format_failure> encode(const tlv::element_view& value,
                                                      tlv::span<tlv::byte> output) const noexcept {
        auto size = measure({value.tag(), value.value().size(), value.value().as_bytes()});
        if (!size) return tlv::unexpected<tlv::format_failure>(size.error());
        if (output.size() < size->total) return fail(TLV_ERR_BUFFER_TOO_SHORT);
        output[0] = value.tag()[0];
        output[1] = static_cast<tlv::byte>(value.value().size() & 0xFF);
        output[2] = static_cast<tlv::byte>(value.value().size() >> 8);
        if (!value.value().empty())
            std::memcpy(output.data() + 3, value.value().data(), value.value().size());
        return value.value().size() + 3;
    }

private:
    static tlv::unexpected<tlv::format_failure> fail(tlv_result_t code) noexcept {
        return tlv::unexpected<tlv::format_failure>(tlv::format_failure(code));
    }
};

int main() {
    const unsigned char    expected[] = {0x09, 0x02, 0x00, 0x41, 0x42};
    const tlv::bytes       input(reinterpret_cast<const tlv::byte*>(expected), sizeof(expected));
    tlv::byte              output[5]{};
    tlv::writer<my_format> writer(output, sizeof(output));
    try {
        for (auto element : tlv::parse<my_format>(input)) {
            if (element.tag() != tlv::tag_bytes<0x09>() || element.value().size() != 2) return 1;
            if (!writer.write(element)) return 2;
        }
    } catch (const tlv::parse_error&) {
        return 1;
    }
    if (writer.size() != sizeof(expected)) return 2;
    return std::memcmp(output, expected, sizeof(expected)) == 0 ? 0 : 3;
}
