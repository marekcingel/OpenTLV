#include <array>
#include <cstring>

#include "tlv++/tlv.hpp"
#include "tlv++/formats/fixed_format.hpp"

int main() {
    using format = tlv::fixed_format<1, 1, TLV_BYTE_ORDER_BIG_ENDIAN>;

    const tlv::tag                 tag = tlv::tag_bytes<0x01>();
    const std::array<tlv::byte, 3> value = {
        static_cast<tlv::byte>(0xAA), static_cast<tlv::byte>(0xBB), static_cast<tlv::byte>(0xCC)};
    std::array<tlv::byte, 5> buffer{};
    tlv::writer              writer(buffer.data(), buffer.size(), format::format());

    if (!writer.write(tag, tlv::bytes(value.data(), value.size()))) return 1;

    // element.value() borrows buffer; keep it alive while using the element.
    tlv::reader reader(tlv::bytes(buffer.data(), writer.size()), format::format());
    auto        element = reader.next();
    if (!element || !reader.at_end()) return 1;

    if (element->tag() != tlv::tag_bytes<0x01>()) return 1;
    if (element->value().size() != value.size() ||
        std::memcmp(element->value().data(), value.data(), value.size()) != 0)
        return 1;
    return 0;
}
