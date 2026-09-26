#include <array>
#include <cstring>

#include "tlv++/tlv.hpp"
#include "tlv++/builtins/fixed/fixed_format.hpp"

int main() {
    using format = tlv::fixed_format<1, 1, TLV_BYTE_ORDER_BIG_ENDIAN>;

    const tlv::tag_t               tag = TLV_TAG(0x01);
    const std::array<tlv::byte, 3> value = {
        static_cast<tlv::byte>(0xAA), static_cast<tlv::byte>(0xBB), static_cast<tlv::byte>(0xCC)};
    std::array<tlv::byte, 5> buffer{};
    tlv::writer              writer(buffer.data(), buffer.size(), format::writer());

    if (!writer.write(tag, tlv::bytes(value.data(), value.size()))) return 1;

    // entry.value borrows buffer; keep it alive while using the entry.
    tlv::reader reader(tlv::bytes(buffer.data(), writer.size()), format::reader());
    auto        entry = reader.next();
    if (!entry || !reader.at_end()) return 1;

    if (entry->tag.size != 1 || entry->tag.data[0] != 0x01) return 1;
    if (entry->value.size() != value.size() ||
        std::memcmp(entry->value.data(), value.data(), value.size()) != 0)
        return 1;
    return 0;
}
