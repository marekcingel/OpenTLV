#include <array>
#include <cstring>

#include "tlv++/tlv.hpp"
#include "tlv/formats/fixed/fixed_1byte.h"

int main() {
    const tlv::tag_t               tag = TLV_TAG(0x01);
    const std::array<tlv::byte, 3> value = {
        static_cast<tlv::byte>(0xAA), static_cast<tlv::byte>(0xBB), static_cast<tlv::byte>(0xCC)};
    std::array<tlv::byte, 5> buffer{};
    tlv::writer              writer(buffer.data(), buffer.size(), tlv_writer_format_fixed_1byte);

    if (!writer.write(tag, tlv::bytes(value.data(), value.size()))) return 1;

    // entry.value borrows buffer; keep it alive while using the entry.
    tlv::reader reader(tlv::bytes(buffer.data(), writer.size()), tlv_reader_format_fixed_1byte);
    auto        entry = reader.next();
    if (!entry || !reader.at_end()) return 1;

    if (entry->tag.size != 1 || entry->tag.data[0] != 0x01) return 1;
    if (entry->value.size() != value.size() ||
        std::memcmp(entry->value.data(), value.data(), value.size()) != 0)
        return 1;
    return 0;
}
