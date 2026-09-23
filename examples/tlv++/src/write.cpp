// Builds the same nested BER-TLV document parse.cpp reads, encoding the
// innermost elements first and using each encoded result as the next
// level's value: the standard way to build constructed TLV bottom-up.
#include <array>
#include <cstring>
#include <iostream>

#include "tlv++/tlv.hpp"

// Same bytes as parse.cpp's document.
static const std::array<tlv::byte, 12> expected = {
    tlv::byte(0x6F), tlv::byte(0x0A), tlv::byte(0x84), tlv::byte(0x03),
    tlv::byte(0x41), tlv::byte(0x42), tlv::byte(0x43), tlv::byte(0xA5),
    tlv::byte(0x03), tlv::byte(0x50), tlv::byte(0x01), tlv::byte(0x01)};

int main() {
    std::array<tlv::byte, 5>  df_name_buf{};
    std::array<tlv::byte, 3>  application_label_buf{};
    std::array<tlv::byte, 8>  proprietary_buf{};
    std::array<tlv::byte, 16> value_buf{};
    std::array<tlv::byte, 20> document_buf{};

    tlv::writer df_name_writer(df_name_buf.data(), df_name_buf.size(), tlv_writer_format_ber);
    auto        df_name_result = df_name_writer.write(
        TLV_TAG(0x84), tlv::bytes(reinterpret_cast<const tlv::byte*>("ABC"), 3));
    if (!df_name_result) {
        std::cerr << "write error: " << df_name_result.error().message << "\n";
        return 1;
    }

    const tlv::byte application_label = tlv::byte(0x01);
    tlv::writer application_label_writer(application_label_buf.data(), application_label_buf.size(),
                                         tlv_writer_format_ber);
    auto        label_result =
        application_label_writer.write(TLV_TAG(0x50), tlv::bytes(&application_label, 1));
    if (!label_result) {
        std::cerr << "write error: " << label_result.error().message << "\n";
        return 1;
    }

    tlv::writer proprietary_writer(proprietary_buf.data(), proprietary_buf.size(),
                                   tlv_writer_format_ber);
    auto        proprietary_result = proprietary_writer.write(
        TLV_TAG(0xA5), tlv::bytes(application_label_buf.data(), application_label_writer.size()));
    if (!proprietary_result) {
        std::cerr << "write error: " << proprietary_result.error().message << "\n";
        return 1;
    }

    std::memcpy(value_buf.data(), df_name_buf.data(), df_name_writer.size());
    std::memcpy(value_buf.data() + df_name_writer.size(), proprietary_buf.data(),
                proprietary_writer.size());
    const size_t value_size = df_name_writer.size() + proprietary_writer.size();

    tlv::writer document_writer(document_buf.data(), document_buf.size(), tlv_writer_format_ber);
    auto        document_result =
        document_writer.write(TLV_TAG(0x6F), tlv::bytes(value_buf.data(), value_size));
    if (!document_result) {
        std::cerr << "write error: " << document_result.error().message << "\n";
        return 1;
    }

    std::cout << "Wrote " << document_writer.size() << " bytes\n";
    return document_writer.size() == expected.size() &&
                   std::memcmp(document_buf.data(), expected.data(), expected.size()) == 0
               ? 0
               : 1;
}
