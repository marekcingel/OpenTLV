// Checks a document's structure -- which tags are required, how many times,
// in what nesting, and with what value lengths -- without decoding it. See
// parse.cpp for the document this schema describes.
#include <array>
#include <cstdint>
#include <iostream>

#include "tlv++/tlv.hpp"

// Same bytes as parse.cpp's document.
static const std::array<tlv::byte, 12> document = {
    tlv::byte(0x6F), tlv::byte(0x0A), tlv::byte(0x84), tlv::byte(0x03),
    tlv::byte(0x41), tlv::byte(0x42), tlv::byte(0x43), tlv::byte(0xA5),
    tlv::byte(0x03), tlv::byte(0x50), tlv::byte(0x01), tlv::byte(0x01)};
// Missing the FCI Proprietary Template (A5) the schema requires.
static const std::array<tlv::byte, 7> incomplete = {
    tlv::byte(0x6F), tlv::byte(0x05), tlv::byte(0x84), tlv::byte(0x03),
    tlv::byte(0x41), tlv::byte(0x42), tlv::byte(0x43)};

static const uint8_t              application_label_tag[] = {0x50};
static const tlv_structure_rule_t proprietary_rules[] = {
    {{{application_label_tag, 1}, 1, 1, 0, nullptr}, 1, 1, TLV_SCHEMA_PRIMITIVE, nullptr, 0}};
static const tlv_structure_schema_t proprietary_schema = {proprietary_rules,   1, 0, nullptr, 0,
                                                          TLV_SCHEMA_ORDER_ANY};

static const uint8_t              df_name_tag[] = {0x84};
static const uint8_t              proprietary_tag[] = {0xA5};
static const tlv_structure_rule_t fci_rules[] = {
    {{{df_name_tag, 1}, 1, 16, 0, "df_name"}, 1, 1, TLV_SCHEMA_PRIMITIVE, nullptr, 0},
    {{{proprietary_tag, 1}, 0, SIZE_MAX, 0, nullptr},
     1,
     1,
     TLV_SCHEMA_CONSTRUCTED,
     &proprietary_schema,
     0}};
static const tlv_structure_schema_t fci_schema = {fci_rules, 2, 0,
                                                  nullptr,   0, TLV_SCHEMA_ORDER_ANY};

static const uint8_t              fci_tag[] = {0x6F};
static const tlv_structure_rule_t top_rules[] = {
    {{{fci_tag, 1}, 0, SIZE_MAX, 0, nullptr}, 1, 1, TLV_SCHEMA_CONSTRUCTED, &fci_schema, 0}};
static const tlv_structure_schema_t top_schema = {top_rules, 1, 0,
                                                  nullptr,   0, TLV_SCHEMA_ORDER_ANY};

int main() {
    auto ok = tlv::validate(tlv::bytes(document.data(), document.size()), tlv_reader_format_ber,
                            tlv_ber_is_constructed, top_schema, TLV_WALK_MAX_DEPTH, 16);
    if (!ok) {
        std::cerr << "unexpected: " << ok.error().message << "\n";
        return 1;
    }
    std::cout << "Document conforms to the schema\n";

    auto rejected =
        tlv::validate(tlv::bytes(incomplete.data(), incomplete.size()), tlv_reader_format_ber,
                      tlv_ber_is_constructed, top_schema, TLV_WALK_MAX_DEPTH, 16);
    if (rejected || rejected.error().code != TLV_ERR_SCHEMA_MISSING) {
        std::cerr << "expected a missing-field error\n";
        return 1;
    }
    std::cout << "Incomplete document rejected: " << rejected.error().message << "\n";
    return 0;
}
