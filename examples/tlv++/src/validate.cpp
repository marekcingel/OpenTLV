// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

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

static const tlv::schema_storage<1>
    proprietary_schema({{tlv::tag_bytes<0x50>(), tlv::bounds::exactly(1), tlv::bounds::exactly(1),
                         tlv::schema_kind::primitive}});
static const tlv::schema_storage<2> fci_schema({{tlv::tag_bytes<0x84>(),
                                                 {1, 16},
                                                 tlv::bounds::exactly(1),
                                                 tlv::schema_kind::primitive,
                                                 {},
                                                 "df_name"},
                                                {tlv::tag_bytes<0xA5>(),
                                                 {},
                                                 tlv::bounds::exactly(1),
                                                 tlv::schema_kind::constructed,
                                                 proprietary_schema.view()}});
static const tlv::schema_storage<1> top_schema({{tlv::tag_bytes<0x6F>(),
                                                 {},
                                                 tlv::bounds::exactly(1),
                                                 tlv::schema_kind::constructed,
                                                 fci_schema.view()}});

int main() {
    auto ok = tlv::validate(tlv::bytes(document.data(), document.size()), tlv::ber::format{},
                            top_schema.view(), 64, 16);
    if (!ok) {
        std::cerr << "unexpected: " << ok.error().message() << "\n";
        return 1;
    }
    std::cout << "Document conforms to the schema\n";

    auto rejected = tlv::validate(tlv::bytes(incomplete.data(), incomplete.size()),
                                  tlv::ber::format{}, top_schema.view(), 64, 16);
    if (rejected || rejected.error().status() != tlv::errc::schema) {
        std::cerr << "expected a missing-field error\n";
        return 1;
    }
    std::cout << "Incomplete document rejected: " << rejected.error().message() << "\n";
    return 0;
}
