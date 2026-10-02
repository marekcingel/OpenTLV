// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/definition.h"
#include <gtest/gtest.h>
#include <string>
#include <vector>

TEST(Unit_Tlv_Definition, CallerOwnedRegistriesScopeMeaningAndNamesAreNotKeys) {
    const std::vector<uint8_t>      keys{0x80, 0x81};
    const std::string               first_name = "same label";
    const std::string               other_name = "other context";
    const tlv_definition_t          first[] = {{{keys.data(), 1}, first_name.c_str()},
                                               {{keys.data() + 1, 1}, first_name.c_str()}};
    const tlv_definition_t          second[] = {{{keys.data(), 1}, other_name.c_str()}};
    const tlv_definition_registry_t first_registry = {first, 2};
    const tlv_definition_registry_t second_registry = {second, 1};
    const auto                      key = TLV_TAG(0x80);
    const auto                      other_key = TLV_TAG(0x81);
    ASSERT_EQ(first, tlv_definition_find(&first_registry, &key));
    ASSERT_EQ(second, tlv_definition_find(&second_registry, &key));
    EXPECT_EQ(first + 1, tlv_definition_find(&first_registry, &other_key));
    EXPECT_EQ(nullptr, tlv_definition_find(&second_registry, &other_key));
    EXPECT_STREQ("same label", tlv_definition_find(&first_registry, &key)->name);
    EXPECT_STREQ("other context", tlv_definition_find(&second_registry, &key)->name);
}

TEST(Unit_Tlv_Definition, MatchesBytesAndSizeAndReturnsFirstBorrowedEntry) {
    const uint8_t                   bytes[] = {0x01, 0x02};
    const tlv_definition_t          entries[] = {{{nullptr, 1}, "invalid"},
                                                 {{bytes, 2}, "pair"},
                                                 {{bytes, 1}, "first"},
                                                 {{bytes, 1}, "duplicate"},
                                                 {{nullptr, 0}, nullptr}};
    const tlv_definition_registry_t registry = {entries, 5};
    const auto                      one = TLV_TAG(0x01);
    const auto                      pair = TLV_TAG(0x01, 0x02);
    const auto                      reversed = TLV_TAG(0x02, 0x01);
    const auto                      empty = tlv_tag(nullptr, 0);
    EXPECT_EQ(entries + 2, tlv_definition_find(&registry, &one));
    EXPECT_EQ(entries + 1, tlv_definition_find(&registry, &pair));
    EXPECT_EQ(nullptr, tlv_definition_find(&registry, &reversed));
    EXPECT_EQ(entries + 4, tlv_definition_find(&registry, &empty));
}

TEST(Unit_Tlv_Definition, HandlesMissingAndInvalidArguments) {
    const auto                      tag = TLV_TAG(0x01);
    const auto                      invalid = tlv_tag(nullptr, 1);
    const tlv_definition_t          entry = {tag, "one"};
    const tlv_definition_registry_t registry = {&entry, 1};
    const tlv_definition_registry_t empty = {nullptr, 0};
    const tlv_definition_registry_t malformed = {nullptr, 1};
    EXPECT_EQ(nullptr, tlv_definition_find(nullptr, &tag));
    EXPECT_EQ(nullptr, tlv_definition_find(&registry, nullptr));
    EXPECT_EQ(nullptr, tlv_definition_find(&registry, &invalid));
    EXPECT_EQ(nullptr, tlv_definition_find(&empty, &tag));
    EXPECT_EQ(nullptr, tlv_definition_find(&malformed, &tag));
}
