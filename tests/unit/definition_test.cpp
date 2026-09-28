#include "tlv/definition.h"
#include <gtest/gtest.h>

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
