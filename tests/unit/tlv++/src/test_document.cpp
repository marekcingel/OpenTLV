#include "controlled_format.h"
#include "tlv++/document/document.hpp"

#include <gtest/gtest.h>

#include <vector>

namespace {

using Bytes = std::vector<tlv::byte>;

Bytes make(std::initializer_list<int> values) {
    Bytes out;
    for (int value : values) out.push_back(static_cast<tlv::byte>(value));
    return out;
}

tlv::bytes view(const Bytes& data) {
    return tlv::bytes(data.data(), data.size());
}

// 6F, A5 and A6 hold nested elements.
int is_constructed(const void*, const tlv_tag_t* tag) {
    return tag->size == 1 && (tag->data[0] == 0x6F || tag->data[0] == 0xA5 || tag->data[0] == 0xA6);
}

tlv::document_format format() {
    return tlv::document_format(controlled::reader, controlled::writer, is_constructed);
}

// 6F { 84 (AA BB), A5 { 50 (41 42) } }, 50 (FF)
const Bytes sample = make(
    {0x6F, 0x0A, 0x84, 0x02, 0xAA, 0xBB, 0xA5, 0x04, 0x50, 0x02, 0x41, 0x42, 0x50, 0x01, 0xFF});

} // namespace

TEST(Unit_TLV_CPP_Document, ParsesInspectsAndEncodesAgain) {
    auto parsed = tlv::document::parse(view(sample), format());
    ASSERT_TRUE(parsed.has_value());
    tlv::document doc = std::move(*parsed);

    EXPECT_EQ(5u, doc.size());
    EXPECT_FALSE(doc.empty());

    tlv::node outer = doc.find(TLV_TAG(0x6F));
    ASSERT_TRUE(static_cast<bool>(outer));
    EXPECT_TRUE(outer.is_constructed());
    EXPECT_EQ(doc.first(), outer);

    std::vector<int> child_tags;
    for (tlv::node child : tlv::node_range(outer.first_child())) {
        child_tags.push_back(child.tag().data[0]);
    }
    EXPECT_EQ((std::vector<int>{0x84, 0xA5}), child_tags);

    tlv::node primitive = outer.find(TLV_TAG(0x84));
    ASSERT_TRUE(static_cast<bool>(primitive));
    EXPECT_EQ(2u, primitive.value().size());
    EXPECT_EQ(outer, primitive.parent());
    EXPECT_FALSE(outer.find(TLV_TAG(0x99)));

    auto path = tlv::query::parse("6F/A5/50");
    ASSERT_TRUE(path.has_value());
    tlv::node leaf = doc.find(*path);
    ASSERT_TRUE(static_cast<bool>(leaf));
    EXPECT_EQ(2u, leaf.value().size());

    auto encoded = doc.encode();
    ASSERT_TRUE(encoded.has_value());
    EXPECT_EQ(sample, *encoded);
    EXPECT_EQ(sample.size(), *doc.encoded_size());
}

TEST(Unit_TLV_CPP_Document, SetInsertAndEraseAsInTheIssueExample) {
    auto parsed = tlv::document::parse(view(sample), format());
    ASSERT_TRUE(parsed.has_value());
    tlv::document doc = std::move(*parsed);

    tlv::node entry = doc.find(TLV_TAG(0x50));
    ASSERT_TRUE(static_cast<bool>(entry));
    const Bytes replacement = make({1, 2, 3});
    ASSERT_TRUE(entry.set(view(replacement)).has_value());

    const Bytes payload = make({0xDE, 0xAD});
    auto        inserted = doc.insert(TLV_TAG(0x51), view(payload));
    ASSERT_TRUE(inserted.has_value());
    EXPECT_EQ(2u, inserted->value().size());

    EXPECT_TRUE(doc.erase(TLV_TAG(0x6F)));
    EXPECT_FALSE(doc.erase(TLV_TAG(0x6F)));

    auto encoded = doc.encode();
    ASSERT_TRUE(encoded.has_value());
    EXPECT_EQ(make({0x50, 0x03, 1, 2, 3, 0x51, 0x02, 0xDE, 0xAD}), *encoded);
    EXPECT_EQ(2u, doc.size());
}

TEST(Unit_TLV_CPP_Document, InsertsIntoConstructedElementsBeforeASibling) {
    auto parsed = tlv::document::parse(view(sample), format());
    ASSERT_TRUE(parsed.has_value());
    tlv::document doc = std::move(*parsed);

    tlv::node   outer = doc.first();
    const Bytes payload = make({0x01});
    auto        inserted = doc.insert(TLV_TAG(0x53), view(payload), outer, outer.first_child());
    ASSERT_TRUE(inserted.has_value());
    EXPECT_EQ(outer.first_child(), *inserted);
    EXPECT_EQ(make({0x6F, 0x0D, 0x53, 0x01, 0x01, 0x84, 0x02, 0xAA, 0xBB, 0xA5, 0x04, 0x50, 0x02,
                    0x41, 0x42, 0x50, 0x01, 0xFF}),
              *doc.encode());

    // A primitive parent is refused and nothing changes.
    auto refused = doc.insert(TLV_TAG(0x50), view(payload), outer.first_child());
    ASSERT_FALSE(refused.has_value());
    EXPECT_EQ(TLV_ERR_INVALID_ARG, refused.error().code);
    EXPECT_EQ(6u, doc.size());
}

TEST(Unit_TLV_CPP_Document, ReportsErrorsAndKeepsTheDocumentUnchanged) {
    auto parsed = tlv::document::parse(view(sample), format());
    ASSERT_TRUE(parsed.has_value());
    tlv::document doc = std::move(*parsed);

    tlv::node   inner = doc.find(*tlv::query::parse("6F/A5"));
    const Bytes malformed = make({0x50, 0x09});
    auto        result = inner.set(view(malformed));
    ASSERT_FALSE(result.has_value());
    EXPECT_NE(TLV_OK, result.error().code);
    EXPECT_EQ(sample, *doc.encode());

    size_t offset = 0;
    auto   broken = tlv::document::parse(view(make({0x50, 0x00, 0x50, 0x05})), format(), &offset);
    ASSERT_FALSE(broken.has_value());
    EXPECT_EQ(2u, offset);

    tlv::document_format limited = format();
    limited.max_elements = 2;
    auto limited_parse = tlv::document::parse(view(sample), limited);
    ASSERT_FALSE(limited_parse.has_value());
    EXPECT_EQ(TLV_ERR_LIMIT, limited_parse.error().code);
}

TEST(Unit_TLV_CPP_Document, MovedDocumentKeepsHandlesValid) {
    auto created = tlv::document::create(format());
    ASSERT_TRUE(created.has_value());
    tlv::document doc = std::move(*created);
    EXPECT_TRUE(doc.empty());

    auto container = doc.insert(TLV_TAG(0x6F), tlv::bytes());
    ASSERT_TRUE(container.has_value());
    const Bytes payload = make({0x0A});
    ASSERT_TRUE(doc.insert(TLV_TAG(0x50), view(payload), *container).has_value());

    tlv::document moved(std::move(doc));
    EXPECT_EQ(1u, container->first_child().value().size());
    EXPECT_EQ(make({0x6F, 0x03, 0x50, 0x01, 0x0A}), *moved.encode());

    // A single node can be encoded on its own, and an erased handle turns empty.
    EXPECT_EQ(make({0x50, 0x01, 0x0A}), *container->first_child().encode());
    tlv::node child = container->first_child();
    child.erase();
    EXPECT_FALSE(static_cast<bool>(child));
    EXPECT_EQ(make({0x6F, 0x00}), *moved.encode());
}

TEST(Unit_TLV_CPP_Document, RejectsUnusableFormats) {
    tlv::document_format broken = format();
    broken.reader.read_tag = nullptr;
    auto created = tlv::document::create(broken);
    ASSERT_FALSE(created.has_value());
    EXPECT_EQ(TLV_ERR_NULL_ARG, created.error().code);
}
