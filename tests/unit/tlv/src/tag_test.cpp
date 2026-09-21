#include "tlv/tag.h"
#include <gtest/gtest.h>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

namespace {

std::vector<uint8_t> sequence(size_t size, uint8_t first = 1) {
    std::vector<uint8_t> bytes(size);
    for (size_t i = 0; i < size; ++i) bytes[i] = static_cast<uint8_t>(first + i);
    return bytes;
}

tlv_tag_t view_of(const std::vector<uint8_t>& bytes) {
    return tlv_tag(bytes.empty() ? nullptr : bytes.data(), bytes.size());
}

} // namespace

TEST(Unit_Tag, IsAPointerAndASizeWithNoConfigurableCapacity) {
    struct borrowed {
        const uint8_t* data;
        size_t         size;
    };
    EXPECT_EQ(sizeof(borrowed), sizeof(tlv_tag_t));
    EXPECT_EQ(offsetof(borrowed, data), offsetof(tlv_tag_t, data));
    EXPECT_EQ(offsetof(borrowed, size), offsetof(tlv_tag_t, size));
#ifdef TLV_TAG_CAPACITY
    FAIL() << "TLV_TAG_CAPACITY must not be defined by the library";
#endif
}

TEST(Unit_Tag, ConstructionBorrowsTheGivenBytes) {
    const uint8_t   bytes[] = {0x9F, 0x02};
    const tlv_tag_t tag = tlv_tag(bytes, sizeof(bytes));
    EXPECT_EQ(bytes, tag.data);
    EXPECT_EQ(2u, tag.size);

    const tlv_tag_t empty = tlv_tag(nullptr, 0);
    EXPECT_EQ(nullptr, empty.data);
    EXPECT_EQ(0u, empty.size);
}

TEST(Unit_Tag, LiteralConstructionForSingleAndMultiByteTags) {
    const tlv_tag_t one = TLV_TAG(0x5A);
    ASSERT_EQ(1u, one.size);
    EXPECT_EQ(0x5A, one.data[0]);

    const tlv_tag_t two = TLV_TAG(0x9F, 0x02);
    ASSERT_EQ(2u, two.size);
    EXPECT_EQ(0x9F, two.data[0]);
    EXPECT_EQ(0x02, two.data[1]);

    const tlv_tag_t twelve = TLV_TAG(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12);
    ASSERT_EQ(12u, twelve.size);
    EXPECT_EQ(12, twelve.data[11]);
}

TEST(Unit_Tag, LiteralsCanBeStoredAndCopied) {
    const tlv_tag_t first = TLV_TAG(0xDF, 0x01);
    tlv_tag_t       copy = first;
    // Copying copies only the pointer and the size.
    EXPECT_EQ(first.data, copy.data);
    EXPECT_EQ(first.size, copy.size);
    EXPECT_TRUE(tlv_tag_equal(first, copy));
}

TEST(Unit_Tag, EqualComparesContentsNotPointers) {
    const std::vector<uint8_t> a = {0x9F, 0x02};
    const std::vector<uint8_t> b = {0x9F, 0x02};
    ASSERT_NE(a.data(), b.data());
    EXPECT_TRUE(tlv_tag_equal(view_of(a), view_of(b)));
    EXPECT_TRUE(tlv_tag_equal(view_of(a), view_of(a)));
}

TEST(Unit_Tag, EqualRejectsDifferentBytesAndSizes) {
    EXPECT_FALSE(tlv_tag_equal(TLV_TAG(0x9F, 0x02), TLV_TAG(0x9F, 0x03)));
    EXPECT_FALSE(tlv_tag_equal(TLV_TAG(0x9F, 0x02), TLV_TAG(0x9F)));
    EXPECT_FALSE(tlv_tag_equal(TLV_TAG(0x9F), TLV_TAG(0x9F, 0x00)));
    // Leading zero bytes are part of the tag.
    EXPECT_FALSE(tlv_tag_equal(TLV_TAG(0x00, 0x82), TLV_TAG(0x82)));
    EXPECT_FALSE(tlv_tag_equal(TLV_TAG(0x82), tlv_tag(nullptr, 0)));
}

TEST(Unit_Tag, EqualDetectsADifferenceInTheLastOfManyBytes) {
    const std::vector<uint8_t> a = sequence(40);
    std::vector<uint8_t>       b = a;
    EXPECT_TRUE(tlv_tag_equal(view_of(a), view_of(b)));
    b.back() ^= 0x01;
    EXPECT_FALSE(tlv_tag_equal(view_of(a), view_of(b)));
}

TEST(Unit_Tag, EmptyTags) {
    const uint8_t byte = 0;
    EXPECT_TRUE(tlv_tag_equal(tlv_tag(nullptr, 0), tlv_tag(nullptr, 0)));
    // An empty tag does not depend on its pointer.
    EXPECT_TRUE(tlv_tag_equal(tlv_tag(nullptr, 0), tlv_tag(&byte, 0)));
    EXPECT_EQ(0, tlv_tag_compare(tlv_tag(nullptr, 0), tlv_tag(&byte, 0)));
    EXPECT_LT(tlv_tag_compare(tlv_tag(nullptr, 0), TLV_TAG(0x00)), 0);
    EXPECT_GT(tlv_tag_compare(TLV_TAG(0x00), tlv_tag(nullptr, 0)), 0);
}

TEST(Unit_Tag, EqualAndCompareAgreeOnValidTags) {
    const std::vector<std::vector<uint8_t>> tags = {
        {}, {0x00}, {0x9F}, {0x9F, 0x00}, {0x9F, 0x02}, {0xFF}, sequence(12), sequence(13)};
    for (const auto& a : tags) {
        for (const auto& b : tags) {
            EXPECT_EQ(tlv_tag_equal(view_of(a), view_of(b)),
                      tlv_tag_compare(view_of(a), view_of(b)) == 0);
        }
    }
}

TEST(Unit_Tag, CompareIsLexicographicByBytes) {
    EXPECT_EQ(0, tlv_tag_compare(TLV_TAG(0x9F, 0x02), TLV_TAG(0x9F, 0x02)));
    EXPECT_LT(tlv_tag_compare(TLV_TAG(0x9F, 0x02), TLV_TAG(0x9F, 0x03)), 0);
    EXPECT_GT(tlv_tag_compare(TLV_TAG(0x9F, 0x03), TLV_TAG(0x9F, 0x02)), 0);
    // The first difference decides, whatever follows it.
    EXPECT_LT(tlv_tag_compare(TLV_TAG(0x01, 0xFF, 0xFF), TLV_TAG(0x02, 0x00)), 0);
    // A prefix orders before a longer tag.
    EXPECT_LT(tlv_tag_compare(TLV_TAG(0x9F), TLV_TAG(0x9F, 0x00)), 0);
    EXPECT_GT(tlv_tag_compare(TLV_TAG(0x9F, 0x00), TLV_TAG(0x9F)), 0);
}

TEST(Unit_Tag, CompareTreatsBytesAsUnsigned) {
    EXPECT_LT(tlv_tag_compare(TLV_TAG(0x7F), TLV_TAG(0x80)), 0);
    EXPECT_GT(tlv_tag_compare(TLV_TAG(0xFF), TLV_TAG(0x00)), 0);
}

TEST(Unit_Tag, CompareDoesNotInterpretTheTagAsAnInteger) {
    // As big-endian integers 01 FF < 02 00 and as little-endian integers
    // 01 FF > 02 00; byte order comparison always agrees with the first.
    EXPECT_LT(tlv_tag_compare(TLV_TAG(0x01, 0xFF), TLV_TAG(0x02, 0x00)), 0);
    // A longer tag is not "greater" just because it has more bytes.
    EXPECT_LT(tlv_tag_compare(TLV_TAG(0x01, 0x00, 0x00), TLV_TAG(0x02)), 0);
}

TEST(Unit_Tag, CompareIsAntisymmetricAndBackedByAnyMemory) {
    const std::vector<uint8_t> a = sequence(20);
    std::vector<uint8_t>       b = a;
    EXPECT_EQ(0, tlv_tag_compare(view_of(a), view_of(b)));
    b[19] = 0xFF;
    EXPECT_LT(tlv_tag_compare(view_of(a), view_of(b)), 0);
    EXPECT_GT(tlv_tag_compare(view_of(b), view_of(a)), 0);
}

TEST(Unit_Tag, TagsLongerThanTheFormerDefaultCapacity) {
    for (size_t size :
         {size_t(9), size_t(12), size_t(16), size_t(255), size_t(256), size_t(1000)}) {
        SCOPED_TRACE(size);
        const std::vector<uint8_t> a = sequence(size);
        std::vector<uint8_t>       b = a;
        const tlv_tag_t            tag = view_of(a);
        EXPECT_EQ(size, tag.size);
        EXPECT_TRUE(tlv_tag_equal(tag, view_of(b)));
        EXPECT_EQ(0, tlv_tag_compare(tag, view_of(b)));
        b.back() = static_cast<uint8_t>(b.back() ^ 0x80);
        EXPECT_FALSE(tlv_tag_equal(tag, view_of(b)));
        EXPECT_NE(0, tlv_tag_compare(tag, view_of(b)));
        EXPECT_EQ(tlv_tag_compare(tag, view_of(b)) < 0, tlv_tag_compare(view_of(b), tag) > 0);
    }
}

TEST(Unit_Tag, TwelveByteTagFromRuntimeData) {
    const uint8_t   bytes[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                               0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C};
    const tlv_tag_t tag = tlv_tag(bytes, sizeof(bytes));
    EXPECT_EQ(12u, tag.size);
    EXPECT_EQ(bytes, tag.data);
    EXPECT_TRUE(tlv_tag_equal(tag, TLV_TAG(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12)));
}
