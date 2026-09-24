#include "tlv/config.h"
#if OPENTLV_FORMAT_BER
#include "tlv/builtins/asn1/ber.h"
#endif
#include "tlv/builtins/asn1/cer.h"
#include "tlv/builtins/asn1/cer_profile.h"
#include "tlv/reader/reader.h"
#include <gtest/gtest.h>
#include <cstring>
#include <string>
#include <vector>

namespace {

struct Segment {
    tlv_tag_t      tag;
    const uint8_t* data;
    size_t         length;
};

tlv_visit_result_t collect_segment(const tlv_view_t* view, void* context) {
    static_cast<std::vector<Segment>*>(context)->push_back(
        {view->tag, view->value.data, static_cast<size_t>(view->value.length)});
    return TLV_VISIT_CONTINUE;
}

/* Zero-copy segment iteration over a constructed element's already-borrowed
 * content, per docs/profiles/cer/README.md's documented tlv_walk pattern. */
std::vector<Segment> segments_of(const tlv_view_t& view) {
    std::vector<Segment> result;
    if (view.value.length)
        EXPECT_EQ(TLV_OK, tlv_walk(view.value.data, static_cast<size_t>(view.value.length),
                                   &tlv_reader_format_cer, collect_segment, &result));
    return result;
}

/* Builds canonical CER bytes for logical content via tlv_cer_write_segmented_string. */
std::vector<uint8_t> write_segmented(uint8_t                     primitive_tag_byte,
                                     const std::vector<uint8_t>& content) {
    const tlv_tag_t tag = tlv_tag(&primitive_tag_byte, 1);
    size_t          required = 0, written = 0;
    EXPECT_EQ(TLV_OK, tlv_cer_write_segmented_string(nullptr, 0, tag,
                                                     content.empty() ? nullptr : content.data(),
                                                     content.size(), nullptr, &required, nullptr));
    std::vector<uint8_t> data(required);
    EXPECT_EQ(TLV_OK, tlv_cer_write_segmented_string(data.data(), data.size(), tag,
                                                     content.empty() ? nullptr : content.data(),
                                                     content.size(), nullptr, &written, nullptr));
    EXPECT_EQ(required, written);
    return data;
}

} // namespace

TEST(Unit_Tlv_CerValues, OctetStringSegmentThresholds) {
    for (size_t length : {999u, 1000u, 1001u, 2000u, 2500u, 3000u}) {
        SCOPED_TRACE(length);
        std::vector<uint8_t> content(length);
        for (size_t i = 0; i < length; ++i) content[i] = static_cast<uint8_t>(i);
        const auto data = write_segmented(0x04, content);

        tlv_view_t view{};
        size_t     consumed = 0;
        ASSERT_EQ(TLV_OK, tlv_cer_read_strict(data.data(), data.size(), nullptr, &view, &consumed,
                                              nullptr));
        EXPECT_EQ(data.size(), consumed);
        EXPECT_EQ(length > 1000, static_cast<bool>(tlv_cer_tag_is_constructed(&view.tag)));

        if (length <= 1000) {
            EXPECT_EQ(length, view.value.length);
            EXPECT_EQ(0, std::memcmp(view.value.data, content.data(), length));
            continue;
        }
        const auto segments = segments_of(view);
        size_t     reassembled = 0;
        for (size_t i = 0; i < segments.size(); ++i) {
            const bool final_segment = i + 1 == segments.size();
            EXPECT_EQ(0x04, segments[i].tag.data[0]);
            EXPECT_FALSE(tlv_cer_tag_is_constructed(&segments[i].tag));
            if (!final_segment)
                EXPECT_EQ(1000u, segments[i].length);
            else
                EXPECT_LE(segments[i].length, 1000u);
            EXPECT_GE(segments[i].length, 1u);
            /* Zero-copy: the segment view genuinely borrows the encoded
             * buffer rather than a concatenated/copied one. */
            EXPECT_GE(segments[i].data, data.data());
            EXPECT_LE(segments[i].data + segments[i].length, data.data() + data.size());
            EXPECT_EQ(
                0, std::memcmp(segments[i].data, content.data() + reassembled, segments[i].length));
            reassembled += segments[i].length;
        }
        EXPECT_EQ(length, reassembled);
    }
}

TEST(Unit_Tlv_CerValues, RejectsIncorrectSegmentTag) {
    /* OCTET STRING wrapper carrying a BIT STRING-tagged segment. */
    std::vector<uint8_t> data = {0x24, 0x80};
    std::vector<uint8_t> seg(1003, 'a');
    seg[0] = 0x03;
    seg[1] = 0x82;
    seg[2] = 0x03;
    seg[3] = 0xE7; /* wrong tag, len=999 */
    data.insert(data.end(), seg.begin(), seg.end());
    data.push_back(0x04);
    data.push_back(1);
    data.push_back('z');
    data.push_back(0);
    data.push_back(0);
    size_t offset = 99;
    EXPECT_EQ(TLV_ERR_INVALID_TAG,
              tlv_cer_walk(data.data(), data.size(), nullptr, nullptr, nullptr, &offset));
    EXPECT_EQ(2u, offset);
}

TEST(Unit_Tlv_CerValues, RejectsConstructedSegment) {
    /* OCTET STRING wrapper whose only "segment" is itself constructed. */
    const uint8_t data[] = {0x24, 0x80, 0x24, 0x80, 0x04, 1, 'a', 0, 0, 0, 0};
    size_t        offset = 99;
    EXPECT_EQ(TLV_ERR_INVALID_TAG,
              tlv_cer_walk(data, sizeof(data), nullptr, nullptr, nullptr, &offset));
    EXPECT_EQ(2u, offset);
}

TEST(Unit_Tlv_CerValues, RejectsShortNonFinalSegment) {
    std::vector<uint8_t> data = {0x24, 0x80};
    std::vector<uint8_t> seg(1003, 'a'); /* 999 content octets, one short */
    seg[0] = 0x04;
    seg[1] = 0x82;
    seg[2] = 0x03;
    seg[3] = 0xE7;
    data.insert(data.end(), seg.begin(), seg.end());
    data.push_back(0x04);
    data.push_back(1);
    data.push_back('z'); /* proves seg wasn't last */
    data.push_back(0);
    data.push_back(0);
    size_t offset = 99;
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH,
              tlv_cer_walk(data.data(), data.size(), nullptr, nullptr, nullptr, &offset));
    EXPECT_EQ(2u, offset);
}

TEST(Unit_Tlv_CerValues, RejectsOversizedSegment) {
    std::vector<uint8_t> data = {0x24, 0x80, 0x04, 0x82, 0x03, 0xE9};
    data.resize(data.size() + 1001, 'a');
    data.push_back(0);
    data.push_back(0);
    size_t offset = 99;
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH,
              tlv_cer_walk(data.data(), data.size(), nullptr, nullptr, nullptr, &offset));
    EXPECT_EQ(2u, offset);
}

TEST(Unit_Tlv_CerValues, RejectsEmptySegment) {
    /* A sole empty segment: noncanonical (should have been primitive with
     * zero-length content, or omitted entirely). */
    const uint8_t data[] = {0x24, 0x80, 0x04, 0, 0, 0};
    size_t        offset = 99;
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH,
              tlv_cer_walk(data, sizeof(data), nullptr, nullptr, nullptr, &offset));
    EXPECT_EQ(2u, offset);
}

TEST(Unit_Tlv_CerValues, RejectsUnjustifiedConstructedEncoding) {
    /* Constructed OCTET STRING whose single segment is well under the
     * 1000-octet threshold: should have used primitive form. Reported at
     * the outer element's length field (its 0x80 indefinite marker),
     * matching the "length-form errors point to the length field" offset
     * convention used throughout this profile. */
    const uint8_t data[] = {0x24, 0x80, 0x04, 1, 'a', 0, 0};
    size_t        offset = 99;
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH,
              tlv_cer_walk(data, sizeof(data), nullptr, nullptr, nullptr, &offset));
    EXPECT_EQ(1u, offset);
}

TEST(Unit_Tlv_CerValues, BitStringSegmentation) {
    /* 1999 bit-content octets (+1 unused-bits octet = 2000 logical) needs
     * two non-final 999-octet chunks and a final 2-octet remainder. */
    std::vector<uint8_t> content(2000, 0);
    content[0] = 3; /* unused bits in the final segment */
    for (size_t i = 1; i < content.size(); ++i) content[i] = static_cast<uint8_t>(i);
    content.back() = 0xF8; /* top 3 bits set, low 3 (unused) bits zero: canonical padding */
    const auto data = write_segmented(0x03, content);

    tlv_view_t view{};
    size_t     consumed = 0;
    ASSERT_EQ(TLV_OK,
              tlv_cer_read_strict(data.data(), data.size(), nullptr, &view, &consumed, nullptr));
    EXPECT_EQ(data.size(), consumed);
    ASSERT_TRUE(tlv_cer_tag_is_constructed(&view.tag));
    const auto segments = segments_of(view);
    ASSERT_EQ(3u, segments.size());
    EXPECT_EQ(1000u, segments[0].length);
    EXPECT_EQ(0, segments[0].data[0]); /* non-final: synthesized unused-bits octet is 0 */
    EXPECT_EQ(1000u, segments[1].length);
    EXPECT_EQ(0, segments[1].data[0]);
    EXPECT_EQ(2u, segments[2].length);
    EXPECT_EQ(3, segments[2].data[0]); /* final: the real unused-bits count */

    /* Structural (non-strict) mode accepts a nonzero non-final unused-bits
     * octet; strict content validation rejects it. */
    std::vector<uint8_t> tampered = data;
    tampered[2 + 4] = 1; /* first byte of the first segment's content */
    size_t offset = 99;
    EXPECT_EQ(TLV_OK,
              tlv_cer_walk(tampered.data(), tampered.size(), nullptr, nullptr, nullptr, nullptr));
    EXPECT_EQ(TLV_ERR_INVALID_VALUE, tlv_cer_walk_strict(tampered.data(), tampered.size(), nullptr,
                                                         nullptr, nullptr, &offset));
}

TEST(Unit_Tlv_CerValues, Utf8StringCharacterSplitAcrossSegmentBoundary) {
    /* 999 'a' bytes plus a 2-byte UTF-8 character (U+00E9): the character's
     * two bytes land in different segments (bytes 999 and 1000). */
    std::string content(999, 'a');
    content += "\xC3\xA9";
    std::vector<uint8_t> bytes(content.begin(), content.end());
    const auto           data = write_segmented(0x0C, bytes);

    tlv_view_t view{};
    size_t     consumed = 0;
    ASSERT_EQ(TLV_OK,
              tlv_cer_read_strict(data.data(), data.size(), nullptr, &view, &consumed, nullptr));
    EXPECT_EQ(data.size(), consumed);
    const auto segments = segments_of(view);
    ASSERT_EQ(2u, segments.size());
    EXPECT_EQ(1000u, segments[0].length);
    EXPECT_EQ(0xC3, segments[0].data[999]);
    EXPECT_EQ(1u, segments[1].length);
    EXPECT_EQ(0xA9, segments[1].data[0]);

    /* Truncating the trailing continuation byte makes the split character
     * invalid; strict validation must still catch it across the boundary. */
    std::vector<uint8_t> truncated = data;
    truncated[truncated.size() - 3] = 0x41; /* replace the continuation byte with 'A' */
    size_t offset = 99;
    EXPECT_EQ(TLV_ERR_INVALID_VALUE, tlv_cer_read_strict(truncated.data(), truncated.size(),
                                                         nullptr, &view, &consumed, &offset));
}

TEST(Unit_Tlv_CerValues, CharacterStringRejectsInvalidCharsetPerSegment) {
    /* NumericString: only digits and space are legal. tlv_cer_write_segmented_string
     * validates whole logical content up front and would refuse to write an
     * illegal character at all, so this builds the pre-encoded two-segment
     * children directly (structurally canonical, content deliberately
     * invalid) and wraps them with the non-strict tlv_cer_write, which does
     * not validate content -- only tlv_cer_read_strict below does. */
    std::vector<uint8_t> children = {0x12, 0x82, 0x03, 0xE8};
    std::vector<uint8_t> seg1(1000, '5');
    seg1[10] = 'x';
    children.insert(children.end(), seg1.begin(), seg1.end());
    children.push_back(0x12);
    children.push_back(0x82);
    children.push_back(0x01);
    children.push_back(0xF4);
    children.insert(children.end(), 500, '5');

    uint8_t output[1520];
    size_t  written = 0;
    ASSERT_EQ(TLV_OK, tlv_cer_write(output, sizeof(output), (TLV_TAG(0x32)), children.data(),
                                    children.size(), nullptr, &written, nullptr));
    tlv_view_t view{};
    size_t     consumed = 0, offset = 99;
    ASSERT_EQ(TLV_OK, tlv_cer_read(output, written, nullptr, &view, &consumed, nullptr));
    EXPECT_EQ(TLV_ERR_INVALID_VALUE,
              tlv_cer_read_strict(output, written, nullptr, &view, &consumed, &offset));
}

TEST(Unit_Tlv_CerValues, UnrecognizedNumberBeyond36SkipsValueValidation) {
    /* Every primitive-capable universal number through 36 now has an
     * implemented content rule (0 and 15 are reserved and rejected at tag
     * validation, and 8/11/16/17/29 must be constructed), unlike DER's shared
     * dispatch, CER only calls value validation at all for a UNIVERSAL number
     * <=36 (see cer_profile.c's "recognized_universal" gate); a number beyond
     * that, like 37 here (needing the high-tag-number form), is therefore
     * always structurally accepted in strict mode, with no possible
     * UNSUPPORTED_TYPE outcome the way DER has via tag 37 in
     * der_values_test.cpp. */
    tlv_tag_t tag{};
    uint8_t   storage[TLV_ASN1_TAG_MAX_SIZE];
    ASSERT_EQ(TLV_OK, tlv_ber_tag_make(TLV_ASN1_UNIVERSAL, 0, 37, storage, &tag));
    uint8_t data[TLV_ASN1_TAG_MAX_SIZE + 2];
    std::memcpy(data, tag.data, tag.size);
    data[tag.size] = 1;
    data[tag.size + 1] = 'x';
    const size_t size = tag.size + 2;

    tlv_view_t view{};
    size_t     consumed = 0;
    EXPECT_EQ(TLV_OK, tlv_cer_read(data, size, nullptr, &view, &consumed, nullptr));
    EXPECT_EQ(TLV_OK, tlv_cer_read_strict(data, size, nullptr, &view, &consumed, nullptr));
}

TEST(Unit_Tlv_CerValues, WriteStrictRejectsInvalidContentButNonStrictAccepts) {
    const tlv_tag_t tag = TLV_TAG(0x01);  /* BOOLEAN */
    const uint8_t   bad_value[] = {0x02}; /* only 0x00/0xFF are canonical */
    uint8_t         output[8];
    std::memset(output, 0xEE, sizeof(output));
    size_t written = 99, offset = 0;

    EXPECT_EQ(TLV_ERR_INVALID_VALUE,
              tlv_cer_write_strict(output, sizeof(output), tag, bad_value, sizeof(bad_value),
                                   nullptr, &written, &offset));
    EXPECT_EQ(99u, written);
    EXPECT_EQ(1u, offset); /* just past the 1-byte tag, matching write_impl's offset_base */
    for (auto byte : output) EXPECT_EQ(0xEE, byte);

    EXPECT_EQ(TLV_OK, tlv_cer_write(output, sizeof(output), tag, bad_value, sizeof(bad_value),
                                    nullptr, &written, nullptr));
    EXPECT_EQ(3u, written);

    /* A canonical BOOLEAN still writes successfully in strict mode. */
    const uint8_t good_value[] = {0xFF};
    EXPECT_EQ(TLV_OK, tlv_cer_write_strict(output, sizeof(output), tag, good_value,
                                           sizeof(good_value), nullptr, &written, nullptr));
    EXPECT_EQ(3u, written);
    EXPECT_EQ(0x01, output[0]);
    EXPECT_EQ(0x01, output[1]);
    EXPECT_EQ(0xFF, output[2]);
}
