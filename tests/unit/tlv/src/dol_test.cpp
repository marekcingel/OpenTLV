#include "tlv/profiles/dol.h"
#include <gtest/gtest.h>
#include <cstring>
#include <vector>

namespace {

tlv_tag_t Tag1(uint8_t b) {
    tlv_tag_t tag{};
    tlv_tag_from_u8(b, 1, TLV_BYTE_ORDER_BIG_ENDIAN, &tag);
    return tag;
}

tlv_tag_t Tag2(uint16_t v) {
    tlv_tag_t tag{};
    tlv_tag_from_u16(v, 2, TLV_BYTE_ORDER_BIG_ENDIAN, &tag);
    return tag;
}

bool TagsEqual(const tlv_tag_t& a, const tlv_tag_t& b) {
    int equal = 0;
    return tlv_tag_equal(&a, &b, &equal) == TLV_OK && equal;
}

tlv_result_t CollectVisitor(const tlv_dol_entry_t* entry, size_t index, void* context) {
    (void)index;
    static_cast<std::vector<tlv_dol_entry_t>*>(context)->push_back(*entry);
    return TLV_OK;
}

tlv_result_t Read(const std::vector<uint8_t>& data, std::vector<tlv_dol_entry_t>* entries,
                  size_t* error_offset = nullptr, const tlv_dol_limits_t* limits = nullptr) {
    size_t local_offset = 0;
    return tlv_dol_read(data.data(), data.size(), limits, CollectVisitor, entries,
                        error_offset ? error_offset : &local_offset);
}

struct ScriptValue {
    bool                 present;
    std::vector<uint8_t> bytes;
    tlv_dol_format_t     format;
};

tlv_result_t ScriptResolve(const tlv_dol_entry_t* entry, size_t index, size_t skip, uint8_t* data,
                           size_t capacity, size_t* available_length, tlv_dol_format_t* format,
                           int* absent, void* context) {
    (void)entry;
    const auto*        script = static_cast<const std::vector<ScriptValue>*>(context);
    const ScriptValue& value = (*script)[index];
    if (!value.present) {
        *absent = 1;
        return TLV_OK;
    }
    *absent = 0;
    if (!data) {
        *available_length = value.bytes.size();
        *format = value.format;
        return TLV_OK;
    }
    if (skip + capacity > value.bytes.size()) return TLV_ERR_INVALID_ARG;
    std::memcpy(data, value.bytes.data() + skip, capacity);
    return TLV_OK;
}

tlv_result_t Write(const std::vector<uint8_t>& dol, const std::vector<ScriptValue>& script,
                   std::vector<uint8_t>* output, size_t* error_offset = nullptr,
                   const tlv_dol_limits_t* limits = nullptr) {
    size_t local_offset = 0, written = 0;
    output->assign(256, 0xCC);
    tlv_result_t rc = tlv_dol_write(dol.data(), dol.size(), output->data(), output->size(), limits,
                                    ScriptResolve, const_cast<std::vector<ScriptValue>*>(&script),
                                    &written, error_offset ? error_offset : &local_offset);
    output->resize(rc == TLV_OK ? written : output->size());
    return rc;
}

} // namespace

TEST(Unit_Dol, ReadParsesEntriesInOrder) {
    const std::vector<uint8_t>   data = {0x9F, 0x02, 0x06, 0x5A, 0x08};
    std::vector<tlv_dol_entry_t> entries;
    EXPECT_EQ(TLV_OK, Read(data, &entries));
    ASSERT_EQ(2u, entries.size());
    EXPECT_TRUE(TagsEqual(entries[0].tag, Tag2(0x9F02)));
    EXPECT_EQ(6u, entries[0].requested_length);
    EXPECT_TRUE(TagsEqual(entries[1].tag, Tag1(0x5A)));
    EXPECT_EQ(8u, entries[1].requested_length);
}

TEST(Unit_Dol, ReadPreservesDuplicateTags) {
    const std::vector<uint8_t>   data = {0x9F, 0x02, 0x04, 0x9F, 0x02, 0x06};
    std::vector<tlv_dol_entry_t> entries;
    EXPECT_EQ(TLV_OK, Read(data, &entries));
    ASSERT_EQ(2u, entries.size());
    EXPECT_EQ(4u, entries[0].requested_length);
    EXPECT_EQ(6u, entries[1].requested_length);
}

TEST(Unit_Dol, ReadAcceptsEmptyDol) {
    std::vector<tlv_dol_entry_t> entries;
    EXPECT_EQ(TLV_OK, Read({}, &entries));
    EXPECT_TRUE(entries.empty());
}

TEST(Unit_Dol, ReadRejectsDanglingTag) {
    /* A complete entry (5A 08) followed by a tag (9F 02) with no length byte. */
    const std::vector<uint8_t>   data = {0x5A, 0x08, 0x9F, 0x02};
    std::vector<tlv_dol_entry_t> entries;
    size_t                       offset = 99;
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, Read(data, &entries, &offset));
    EXPECT_EQ(2u, offset);
    EXPECT_EQ(1u, entries.size());
}

TEST(Unit_Dol, ReadRejectsMalformedTag) {
    /* A high-tag-number lead byte with no continuation byte at all. */
    const std::vector<uint8_t>   data = {0x9F};
    std::vector<tlv_dol_entry_t> entries;
    size_t                       offset = 99;
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, Read(data, &entries, &offset));
    EXPECT_EQ(0u, offset);
}

TEST(Unit_Dol, ReadRejectsReservedTagByte) {
    const std::vector<uint8_t>   data = {0x00, 0x01};
    std::vector<tlv_dol_entry_t> entries;
    size_t                       offset = 99;
    EXPECT_EQ(TLV_ERR_INVALID_TAG, Read(data, &entries, &offset));
    EXPECT_EQ(0u, offset);
}

TEST(Unit_Dol, ReadStopsAtEntryCountLimit) {
    const std::vector<uint8_t>   data = {0x5A, 0x08, 0x9F, 0x1A, 0x02};
    std::vector<tlv_dol_entry_t> entries;
    tlv_dol_limits_t             limits = tlv_dol_default_limits;
    limits.max_entries = 1;
    size_t offset = 99;
    EXPECT_EQ(TLV_ERR_LIMIT, Read(data, &entries, &offset, &limits));
    EXPECT_EQ(2u, offset);
    EXPECT_EQ(1u, entries.size());
}

TEST(Unit_Dol, ReadPropagatesVisitorErrorAndStopsIteration) {
    const std::vector<uint8_t>   data = {0x5A, 0x01, 0x9F, 0x1A, 0x02};
    std::vector<tlv_dol_entry_t> entries;
    auto                         stop_after_first = [](const tlv_dol_entry_t* entry, size_t index,
                                                       void* context) -> tlv_result_t {
        static_cast<std::vector<tlv_dol_entry_t>*>(context)->push_back(*entry);
        return index == 0 ? TLV_OK : TLV_ERR_VISITOR;
    };
    size_t offset = 99;
    EXPECT_EQ(TLV_ERR_VISITOR,
              tlv_dol_read(data.data(), data.size(), nullptr, stop_after_first, &entries, &offset));
    EXPECT_EQ(2u, offset);
    EXPECT_EQ(2u, entries.size());
}

TEST(Unit_Dol, ReadRejectsNullVisitor) {
    const std::vector<uint8_t> data = {0x5A, 0x01};
    EXPECT_EQ(TLV_ERR_NULL_ARG,
              tlv_dol_read(data.data(), data.size(), nullptr, nullptr, nullptr, nullptr));
}

TEST(Unit_Dol, WriteSizeQueryEqualsSumOfRequestedLengths) {
    const std::vector<uint8_t> dol = {0x9F, 0x02, 0x06, 0x5A, 0x08};
    size_t                     written = 0, offset = 99;
    EXPECT_EQ(TLV_OK, tlv_dol_write(dol.data(), dol.size(), nullptr, 0, nullptr, nullptr, nullptr,
                                    &written, &offset));
    EXPECT_EQ(14u, written);
}

TEST(Unit_Dol, WriteSizeQueryValidatesMalformedDol) {
    const std::vector<uint8_t> dol = {0x5A};
    size_t                     written = 99, offset = 99;
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_dol_write(dol.data(), dol.size(), nullptr, 0, nullptr,
                                                      nullptr, nullptr, &written, &offset));
    EXPECT_EQ(0u, offset);
}

TEST(Unit_Dol, WriteRejectsNullResolveWhenProducing) {
    const std::vector<uint8_t> dol = {0x5A, 0x02};
    std::vector<uint8_t>       output(2, 0);
    size_t                     written = 0;
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_dol_write(dol.data(), dol.size(), output.data(), output.size(),
                                              nullptr, nullptr, nullptr, &written, nullptr));
}

TEST(Unit_Dol, WritePadsShortBinaryValueOnRight) {
    const std::vector<uint8_t> dol = {0x9F, 0x37, 0x04};
    std::vector<uint8_t>       output;
    ASSERT_EQ(TLV_OK, Write(dol, {{true, {0xAA, 0xBB}, TLV_DOL_FORMAT_BINARY}}, &output));
    const std::vector<uint8_t> expected = {0xAA, 0xBB, 0x00, 0x00};
    EXPECT_EQ(expected, output);
}

TEST(Unit_Dol, WritePadsShortNumericValueOnLeft) {
    const std::vector<uint8_t> dol = {0x9F, 0x02, 0x04};
    std::vector<uint8_t>       output;
    ASSERT_EQ(TLV_OK, Write(dol, {{true, {0x12, 0x34}, TLV_DOL_FORMAT_NUMERIC}}, &output));
    const std::vector<uint8_t> expected = {0x00, 0x00, 0x12, 0x34};
    EXPECT_EQ(expected, output);
}

TEST(Unit_Dol, WriteTruncatesLongBinaryValueFromRight) {
    const std::vector<uint8_t> dol = {0x9F, 0x37, 0x02};
    std::vector<uint8_t>       output;
    ASSERT_EQ(TLV_OK,
              Write(dol, {{true, {0x11, 0x22, 0x33, 0x44}, TLV_DOL_FORMAT_BINARY}}, &output));
    const std::vector<uint8_t> expected = {0x11, 0x22};
    EXPECT_EQ(expected, output);
}

TEST(Unit_Dol, WriteTruncatesLongNumericValueFromLeft) {
    const std::vector<uint8_t> dol = {0x9F, 0x02, 0x02};
    std::vector<uint8_t>       output;
    ASSERT_EQ(TLV_OK,
              Write(dol, {{true, {0x11, 0x22, 0x33, 0x44}, TLV_DOL_FORMAT_NUMERIC}}, &output));
    const std::vector<uint8_t> expected = {0x33, 0x44};
    EXPECT_EQ(expected, output);
}

TEST(Unit_Dol, WriteKeepsExactLengthValueUnchanged) {
    const std::vector<uint8_t> dol = {0x9F, 0x1A, 0x02};
    std::vector<uint8_t>       output;
    ASSERT_EQ(TLV_OK, Write(dol, {{true, {0x08, 0x26}, TLV_DOL_FORMAT_NUMERIC}}, &output));
    const std::vector<uint8_t> expected = {0x08, 0x26};
    EXPECT_EQ(expected, output);
}

TEST(Unit_Dol, WriteFillsMissingValueWithZeros) {
    const std::vector<uint8_t> dol = {0x9F, 0x02, 0x06};
    std::vector<uint8_t>       output;
    ASSERT_EQ(TLV_OK, Write(dol, {{false, {}, TLV_DOL_FORMAT_BINARY}}, &output));
    const std::vector<uint8_t> expected(6, 0x00);
    EXPECT_EQ(expected, output);
}

TEST(Unit_Dol, WriteEmptyDolProducesEmptyOutput) {
    std::vector<uint8_t> output;
    ASSERT_EQ(TLV_OK, Write({}, {}, &output));
    EXPECT_TRUE(output.empty());
}

TEST(Unit_Dol, WritePreservesEntryOrderAcrossMultipleEntries) {
    const std::vector<uint8_t> dol = {0x5A, 0x03, 0x9F, 0x02, 0x02, 0x9F, 0x1A, 0x01};
    std::vector<uint8_t>       output;
    ASSERT_EQ(TLV_OK, Write(dol,
                            {{true, {0x11, 0x22}, TLV_DOL_FORMAT_NUMERIC},
                             {true, {0x33, 0x44}, TLV_DOL_FORMAT_BINARY},
                             {false, {}, TLV_DOL_FORMAT_BINARY}},
                            &output));
    const std::vector<uint8_t> expected = {0x00, 0x11, 0x22, 0x33, 0x44, 0x00};
    EXPECT_EQ(expected, output);
}

TEST(Unit_Dol, WriteRejectsBufferTooShort) {
    const std::vector<uint8_t> dol = {0x5A, 0x03, 0x9F, 0x02, 0x02};
    std::vector<ScriptValue>   script = {{true, {0x11, 0x22, 0x33}, TLV_DOL_FORMAT_BINARY}};
    std::vector<uint8_t>       output(4, 0);
    size_t                     written = 0, offset = 99;
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
              tlv_dol_write(dol.data(), dol.size(), output.data(), output.size(), nullptr,
                            ScriptResolve, &script, &written, &offset));
    EXPECT_EQ(2u, offset);
}

TEST(Unit_Dol, WriteRejectsAvailableLengthOverLimit) {
    const std::vector<uint8_t> dol = {0x5A, 0x02};
    std::vector<ScriptValue>   script = {
        {true, std::vector<uint8_t>(TLV_DOL_MAX_VALUE_LENGTH + 1, 0x01), TLV_DOL_FORMAT_BINARY}};
    std::vector<uint8_t> output(2, 0);
    size_t               written = 0, offset = 99;
    EXPECT_EQ(TLV_ERR_LIMIT, tlv_dol_write(dol.data(), dol.size(), output.data(), output.size(),
                                           nullptr, ScriptResolve, &script, &written, &offset));
    EXPECT_EQ(0u, offset);
}

TEST(Unit_Dol, WriteRejectsInvalidFormatEnum) {
    const std::vector<uint8_t> dol = {0x5A, 0x02};
    std::vector<uint8_t>       output(2, 0);
    size_t                     written = 0, offset = 99;
    auto bad_format_resolve = [](const tlv_dol_entry_t*, size_t, size_t, uint8_t* data, size_t,
                                 size_t* available_length, tlv_dol_format_t* format, int* absent,
                                 void*) -> tlv_result_t {
        if (!data) {
            *absent = 0;
            *available_length = 1;
            *format = static_cast<tlv_dol_format_t>(99);
        }
        return TLV_OK;
    };
    EXPECT_EQ(TLV_ERR_INVALID_ARG,
              tlv_dol_write(dol.data(), dol.size(), output.data(), output.size(), nullptr,
                            bad_format_resolve, nullptr, &written, &offset));
    EXPECT_EQ(0u, offset);
}

TEST(Unit_Dol, WriteMalformedDolPropagatesReadError) {
    const std::vector<uint8_t> dol = {0x5A};
    std::vector<uint8_t>       output(4, 0);
    size_t                     written = 99, offset = 99;
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
              tlv_dol_write(dol.data(), dol.size(), output.data(), output.size(), nullptr,
                            ScriptResolve, nullptr, &written, &offset));
    EXPECT_EQ(0u, offset);
}

TEST(Unit_Dol, WriteStopsAtEntryCountLimit) {
    const std::vector<uint8_t> dol = {0x5A, 0x01, 0x9F, 0x1A, 0x01};
    tlv_dol_limits_t           limits = tlv_dol_default_limits;
    limits.max_entries = 1;
    size_t written = 99, offset = 99;
    EXPECT_EQ(TLV_ERR_LIMIT, tlv_dol_write(dol.data(), dol.size(), nullptr, 0, &limits, nullptr,
                                           nullptr, &written, &offset));
    EXPECT_EQ(2u, offset);
}

TEST(Unit_Dol, WriteRejectsMaxValueLengthAboveHardCeiling) {
    const std::vector<uint8_t> dol;
    tlv_dol_limits_t           limits = tlv_dol_default_limits;
    limits.max_value_length = TLV_DOL_MAX_VALUE_LENGTH + 1;
    size_t written = 99, offset = 99;
    EXPECT_EQ(TLV_ERR_LIMIT, tlv_dol_write(dol.data(), dol.size(), nullptr, 0, &limits, nullptr,
                                           nullptr, &written, &offset));
    EXPECT_EQ(0u, offset);
}
