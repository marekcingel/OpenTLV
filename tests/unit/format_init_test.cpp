#include "tlv/format.h"
#include "tlv/config.h"
#include "tlv/reader/reader.h"
#include "tlv/writer/writer.h"
#include <gtest/gtest.h>
#include <cstring>

namespace {
tlv_result_t read_tag(const void*, const uint8_t*, size_t, tlv_tag_t*, size_t*) {
    return TLV_OK;
}
tlv_result_t read_length(const void*, const uint8_t*, size_t, tlv_size_t*, size_t*) {
    return TLV_OK;
}
tlv_result_t write_tag(const void*, uint8_t*, size_t, const tlv_tag_t*, size_t*) {
    return TLV_OK;
}
tlv_result_t write_length(const void*, uint8_t*, size_t, tlv_size_t, size_t*) {
    return TLV_OK;
}
tlv_result_t length_size(const void*, tlv_size_t, size_t*) {
    return TLV_OK;
}
tlv_result_t read_element(const void*, const uint8_t*, size_t, tlv_tag_t*, tlv_length_t*, size_t*,
                          tlv_size_t*, size_t*) {
    return TLV_OK;
}
tlv_result_t write_header(const void*, uint8_t*, size_t, const tlv_tag_t*, tlv_size_t, size_t*) {
    return TLV_OK;
}
} // namespace

TEST(Unit_Tlv_FormatInit, BothDirectionsValidInputAndOptionalContext) {
    const int    context = 42;
    tlv_format_t format{};
    for (const void* ctx :
         {static_cast<const void*>(&context), static_cast<const void*>(nullptr)}) {
        ASSERT_EQ(TLV_OK, tlv_format_init(&format, ctx, read_tag, read_length, write_tag,
                                          write_length, length_size));
        EXPECT_EQ(ctx, format.context);
        EXPECT_EQ(read_tag, format.read_tag);
        EXPECT_EQ(read_length, format.read_length);
        EXPECT_EQ(nullptr, format.read_value_bounds);
        EXPECT_EQ(nullptr, format.read_element);
        EXPECT_EQ(write_tag, format.write_tag);
        EXPECT_EQ(write_length, format.write_length);
        EXPECT_EQ(length_size, format.length_size);
        EXPECT_EQ(nullptr, format.write_header);
        EXPECT_EQ(nullptr, format.is_constructed);
    }
}

TEST(Unit_Tlv_FormatInit, ReadOnlyLeavesWriteCallbacksUnset) {
    tlv_format_t format{};
    ASSERT_EQ(TLV_OK,
              tlv_format_init(&format, nullptr, read_tag, read_length, nullptr, nullptr, nullptr));
    EXPECT_EQ(read_tag, format.read_tag);
    EXPECT_EQ(read_length, format.read_length);
    EXPECT_EQ(nullptr, format.write_tag);
    EXPECT_EQ(nullptr, format.write_length);
    EXPECT_EQ(nullptr, format.length_size);
    EXPECT_TRUE(tlv_format_can_read(&format));
    EXPECT_FALSE(tlv_format_can_write(&format));
}

TEST(Unit_Tlv_FormatInit, WriteOnlyLeavesReadCallbacksUnset) {
    tlv_format_t format{};
    ASSERT_EQ(TLV_OK, tlv_format_init(&format, nullptr, nullptr, nullptr, write_tag, write_length,
                                      length_size));
    EXPECT_EQ(nullptr, format.read_tag);
    EXPECT_EQ(nullptr, format.read_length);
    EXPECT_EQ(write_tag, format.write_tag);
    EXPECT_EQ(write_length, format.write_length);
    EXPECT_EQ(length_size, format.length_size);
    EXPECT_FALSE(tlv_format_can_read(&format));
    EXPECT_TRUE(tlv_format_can_write(&format));
}

TEST(Unit_Tlv_FormatInit, RejectsNullFormatOrPartialOrEmptyGroupsWithoutModification) {
    const int     context = 42;
    tlv_format_t  format = {&context,  read_tag,     read_length, nullptr, nullptr,
                            write_tag, write_length, length_size, nullptr, nullptr};
    unsigned char before[sizeof(format)];
    std::memcpy(before, &format, sizeof(format));

    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_format_init(nullptr, nullptr, read_tag, read_length,
                                                   write_tag, write_length, length_size));

    // Partial read group.
    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_format_init(&format, nullptr, nullptr, read_length,
                                                   write_tag, write_length, length_size));
    EXPECT_EQ(0, std::memcmp(before, &format, sizeof(format)));
    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_format_init(&format, nullptr, read_tag, nullptr, write_tag,
                                                   write_length, length_size));
    EXPECT_EQ(0, std::memcmp(before, &format, sizeof(format)));

    // Partial write group.
    for (int missing = 0; missing < 3; ++missing) {
        EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_format_init(&format, nullptr, read_tag, read_length,
                                                       missing == 0 ? nullptr : write_tag,
                                                       missing == 1 ? nullptr : write_length,
                                                       missing == 2 ? nullptr : length_size));
        EXPECT_EQ(0, std::memcmp(before, &format, sizeof(format)));
    }

    // Neither group given at all.
    EXPECT_EQ(TLV_ERR_INVALID_ARG,
              tlv_format_init(&format, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr));
    EXPECT_EQ(0, std::memcmp(before, &format, sizeof(format)));

    EXPECT_STREQ("invalid argument", tlv_strerror(TLV_ERR_INVALID_ARG));
}

TEST(Unit_Tlv_FormatInitElement, BothDirectionsAndEachAlone) {
    const int    context = 42;
    tlv_format_t format{};

    ASSERT_EQ(TLV_OK, tlv_format_init_element(&format, &context, read_element, write_header));
    EXPECT_EQ(&context, format.context);
    EXPECT_EQ(read_element, format.read_element);
    EXPECT_EQ(write_header, format.write_header);
    EXPECT_EQ(nullptr, format.read_tag);
    EXPECT_EQ(nullptr, format.write_tag);
    EXPECT_EQ(nullptr, format.is_constructed);

    ASSERT_EQ(TLV_OK, tlv_format_init_element(&format, nullptr, read_element, nullptr));
    EXPECT_TRUE(tlv_format_can_read(&format));
    EXPECT_FALSE(tlv_format_can_write(&format));

    ASSERT_EQ(TLV_OK, tlv_format_init_element(&format, nullptr, nullptr, write_header));
    EXPECT_FALSE(tlv_format_can_read(&format));
    EXPECT_TRUE(tlv_format_can_write(&format));
}

TEST(Unit_Tlv_FormatInitElement, RejectsNullFormatOrBothCallbacksMissing) {
    tlv_format_t  format = {nullptr, nullptr, nullptr, nullptr,      read_element,
                            nullptr, nullptr, nullptr, write_header, nullptr};
    unsigned char before[sizeof(format)];
    std::memcpy(before, &format, sizeof(format));

    EXPECT_EQ(TLV_ERR_INVALID_ARG,
              tlv_format_init_element(nullptr, nullptr, read_element, write_header));
    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_format_init_element(&format, nullptr, nullptr, nullptr));
    EXPECT_EQ(0, std::memcmp(before, &format, sizeof(format)));
}

TEST(Unit_Tlv_FormatCapability, ReaderAndWriterInitEnforceCapabilityAtRuntime) {
    tlv_format_t both{};
    ASSERT_EQ(TLV_OK, tlv_format_init(&both, nullptr, read_tag, read_length, write_tag,
                                      write_length, length_size));
    tlv_format_t read_only{};
    ASSERT_EQ(TLV_OK, tlv_format_init(&read_only, nullptr, read_tag, read_length, nullptr, nullptr,
                                      nullptr));
    tlv_format_t write_only{};
    ASSERT_EQ(TLV_OK, tlv_format_init(&write_only, nullptr, nullptr, nullptr, write_tag,
                                      write_length, length_size));

    tlv_reader_t reader;
    tlv_writer_t writer;
    uint8_t      buf[4] = {0};

    // A wrong-capability format no longer fails to compile (there is one type); it fails at
    // runtime instead, matching the point of unifying tlv_reader_format_t/tlv_writer_format_t.
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_reader_init(&reader, buf, sizeof(buf), &write_only));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_writer_init(&writer, buf, sizeof(buf), &read_only));

    // Positive control: a fully capable format works both ways.
    EXPECT_EQ(TLV_OK, tlv_reader_init(&reader, buf, sizeof(buf), &both));
    EXPECT_EQ(TLV_OK, tlv_writer_init(&writer, buf, sizeof(buf), &both));
}
