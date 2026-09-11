#include "tlv/formats/format.h"
#include "tlv/config.h"
#include "tlv/reader/reader.h"
#include "tlv/writer/writer.h"
#include <gtest/gtest.h>
#include <cstring>
#include <type_traits>

namespace {
tlv_result_t read_tag(const void*, const uint8_t*, size_t, tlv_tag_t*, size_t*) { return TLV_OK; }
tlv_result_t read_length(const void*, const uint8_t*, size_t, size_t*, size_t*) { return TLV_OK; }
tlv_result_t write_tag(const void*, uint8_t*, size_t, const tlv_tag_t*, size_t*) { return TLV_OK; }
tlv_result_t write_length(const void*, uint8_t*, size_t, size_t, size_t*) { return TLV_OK; }
tlv_result_t length_size(const void*, size_t, size_t*) { return TLV_OK; }

static_assert(!std::is_convertible<const tlv_reader_format_t*, const tlv_writer_format_t*>::value,
              "Reader formats must not convert to writer formats");
static_assert(!std::is_convertible<const tlv_writer_format_t*, const tlv_reader_format_t*>::value,
              "Writer formats must not convert to reader formats");
}

TEST(Unit_FormatInit, ReaderValidInputAndOptionalContext) {
    const int context = 42;
    tlv_reader_format_t format{};
    for (const void* ctx : {static_cast<const void*>(&context), static_cast<const void*>(nullptr)}) {
        ASSERT_EQ(TLV_OK, tlv_reader_format_init(&format, ctx, read_tag, read_length));
        EXPECT_EQ(ctx, format.context);
        EXPECT_EQ(read_tag, format.read_tag);
        EXPECT_EQ(read_length, format.read_length);
        EXPECT_EQ(nullptr, format.read_value_bounds);
    }
}

TEST(Unit_FormatInit, ReaderRejectsNullArgumentsWithoutModification) {
    const int context = 42;
    tlv_reader_format_t format = {&context, read_tag, read_length, nullptr};
    unsigned char before[sizeof(format)];
    std::memcpy(before, &format, sizeof(format));
    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_reader_format_init(nullptr, nullptr, read_tag, read_length));
    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_reader_format_init(&format, nullptr, nullptr, read_length));
    EXPECT_EQ(0, std::memcmp(before, &format, sizeof(format)));
    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_reader_format_init(&format, nullptr, read_tag, nullptr));
    EXPECT_EQ(0, std::memcmp(before, &format, sizeof(format)));
}

TEST(Unit_FormatInit, WriterValidInputAndOptionalContext) {
    const int context = 42;
    tlv_writer_format_t format{};
    for (const void* ctx : {static_cast<const void*>(&context), static_cast<const void*>(nullptr)}) {
        ASSERT_EQ(TLV_OK, tlv_writer_format_init(&format, ctx, write_tag, write_length, length_size));
        EXPECT_EQ(ctx, format.context);
        EXPECT_EQ(write_tag, format.write_tag);
        EXPECT_EQ(write_length, format.write_length);
        EXPECT_EQ(length_size, format.length_size);
    }
}

TEST(Unit_FormatInit, WriterRejectsNullArgumentsWithoutModification) {
    const int context = 42;
    tlv_writer_format_t format = {&context, write_tag, write_length, length_size};
    unsigned char before[sizeof(format)];
    std::memcpy(before, &format, sizeof(format));
    EXPECT_EQ(TLV_ERR_INVALID_ARG,
              tlv_writer_format_init(nullptr, nullptr, write_tag, write_length, length_size));
    for (int missing = 0; missing < 3; ++missing) {
        EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_writer_format_init(&format, nullptr,
            missing == 0 ? nullptr : write_tag, missing == 1 ? nullptr : write_length,
            missing == 2 ? nullptr : length_size));
        EXPECT_EQ(0, std::memcmp(before, &format, sizeof(format)));
    }
    EXPECT_STREQ("invalid argument", tlv_strerror(TLV_ERR_INVALID_ARG));
}

