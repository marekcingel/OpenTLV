#include "tlv/formats/format.h"
#include "tlv/config.h"
#include "tlv/reader/reader.h"
#include "tlv/writer/writer.h"
#include <gtest/gtest.h>
#include <cstring>
#include <type_traits>
#if OPENTLV_FORMAT_DEFAULT
#include "tlv/formats/default/default.h"
#include <vector>
#endif

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

TEST(FormatInit, ReaderValidInputAndOptionalContext) {
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

TEST(FormatInit, ReaderRejectsNullArgumentsWithoutModification) {
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

TEST(FormatInit, WriterValidInputAndOptionalContext) {
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

TEST(FormatInit, WriterRejectsNullArgumentsWithoutModification) {
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

#if OPENTLV_FORMAT_DEFAULT
TEST(FormatDefault, IndependentReferenceInputsAndOutputs) {
    struct reference { size_t length; std::vector<uint8_t> header; };
    const reference cases[] = {
        {0, {0x9F, 0}}, {127, {0x9F, 0x7F}}, {128, {0x9F, 0x81, 0x80}},
        {255, {0x9F, 0x81, 0xFF}}, {256, {0x9F, 0x82, 1, 0}},
        {65535, {0x9F, 0x82, 0xFF, 0xFF}}
    };
    for (const auto& item : cases) {
        SCOPED_TRACE(item.length);
        auto wire = item.header;
        wire.resize(wire.size() + item.length, 0xAB);
        tlv_view_t view{};
        size_t consumed = 0;
        ASSERT_EQ(TLV_OK, tlv_read(wire.data(), wire.size(), &tlv_reader_format_default,
                                   &view, &consumed));
        EXPECT_EQ(wire.size(), consumed);
        EXPECT_EQ(1, view.tag.size); // 9F is a single raw tag, not BER high-tag form.
        EXPECT_EQ(0x9F, view.tag.data[0]);
        EXPECT_EQ(item.length, view.value.length);
        EXPECT_EQ(wire.data() + item.header.size(), view.value.data);

        std::vector<uint8_t> output(wire.size());
        std::vector<uint8_t> value(item.length, 0xAB);
        size_t written = 0;
        ASSERT_EQ(TLV_OK, tlv_write(output.data(), output.size(), &tlv_writer_format_default,
            tlv_tag_t{{0x9F}, 1}, value.data(), value.size(), &written));
        EXPECT_EQ(wire.size(), written);
        EXPECT_EQ(wire, output);
    }
    size_t size = 123;
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_writer_format_default.length_size(nullptr, 65536, &size));
    const uint8_t too_large[] = {0x9F, 0x83, 1, 0, 0};
    tlv_view_t view{};
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_read(too_large, sizeof(too_large),
        &tlv_reader_format_default, &view, &size));
}
#endif
