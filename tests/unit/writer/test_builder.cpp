#include "tlv++/writer/builder.hpp"
#include "tlv++/native.hpp"
#include "tlv++/formats/fixed_format.hpp"
#include "tlv/config.h"
#include "controlled_format.h"
#include "custom_cpp_format.hpp"
#if OPENTLV_FORMAT_BER
#include "tlv++/builtins/asn1/ber.hpp"
#endif
#include <gtest/gtest.h>
#include <array>
#include <cstring>
#include <iterator>
#include <string>
#include <vector>

namespace {
struct counted_error {
    static int alive;
    int        value;
    explicit counted_error(int value) : value(value) {
        ++alive;
    }
    counted_error(const counted_error& other) : value(other.value) {
        if (value == 99) throw 99;
        ++alive;
    }
    counted_error(counted_error&& other) noexcept : value(other.value) {
        ++alive;
    }
    counted_error& operator=(const counted_error&) = default;
    counted_error& operator=(counted_error&&) = default;
    ~counted_error() {
        --alive;
    }
};
int counted_error::alive = 0;

tlv_format_t nested_format() {
    auto format = controlled::format;
    format.is_constructed = [](const void*, const tlv_tag_t* tag) {
        return tag->size == 1 && tag->data[0] >= 0x80 ? 1 : 0;
    };
    return format;
}
template <size_t N> void expect_wire(const tlv::byte* actual, const uint8_t (&expected)[N]) {
    EXPECT_EQ(0, std::memcmp(actual, expected, N));
}
} // namespace

TEST(Unit_Tlvpp_WriterBuilder, VoidResultsConstructAndDestroyOnlyActiveErrors) {
    EXPECT_EQ(0, counted_error::alive);
    {
        tlv::expected<void, counted_error> success;
        auto                               copied_success = success;
        auto                               moved_success = std::move(copied_success);
        EXPECT_TRUE(moved_success);
        EXPECT_EQ(0, counted_error::alive);
        tlv::expected<void, counted_error> failed{tlv::unexpected<counted_error>(counted_error(7))};
        EXPECT_EQ(1, counted_error::alive);
        auto copied_failure = failed;
        auto moved_failure = std::move(copied_failure);
        EXPECT_EQ(3, counted_error::alive);
        success = failed;
        EXPECT_EQ(4, counted_error::alive);
        EXPECT_EQ(7, success.error().value);
        failed = tlv::expected<void, counted_error>{};
        EXPECT_TRUE(failed);
        EXPECT_EQ(3, counted_error::alive);
        success = moved_failure;
        success = std::move(moved_failure);
        EXPECT_EQ(3, counted_error::alive);
        copied_failure = failed;
        EXPECT_EQ(2, counted_error::alive);
        moved_success = std::move(success);
        EXPECT_EQ(3, counted_error::alive);
        EXPECT_EQ(7, moved_success.error().value);
    }
    EXPECT_EQ(0, counted_error::alive);
}

TEST(Unit_Tlvpp_WriterBuilder, VoidResultSurvivesFailedErrorConstruction) {
    {
        tlv::expected<void, counted_error> success;
        tlv::expected<void, counted_error> failed{
            tlv::unexpected<counted_error>(counted_error(99))};
        EXPECT_THROW(success = failed, int);
        EXPECT_TRUE(success);
        EXPECT_EQ(1, counted_error::alive);
    }
    EXPECT_EQ(0, counted_error::alive);
}

TEST(Unit_Tlvpp_WriterBuilder, ClosingFailurePreservesFirstDiagnosticAndCompletedRoots) {
    auto format = nested_format();
    format.encode = [](const void* context, const tlv_element_t* value, uint8_t* data,
                       size_t capacity, size_t* written, tlv_format_error_t* error) {
        if (value->tag.data[0] == 0xE1) {
            if (capacity) data[0] = 0xFF;
            return TLV_ERR_INVALID_VALUE;
        }
        return tlv_fields_encode(context, value, data, capacity, written, error);
    };
    tlv::byte                  output[16]{};
    tlv::writer_storage<16, 1> storage;
    tlv::writer_diagnostic     diagnostic{};
    tlv::writer_builder writer(tlv::span<tlv::byte>(output, sizeof(output)),
                               tlv::native::borrow_format(format), storage.view(), &diagnostic);
    writer.write<1>("");
    writer.constructed<0xE1>([](tlv::writer_builder& parent) { parent.write<2>("A"); });
    EXPECT_EQ(TLV_ERR_INVALID_VALUE, writer.status());
    EXPECT_EQ(TLV_WRITER_OP_HEADER, diagnostic.operation);
    EXPECT_EQ(2u, diagnostic.diagnostic.offset);
    EXPECT_EQ(2u, writer.size());
    const uint8_t preserved[] = {1, 0, 2, 1, 'A'};
    expect_wire(output, preserved);
    writer.write<3>("");
    EXPECT_EQ(TLV_ERR_INVALID_VALUE, writer.finish().error().code);
    EXPECT_EQ(TLV_WRITER_OP_HEADER, diagnostic.operation);
}

TEST(Unit_Tlvpp_WriterBuilder, SequentialTypedValuesAndSemanticElements) {
    tlv::byte                                                       output[64]{};
    tlv::writer<tlv::fixed_format<1, 1, TLV_BYTE_ORDER_BIG_ENDIAN>> writer(
        tlv::span<tlv::byte>(output, sizeof(output)));
    const uint8_t                  bytes[] = {0xAB, 0x00};
    const std::array<tlv::byte, 2> array{{tlv::byte{1}, tlv::byte{2}}};
    const std::vector<uint8_t>     vector{3, 4};
    ASSERT_TRUE(writer.write<1>(bytes));
    ASSERT_TRUE(writer.write(tlv::tag_bytes<2>(), array));
    ASSERT_TRUE(writer.write<3>(vector));
    ASSERT_TRUE(writer.write<4>("A\0B"));
    ASSERT_TRUE(writer.write<5>(std::string("C\0D", 3)));
    const char unterminated[] = {'E', 'F'};
    ASSERT_TRUE(writer.write<6>(unterminated));
    ASSERT_TRUE(writer.write(tlv::element_view(tlv::tag_bytes<7>(), tlv::value_view{})));
    const uint8_t expected[] = {1,   2, 0xAB, 0, 2, 2,   1, 2,   3, 2, 3,   4,   4, 3,
                                'A', 0, 'B',  5, 3, 'C', 0, 'D', 6, 2, 'E', 'F', 7, 0};
    ASSERT_EQ(sizeof(expected), writer.size());
    expect_wire(output, expected);
#if __cplusplus >= 201703L
    ASSERT_TRUE(writer.write<8>(std::string_view("X\0Y", 3)));
    const uint8_t tail[] = {8, 3, 'X', 0, 'Y'};
    expect_wire(output + std::size(expected), tail);
#endif
}

TEST(Unit_Tlvpp_WriterBuilder, ByteTagTemplatesPreserveLeadingZeros) {
    tlv::byte                                                       output[8]{};
    tlv::writer<tlv::fixed_format<2, 1, TLV_BYTE_ORDER_BIG_ENDIAN>> writer(output, sizeof(output));
    const tlv::byte                                                 value[] = {tlv::byte{0}};
    ASSERT_TRUE((writer.write<0x00, 0x01>(value)));
    const uint8_t expected[] = {0, 1, 1, 0};
    EXPECT_EQ(sizeof(expected), writer.size());
    expect_wire(output, expected);
}

TEST(Unit_Tlvpp_WriterBuilder, FlatOutputNeedsNoScratchOrFramesAndCanContinueAfterFinish) {
    tlv::byte                 output[4]{};
    tlv::writer_storage<0, 0> storage;
    tlv::writer_builder writer(tlv::span<tlv::byte>(output, sizeof(output)),
                               tlv::native::borrow_format(controlled::format), storage.view());
    writer.write<1>(tlv::bytes{});
    auto first = writer.finish();
    ASSERT_TRUE(first);
    EXPECT_EQ(2u, *first);
    writer.write<2>(tlv::value_view{});
    auto second = writer.finish();
    ASSERT_TRUE(second);
    EXPECT_EQ(4u, *second);
    const uint8_t expected[] = {1, 0, 2, 0};
    expect_wire(output, expected);
}

TEST(Unit_Tlvpp_WriterBuilder, RuntimeWorkspaceNestedAndEmptyParents) {
    auto                       format = nested_format();
    tlv::byte                  output[32]{};
    tlv::writer_storage<16, 2> storage;
    int                        calls = 0;
    auto                       result =
        tlv::encode(output, tlv::native::borrow_format(format), storage.view(),
                    [&](tlv::writer_builder& writer) {
                        ++calls;
                        writer.write<1>("A");
                        writer.constructed<0xE1>([&](tlv::writer_builder& parent) {
                            ++calls;
                            const std::array<uint8_t, 2> value{{2, 3}};
                            parent.write<2>(value);
                            parent.constructed(tlv::tag_bytes<0xE2>(), [](tlv::writer_builder&) {});
                        });
                        writer.write(tlv::element_view(tlv::tag_bytes<3>(), tlv::value_view{}));
                    });
    ASSERT_TRUE(result);
    const uint8_t expected[] = {1, 1, 'A', 0xE1, 6, 2, 2, 2, 3, 0xE2, 0, 3, 0};
    ASSERT_EQ(sizeof(expected), *result);
    EXPECT_EQ(2, calls);
    expect_wire(output, expected);
}

TEST(Unit_Tlvpp_WriterBuilder, FirstErrorStopsWritingAndSkipsLaterCallbacks) {
    auto                      format = nested_format();
    tlv::byte                 output[8]{};
    tlv::writer_storage<8, 2> storage;
    tlv::writer_diagnostic    diagnostic{};
    tlv::writer_builder writer(tlv::span<tlv::byte>(output, sizeof(output)),
                               tlv::native::borrow_format(format), storage.view(), &diagnostic);
    writer.write<1>("A");
    writer.constructed<0xE1>([](tlv::writer_builder& parent) { parent.write<2>("too long"); });
    bool called = false;
    writer.constructed<0xE2>([&](tlv::writer_builder&) { called = true; });
    writer.write<3>("");
    writer.fail(TLV_ERR_INVALID_TAG);
    auto result = writer.finish();
    ASSERT_FALSE(result);
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, result.error().code);
    EXPECT_STREQ(tlv_strerror(TLV_ERR_BUFFER_TOO_SHORT), result.error().message());
    EXPECT_FALSE(called);
    EXPECT_EQ(3u, writer.size());
    EXPECT_EQ(3u, diagnostic.diagnostic.offset);
    EXPECT_EQ(10u, diagnostic.required);
    const uint8_t expected[] = {1, 1, 'A'};
    expect_wire(output, expected);
}

TEST(Unit_Tlvpp_WriterBuilder, ScratchFailureKeepsRootProvisional) {
    auto                      format = nested_format();
    tlv::byte                 output[16]{};
    tlv::writer_storage<1, 1> storage;
    tlv::writer_diagnostic    diagnostic{};
    tlv::writer_builder writer(tlv::span<tlv::byte>(output, sizeof(output)),
                               tlv::native::borrow_format(format), storage.view(), &diagnostic);
    writer.constructed<0xE1>([](tlv::writer_builder& parent) { parent.write<1>(""); });
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, writer.status());
    EXPECT_EQ(0u, writer.size());
    EXPECT_EQ(TLV_WRITER_OP_END, diagnostic.operation);
    EXPECT_EQ(2u, diagnostic.required);
    EXPECT_EQ(1u, diagnostic.available);
    EXPECT_FALSE(writer.finish());
}

TEST(Unit_Tlvpp_WriterBuilder, FrameDepthAndElementLimitsAreIndependent) {
    auto                       format = nested_format();
    tlv::byte                  output[32]{};
    tlv::writer_storage<32, 1> storage;
    bool                       called = false;
    auto                       frames =
        tlv::encode(output, tlv::native::borrow_format(format), storage.view(10),
                    [&](tlv::writer_builder& writer) {
                        writer.constructed<0xE1>([&](tlv::writer_builder& parent) {
                            parent.constructed<0xE2>([&](tlv::writer_builder&) { called = true; });
                        });
                    });
    ASSERT_FALSE(frames);
    EXPECT_EQ(TLV_ERR_LIMIT, frames.error().code);
    EXPECT_FALSE(called);
    auto depth = tlv::encode(output, tlv::native::borrow_format(format), storage.view(0),
                             [](tlv::writer_builder& writer) {
                                 writer.constructed<0xE1>(
                                     [](tlv::writer_builder& parent) { parent.write<1>(""); });
                             });
    ASSERT_FALSE(depth);
    EXPECT_EQ(TLV_ERR_LIMIT, depth.error().code);
    auto count = tlv::encode(output, tlv::native::borrow_format(format), storage.view(10, 1),
                             [](tlv::writer_builder& writer) {
                                 writer.write<1>("");
                                 writer.write<2>("");
                             });
    ASSERT_FALSE(count);
    EXPECT_EQ(TLV_ERR_LIMIT, count.error().code);
}

TEST(Unit_Tlvpp_WriterBuilder, InvalidInitializationAndParentSkipCallbacks) {
    const tlv_format_t        invalid{};
    tlv::byte                 output[8]{};
    tlv::writer_storage<8, 1> storage;
    bool                      called = false;
    auto result = tlv::encode(output, tlv::native::borrow_format(invalid), storage.view(),
                              [&](tlv::writer_builder&) { called = true; });
    ASSERT_FALSE(result);
    EXPECT_EQ(TLV_ERR_NULL_ARG, result.error().code);
    EXPECT_FALSE(called);
    auto format = nested_format();
    auto parent =
        tlv::encode(output, tlv::native::borrow_format(format), storage.view(),
                    [&](tlv::writer_builder& writer) {
                        writer.constructed<1>([&](tlv::writer_builder&) { called = true; });
                    });
    ASSERT_FALSE(parent);
    EXPECT_EQ(TLV_ERR_INVALID_TAG, parent.error().code);
    EXPECT_FALSE(called);
}

TEST(Unit_Tlvpp_WriterBuilder, CaughtCallbackExceptionDoesNotPublishPartialRoot) {
    auto                       format = nested_format();
    tlv::byte                  output[16]{};
    tlv::writer_storage<16, 1> storage;
    tlv::writer_builder        writer(tlv::span<tlv::byte>(output, sizeof(output)),
                                      tlv::native::borrow_format(format), storage.view());
    writer.write<1>("");
    EXPECT_THROW(writer.constructed<0xE1>([](tlv::writer_builder& parent) {
        parent.write<2>("");
        throw 42;
    }),
                 int);
    writer.write<3>("");
    EXPECT_EQ(TLV_ERR_INVALID_ARG, writer.status());
    EXPECT_EQ(2u, writer.size());
    EXPECT_FALSE(writer.finish());
}

TEST(Unit_Tlvpp_WriterBuilder, CustomContainerExceptionsPropagateThroughCallback) {
    struct throwing_container {
        const uint8_t* data() const {
            throw 42;
        }
        size_t size() const noexcept {
            return 1;
        }
    };
    auto                       format = nested_format();
    tlv::byte                  output[16]{};
    tlv::writer_storage<16, 1> storage;
    tlv::writer_builder        writer(tlv::span<tlv::byte>(output, sizeof(output)),
                                      tlv::native::borrow_format(format), storage.view());
    EXPECT_THROW(writer.constructed<0xE1>(
                     [](tlv::writer_builder& parent) { parent.write<1>(throwing_container{}); }),
                 int);
    EXPECT_EQ(TLV_ERR_INVALID_ARG, writer.status());
    EXPECT_EQ(0u, writer.size());
}

TEST(Unit_Tlvpp_WriterBuilder, CustomTypedFormatTrailersAndSinglePassMeasurement) {
    std::array<tlv::byte, 32>  staged{}, output{};
    tlv::writer_storage<32, 2> storage;
    int                        calls = 0;
    auto                       callback = [&](tlv::writer_builder& writer) {
        ++calls;
        writer.constructed<0xE1>([](tlv::writer_builder& parent) { parent.write<1>("A"); });
    };
    custom_cpp_format format;
    format.trailer = 0xEE;
    auto size = tlv::encoded_size<custom_cpp_format>(staged, storage.view(), callback, format);
    ASSERT_TRUE(size);
    EXPECT_EQ(1, calls);
    const uint8_t expected[] = {0xE1, 4, 1, 1, 'A', 0xEE, 0xEE};
    ASSERT_EQ(sizeof(expected), *size);
    expect_wire(staged.data(), expected);
    // Reuse measured output without replaying a stateful callback.
    tlv::writer<custom_cpp_format> writer(output.data(), output.size(), format);
    ASSERT_TRUE(writer.copy_encoded(tlv::bytes(staged.data(), *size)));
    EXPECT_EQ(1, calls);
    expect_wire(output.data(), expected);
}

TEST(Unit_Tlvpp_WriterBuilder, ContentDependentMeasurementReceivesCompleteChildren) {
    auto format = nested_format();
    format.measure = [](const void* context, const tlv_element_t* element, tlv_encoding_t* encoding,
                        tlv_format_error_t* error) {
        if (element->tag.size == 1 && element->tag.data[0] == 0xE1 &&
            (element->value.size != 3 || !element->value.data || element->value.data[0] != 1 ||
             element->value.data[2] != 42))
            return TLV_ERR_INVALID_VALUE;
        return tlv_fields_measure(context, element, encoding, error);
    };
    tlv::byte                  staged[16]{};
    tlv::writer_storage<16, 1> storage;
    auto size = tlv::encoded_size(staged, tlv::native::borrow_format(format), storage.view(),
                                  [](tlv::writer_builder& writer) {
                                      writer.constructed<0xE1>([](tlv::writer_builder& parent) {
                                          const uint8_t value[] = {42};
                                          parent.write<1>(value);
                                      });
                                  });
    ASSERT_TRUE(size);
    const uint8_t expected[] = {0xE1, 3, 1, 1, 42};
    ASSERT_EQ(sizeof(expected), *size);
    expect_wire(staged, expected);
}

TEST(Unit_Tlvpp_WriterBuilder, LtvOrderingUsesDestinationFormat) {
    auto layout = controlled::format_layout;
    layout.order = TLV_ELEMENT_ORDER_LTV;
    auto format = nested_format();
    format.context = &layout;
    tlv::byte                  output[16]{};
    tlv::writer_storage<16, 1> storage;
    auto result = tlv::encode(output, tlv::native::borrow_format(format), storage.view(),
                              [](tlv::writer_builder& writer) {
                                  writer.constructed<0xE1>(
                                      [](tlv::writer_builder& parent) { parent.write<1>("A"); });
                              });
    ASSERT_TRUE(result);
    const uint8_t expected[] = {3, 0xE1, 1, 1, 'A'};
    ASSERT_EQ(sizeof(expected), *result);
    expect_wire(output, expected);
}

#if OPENTLV_FORMAT_BER
TEST(Unit_Tlvpp_WriterBuilder, GenericLambdasUseScopedTemplates) {
    tlv::byte output[16]{};
    auto      result = tlv::ber::encode<16, 1>(output, [](auto& writer) {
        writer.template constructed<0x6F>([](auto& fci) { fci.template write<0x50>("VISA"); });
    });
    ASSERT_TRUE(result);
    const uint8_t expected[] = {0x6F, 6, 0x50, 4, 'V', 'I', 'S', 'A'};
    ASSERT_EQ(sizeof(expected), *result);
    expect_wire(output, expected);
}

TEST(Unit_Tlvpp_WriterBuilder, BerConvenienceAndMultibyteTags) {
    std::array<tlv::byte, 64> output{};
    const uint8_t             pan[] = {0x12, 0x34};
    auto                      result = tlv::ber::encode(output, [&](tlv::writer_builder& writer) {
        writer.write<0x5A>(pan);
        writer.constructed<0x6F>([](tlv::writer_builder& fci) {
            fci.write<0x84>("AID");
            fci.write<0x50>("VISA");
            fci.write<0x9F, 0x02>("");
        });
    });
    ASSERT_TRUE(result);
    const uint8_t expected[] = {0x5A, 2,    0x12, 0x34, 0x6F, 14,  0x84, 3,    'A',  'I',
                                'D',  0x50, 4,    'V',  'I',  'S', 'A',  0x9F, 0x02, 0};
    ASSERT_EQ(sizeof(expected), *result);
    expect_wire(output.data(), expected);
}

TEST(Unit_Tlvpp_WriterBuilder, BerLengthTransitionsAndExplicitWorkspace) {
    for (size_t size :
         {size_t(125), size_t(126), size_t(127), size_t(128), size_t(255), size_t(256)}) {
        tlv::byte                   output[300]{};
        std::vector<uint8_t>        value(size, 0xAB);
        tlv::writer_storage<300, 1> storage;
        auto result = tlv::ber::encode(output, storage.view(), [&](tlv::writer_builder& writer) {
            writer.constructed<0x6F>(
                [&](tlv::writer_builder& parent) { parent.write<0x84>(value); });
        });
        ASSERT_TRUE(result);
        std::vector<uint8_t> expected;
        // Explicit independently specified headers at both child and parent transitions.
        switch (size) {
            case 125: expected = {0x6F, 0x7F, 0x84, 0x7D}; break;
            case 126: expected = {0x6F, 0x81, 0x80, 0x84, 0x7E}; break;
            case 127: expected = {0x6F, 0x81, 0x81, 0x84, 0x7F}; break;
            case 128: expected = {0x6F, 0x81, 0x83, 0x84, 0x81, 0x80}; break;
            case 255: expected = {0x6F, 0x82, 0x01, 0x02, 0x84, 0x81, 0xFF}; break;
            case 256: expected = {0x6F, 0x82, 0x01, 0x04, 0x84, 0x82, 0x01, 0x00}; break;
        }
        expected.insert(expected.end(), size, 0xAB);
        ASSERT_EQ(expected.size(), *result);
        EXPECT_EQ(0, std::memcmp(output, expected.data(), expected.size()));
    }
}
#endif
