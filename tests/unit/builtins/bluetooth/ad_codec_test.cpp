#include "tlv/builtins/bluetooth/ad_codec.h"
#include <gtest/gtest.h>
#include <cstring>
#include <vector>

namespace {
void check_span(const tlv_codec_t& codec, const std::vector<uint8_t>& bytes,
                tlv_codec_result_t expected) {
    tlv_value_t decoded = {};
    EXPECT_EQ(expected,
              tlv_codec_decode(&codec, bytes.data(), bytes.size(), &decoded, sizeof(decoded)));
    if (expected == TLV_CODEC_OK) {
        EXPECT_EQ(bytes.data(), decoded.data);
        EXPECT_EQ(bytes.size(), decoded.size);
    }
    const tlv_value_t input = {bytes.data(), bytes.size()};
    size_t            written = SIZE_MAX;
    EXPECT_EQ(expected, tlv_codec_encode(&codec, &input, sizeof(input), nullptr, 0, &written));
    EXPECT_EQ(expected == TLV_CODEC_OK ? bytes.size() : 0u, written);
    std::vector<uint8_t> output(bytes.size() + 1, 0xA5);
    written = SIZE_MAX;
    EXPECT_EQ(expected, tlv_codec_encode(&codec, &input, sizeof(input), output.data(), bytes.size(),
                                         &written));
    EXPECT_EQ(expected == TLV_CODEC_OK ? bytes.size() : 0u, written);
    EXPECT_EQ(0xA5, output.back());
    if (expected == TLV_CODEC_OK && !bytes.empty())
        EXPECT_EQ(0, std::memcmp(bytes.data(), output.data(), bytes.size()));
}
} // namespace

TEST(Unit_Tlv_BluetoothAdCodec, FlagsBorrowBytesAndExposeDefinedBits) {
    const uint8_t bytes[] = {0x06};
    tlv_value_t   flags = {};
    ASSERT_EQ(TLV_CODEC_OK, tlv_codec_decode(&tlv_bluetooth_ad_codec_flags, bytes, sizeof(bytes),
                                             &flags, sizeof(flags)));
    EXPECT_EQ(bytes, flags.data);
    EXPECT_EQ(1u, flags.size);
    EXPECT_FALSE(
        tlv_bluetooth_ad_flags_test(&flags, TLV_BLUETOOTH_AD_FLAG_LE_LIMITED_DISCOVERABLE));
    EXPECT_TRUE(tlv_bluetooth_ad_flags_test(&flags, TLV_BLUETOOTH_AD_FLAG_LE_GENERAL_DISCOVERABLE));
    EXPECT_TRUE(tlv_bluetooth_ad_flags_test(&flags, TLV_BLUETOOTH_AD_FLAG_BR_EDR_NOT_SUPPORTED));
    EXPECT_FALSE(tlv_bluetooth_ad_flags_test(
        &flags, TLV_BLUETOOTH_AD_FLAG_SIMULTANEOUS_LE_BR_EDR_CONTROLLER));
    EXPECT_FALSE(tlv_bluetooth_ad_flags_test(&flags, 0));
    EXPECT_FALSE(tlv_bluetooth_ad_flags_test(nullptr, 0xFF));
    for (uint8_t mask : {uint8_t(1), uint8_t(2), uint8_t(4), uint8_t(8)}) {
        const tlv_value_t one = {&mask, 1};
        EXPECT_TRUE(tlv_bluetooth_ad_flags_test(&one, mask));
        EXPECT_FALSE(tlv_bluetooth_ad_flags_test(&one, static_cast<uint8_t>(~mask)));
    }
}

TEST(Unit_Tlv_BluetoothAdCodec, FlagsSupportEmptyAndExtensionsWithoutDiscardingUnknownBits) {
    for (const auto& bytes :
         std::vector<std::vector<uint8_t>>{{}, {0x06}, {0x10}, {0xFF}, {0, 0, 0x80}, {0x06, 0x80}})
        check_span(tlv_bluetooth_ad_codec_flags, bytes, TLV_CODEC_OK);
    for (const auto& bytes : std::vector<std::vector<uint8_t>>{{0}, {0, 0}, {0x06, 0}})
        check_span(tlv_bluetooth_ad_codec_flags, bytes, TLV_CODEC_ERR_INVALID_VALUE);
    tlv_value_t empty = {};
    EXPECT_EQ(TLV_CODEC_OK,
              tlv_codec_decode(&tlv_bluetooth_ad_codec_flags, nullptr, 0, &empty, sizeof(empty)));
    EXPECT_FALSE(tlv_bluetooth_ad_flags_test(&empty, 0xFF));
}

TEST(Unit_Tlv_BluetoothAdCodec, TxPowerSignedRoundTripAndBluetoothRange) {
    for (int power = -127; power <= 127; ++power) {
        SCOPED_TRACE(power);
        const int8_t  input = static_cast<int8_t>(power);
        const uint8_t wire = static_cast<uint8_t>(power);
        int8_t        decoded = 0;
        ASSERT_EQ(TLV_CODEC_OK, tlv_codec_decode(&tlv_bluetooth_ad_codec_tx_power, &wire, 1,
                                                 &decoded, sizeof(decoded)));
        EXPECT_EQ(power, decoded);
        size_t written = 0;
        ASSERT_EQ(TLV_CODEC_OK, tlv_codec_encode(&tlv_bluetooth_ad_codec_tx_power, &input,
                                                 sizeof(input), nullptr, 0, &written));
        EXPECT_EQ(1u, written);
        uint8_t output[2] = {0, 0xA5};
        ASSERT_EQ(TLV_CODEC_OK, tlv_codec_encode(&tlv_bluetooth_ad_codec_tx_power, &input,
                                                 sizeof(input), output, 1, &written));
        EXPECT_EQ(wire, output[0]);
        EXPECT_EQ(0xA5, output[1]);
    }
    const uint8_t negative_four = 0xFC;
    int8_t        decoded = 0;
    EXPECT_EQ(TLV_CODEC_OK, tlv_codec_decode(&tlv_bluetooth_ad_codec_tx_power, &negative_four, 1,
                                             &decoded, sizeof(decoded)));
    EXPECT_EQ(-4, decoded);
    const uint8_t invalid[] = {0x80, 0};
    for (size_t length : {size_t(0), size_t(1), size_t(2)})
        EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
                  tlv_codec_decode(&tlv_bluetooth_ad_codec_tx_power, invalid, length, &decoded,
                                   sizeof(decoded)));
    const int8_t invalid_power = INT8_MIN;
    size_t       written = 99;
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
              tlv_codec_encode(&tlv_bluetooth_ad_codec_tx_power, &invalid_power,
                               sizeof(invalid_power), nullptr, 0, &written));
    EXPECT_EQ(0u, written);
}

TEST(Unit_Tlv_BluetoothAdCodec, NamesBorrowCompleteUtf8IncludingEmptyAndEmbeddedNull) {
    const std::vector<std::vector<uint8_t>> valid = {
        {},
        {'S', 'e', 'n', 's', 'o', 'r'},
        {'A', 0, 'B'},
        {0x7F},
        {0xC2, 0x80},
        {0xDF, 0xBF},
        {0xE0, 0xA0, 0x80},
        {0xED, 0x9F, 0xBF},
        {0xEE, 0x80, 0x80},
        {0xEF, 0xBF, 0xBF},
        {0xF0, 0x90, 0x80, 0x80},
        {0xF4, 0x8F, 0xBF, 0xBF},
        {'S', 0xC3, 0xA9, 0xE2, 0x82, 0xAC, 0xF0, 0x9F, 0x98, 0x80}};
    for (const auto& bytes : valid)
        check_span(tlv_bluetooth_ad_codec_local_name, bytes, TLV_CODEC_OK);
    check_span(tlv_bluetooth_ad_codec_local_name, std::vector<uint8_t>(248, 'a'), TLV_CODEC_OK);
    check_span(tlv_bluetooth_ad_codec_local_name, std::vector<uint8_t>(249, 'a'),
               TLV_CODEC_ERR_INVALID_VALUE);
}

TEST(Unit_Tlv_BluetoothAdCodec, NamesRejectMalformedUtf8InBothDirections) {
    const std::vector<std::vector<uint8_t>> invalid = {{0x80},
                                                       {0xBF},
                                                       {0xC0, 0x80},
                                                       {0xC1, 0xBF},
                                                       {0xC2},
                                                       {0xC2, 'A'},
                                                       {0xE0, 0x9F, 0xBF},
                                                       {0xE2, 0x82},
                                                       {0xE2, 0x82, 'A'},
                                                       {0xED, 0xA0, 0x80},
                                                       {0xED, 0xBF, 0xBF},
                                                       {0xF0, 0x8F, 0xBF, 0xBF},
                                                       {0xF0, 0x90, 0x80},
                                                       {0xF4, 0x90, 0x80, 0x80},
                                                       {0xF5, 0x80, 0x80, 0x80},
                                                       {0xFE},
                                                       {0xFF},
                                                       {'a', 0xFF}};
    for (const auto& bytes : invalid)
        check_span(tlv_bluetooth_ad_codec_local_name, bytes, TLV_CODEC_ERR_INVALID_VALUE);
}

TEST(Unit_Tlv_BluetoothAdCodec, NullArgumentsObjectSizesAndDestinationBounds) {
    const uint8_t     raw = 0x06;
    const tlv_value_t span = {&raw, 1};
    const int8_t      power = -4;
    struct Case {
        const tlv_codec_t* codec;
        const void*        value;
        size_t             size;
    };
    const Case cases[] = {{&tlv_bluetooth_ad_codec_flags, &span, sizeof(span)},
                          {&tlv_bluetooth_ad_codec_local_name, &span, sizeof(span)},
                          {&tlv_bluetooth_ad_codec_tx_power, &power, sizeof(power)}};
    for (const auto& test : cases) {
        tlv_value_t storage = {};
        EXPECT_EQ(TLV_CODEC_ERR_NULL_ARG,
                  tlv_codec_decode(test.codec, nullptr, 1, &storage, sizeof(storage)));
        EXPECT_EQ(TLV_CODEC_ERR_NULL_ARG,
                  tlv_codec_decode(test.codec, &raw, 1, nullptr, test.size));
        EXPECT_EQ(TLV_CODEC_ERR_BUFFER_TOO_SHORT,
                  tlv_codec_decode(test.codec, &raw, 1, &storage, test.size - 1));
        size_t  written = 99;
        uint8_t output = 0xA5;
        EXPECT_EQ(TLV_CODEC_ERR_BUFFER_TOO_SHORT,
                  tlv_codec_encode(test.codec, test.value, test.size, &output, 0, &written));
        EXPECT_EQ(0u, written);
        EXPECT_EQ(0xA5, output);
        for (size_t size : {test.size - 1, test.size + 1}) {
            written = 99;
            EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
                      tlv_codec_encode(test.codec, test.value, size, nullptr, 0, &written));
            EXPECT_EQ(0u, written);
        }
        EXPECT_EQ(TLV_CODEC_ERR_NULL_ARG,
                  tlv_codec_encode(test.codec, nullptr, test.size, nullptr, 0, &written));
        EXPECT_EQ(TLV_CODEC_ERR_NULL_ARG,
                  tlv_codec_encode(test.codec, test.value, test.size, nullptr, 1, &written));
        EXPECT_EQ(TLV_CODEC_ERR_NULL_ARG,
                  tlv_codec_encode(test.codec, test.value, test.size, nullptr, 0, nullptr));
    }
}

TEST(Unit_Tlv_BluetoothAdCodec, SpanEncodeValidatesBorrowedPointerAndNativeSize) {
    for (const auto* codec : {&tlv_bluetooth_ad_codec_flags, &tlv_bluetooth_ad_codec_local_name}) {
        tlv_value_t span = {nullptr, 1};
        size_t      written = 99;
        EXPECT_EQ(TLV_CODEC_ERR_NULL_ARG,
                  tlv_codec_encode(codec, &span, sizeof(span), nullptr, 0, &written));
        EXPECT_EQ(0u, written);
        span.size = 0;
        EXPECT_EQ(TLV_CODEC_OK, tlv_codec_encode(codec, &span, sizeof(span), nullptr, 0, &written));
        EXPECT_EQ(0u, written);
#if SIZE_MAX < UINT64_MAX
        const uint8_t byte = 1;
        span = {&byte, static_cast<tlv_size_t>(SIZE_MAX) + 1};
        EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
                  tlv_codec_encode(codec, &span, sizeof(span), nullptr, 0, &written));
        EXPECT_EQ(0u, written);
#endif
    }
}
