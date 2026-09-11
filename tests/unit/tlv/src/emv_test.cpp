#include "tlv/formats/asn1/ber.h"
#include "tlv/profiles/emv.h"
#include "tlv/reader/reader.h"
#include "tlv/writer/writer.h"
#include <gtest/gtest.h>
#include <cstring>
#include <set>
#include <vector>

namespace {
const tlv_emv_definition_t* find(tlv_tag_t tag, tlv_emv_context_t context = TLV_EMV_CONTEXT_BASE) {
    return tlv_emv_find(context, &tag);
}

template<class T>
void check_vector(const tlv_codec_t* codec, const T& expected,
                  std::initializer_list<uint8_t> raw) {
    ASSERT_NE(nullptr, codec);
    const std::vector<uint8_t> bytes(raw);
    T decoded{};
    ASSERT_EQ(TLV_CODEC_OK, tlv_codec_decode(codec, bytes.data(), bytes.size(), &decoded, sizeof(decoded)));
    uint8_t encoded[16] = {};
    size_t count = 99;
    ASSERT_EQ(TLV_CODEC_OK, tlv_codec_encode(codec, &expected, sizeof(expected), nullptr, 0, &count));
    ASSERT_EQ(bytes.size(), count);
    ASSERT_EQ(TLV_CODEC_OK, tlv_codec_encode(codec, &decoded, sizeof(decoded), encoded, sizeof(encoded), &count));
    EXPECT_EQ(bytes.size(), count);
    EXPECT_EQ(0, std::memcmp(encoded, bytes.data(), count));
    ASSERT_EQ(TLV_CODEC_OK, tlv_codec_encode(codec, &expected, sizeof(expected), encoded, sizeof(encoded), &count));
    EXPECT_EQ(0, std::memcmp(encoded, bytes.data(), count));
    EXPECT_EQ(TLV_CODEC_ERR_BUFFER_TOO_SHORT,
              tlv_codec_decode(codec, bytes.data(), bytes.size(), &decoded, sizeof(decoded) - 1));
    EXPECT_EQ(TLV_CODEC_ERR_BUFFER_TOO_SHORT,
              tlv_codec_encode(codec, &expected, sizeof(expected), encoded, bytes.size() - 1, &count));
    EXPECT_EQ(0u, count);
}
}

TEST(Unit_Emv, PublicTagConstantsMatchDefinitions) {
#define EMV_BEGIN(scope)
#define EMV_TAG(scope, name, size, b1, b2, min, max, step, kind, arg) \
    EXPECT_NE(nullptr, find(tlv_emv_tag_##name, TLV_EMV_CONTEXT_##scope));
#define EMV_END(scope)
#include "tlv/profiles/emv_tags.def"
#undef EMV_BEGIN
#undef EMV_TAG
#undef EMV_END
}

TEST(Unit_Emv, ScopeAndInvalidLookup) {
    EXPECT_STREQ("EMV Contact Book 3 v4.4 (October 2022)", TLV_EMV_SPECIFICATION);
    EXPECT_EQ(&tlv_emv_schema, tlv_emv_schema_for(TLV_EMV_CONTEXT_BASE));
    EXPECT_EQ(nullptr, tlv_emv_schema_for(static_cast<tlv_emv_context_t>(-1)));
    EXPECT_EQ(nullptr, tlv_emv_schema_for(TLV_EMV_CONTEXT_COUNT));
    EXPECT_EQ(nullptr, tlv_emv_find(TLV_EMV_CONTEXT_BASE, nullptr));
    EXPECT_EQ(nullptr, tlv_emv_find(TLV_EMV_CONTEXT_COUNT, &tlv_emv_tag_aip));
    const tlv_tag_t empty = {{0}, 0};
    EXPECT_EQ(nullptr, find(empty));
#if TLV_TAG_MAX_SIZE < 255
    tlv_tag_t invalid = {{0x82}, TLV_TAG_MAX_SIZE + 1};
    EXPECT_EQ(nullptr, find(invalid));
#endif
#if TLV_TAG_MAX_SIZE >= 3
    // Contact Book 3 defines one/two-byte tags. Kernel 2's three-byte tag
    // is still readable through generic BER but absent from every EMV table.
    const uint8_t wire[] = {0xDF, 0x81, 0x29, 0};
    tlv_view_t view;
    size_t consumed;
    ASSERT_EQ(TLV_OK, tlv_read(wire, sizeof(wire), &tlv_reader_format_ber, &view, &consumed));
    EXPECT_EQ(3u, view.tag.size);
    for (int c = 0; c < TLV_EMV_CONTEXT_COUNT; ++c)
        EXPECT_EQ(nullptr, find(view.tag, static_cast<tlv_emv_context_t>(c)));
#endif
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_emv_validate_length(nullptr, 1));
}

TEST(Unit_Emv, ContextPreventsTagCollisions) {
    const auto* amount = find(tlv_emv_tag_amount_authorised_binary);
    const auto* biometric = find(tlv_emv_tag_amount_authorised_binary, TLV_EMV_CONTEXT_BHT);
    ASSERT_NE(nullptr, amount);
    ASSERT_NE(nullptr, biometric);
    EXPECT_EQ(TLV_EMV_VALUE_NUMBER, amount->value_kind);
    EXPECT_EQ(TLV_EMV_VALUE_BIOMETRIC, biometric->value_kind);
    EXPECT_EQ(TLV_OK, tlv_emv_validate_length(amount, 4));
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_emv_validate_length(biometric, 4));
    EXPECT_EQ(nullptr, find(tlv_emv_tag_tvr, TLV_EMV_CONTEXT_BHT));
    EXPECT_EQ(1u, find(tlv_emv_tag_aip, TLV_EMV_CONTEXT_BHT)->schema->max_length);
#if TLV_TAG_MAX_SIZE >= 2
    const auto* counter = find(tlv_emv_tag_iris_try_counter, TLV_EMV_CONTEXT_BIOMETRIC_COUNTERS);
    const auto* mac = find(tlv_emv_tag_iris_try_counter, TLV_EMV_CONTEXT_BIOMETRIC_VERIFICATION);
    ASSERT_NE(nullptr, counter);
    ASSERT_NE(nullptr, mac);
    EXPECT_EQ(1u, counter->schema->max_length);
    EXPECT_EQ(8u, mac->schema->max_length);
    EXPECT_EQ(nullptr, mac->codec);
    EXPECT_EQ(nullptr, find(tlv_emv_tag_iris_try_counter));
#endif
}

TEST(Unit_Emv, NonContiguousLengthRules) {
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_emv_validate_length(find(tlv_emv_tag_afl), 5));
    EXPECT_EQ(TLV_OK, tlv_schema_validate_length(find(tlv_emv_tag_afl)->schema, 5));
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_emv_validate_length(find(tlv_emv_tag_cvm_list), 11));
#if TLV_TAG_MAX_SIZE >= 2
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_emv_validate_length(find(tlv_emv_tag_bic), 9));
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_emv_validate_length(find(tlv_emv_tag_language_preference), 3));
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_emv_validate_length(find(tlv_emv_tag_issuer_public_key_exponent), 2));
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_emv_validate_length(find(tlv_emv_tag_application_reference_currency), 3));
#endif
}

TEST(Unit_Emv, SemanticErrorsAndUnalignedStorage) {
    const auto* number_codec = find(tlv_emv_tag_amount_authorised_binary)->codec;
    alignas(uint64_t) uint8_t storage[sizeof(uint64_t) + 1] = {};
    const uint8_t raw[] = {0xFF, 0xFF, 0xFF, 0xFF};
    ASSERT_EQ(TLV_CODEC_OK, tlv_codec_decode(number_codec, raw, 4, storage + 1, sizeof(uint64_t)));
    uint64_t number;
    std::memcpy(&number, storage + 1, sizeof(number));
    EXPECT_EQ(UINT64_C(4294967295), number);
    uint8_t wire[8];
    size_t written;
    ASSERT_EQ(TLV_CODEC_OK, tlv_codec_encode(number_codec, storage + 1, sizeof(uint64_t), wire, 4, &written));
    EXPECT_EQ(0, std::memcmp(raw, wire, 4));
    number = UINT64_C(4294967296);
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE, tlv_codec_encode(number_codec, &number, sizeof(number), nullptr, 0, &written));
    EXPECT_EQ(0u, written);

    const auto* date_codec = find(tlv_emv_tag_transaction_date)->codec;
    const tlv_emv_date_t bad_dates[] = {{23, 2, 29}, {24, 0, 1}, {24, 13, 1}, {24, 4, 31}, {100, 1, 1}, {24, 1, 0}};
    for (const auto& date : bad_dates)
        EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE, tlv_codec_encode(date_codec, &date, sizeof(date), nullptr, 0, &written));
    const auto* bio_codec = find(tlv_emv_tag_biometric_type, TLV_EMV_CONTEXT_BHT)->codec;
    const auto invalid_bio = static_cast<tlv_emv_biometric_type_t>(3);
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE, tlv_codec_encode(bio_codec, &invalid_bio, sizeof(invalid_bio), nullptr, 0, &written));
    const uint8_t invalid_bio_bytes[] = {3};
    tlv_emv_biometric_type_t bio;
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE, tlv_codec_decode(bio_codec, invalid_bio_bytes, 1, &bio, sizeof(bio)));
#if TLV_TAG_MAX_SIZE >= 2
    const auto* time_codec = find(tlv_emv_tag_transaction_time)->codec;
    const tlv_emv_time_t bad_times[] = {{24, 0, 0}, {0, 60, 0}, {0, 0, 60}};
    for (const auto& time : bad_times)
        EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE, tlv_codec_encode(time_codec, &time, sizeof(time), nullptr, 0, &written));
    const uint8_t invalid_time[] = {0x24, 0, 0};
    tlv_emv_time_t time;
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE, tlv_codec_decode(time_codec, invalid_time, 3, &time, sizeof(time)));
    const auto* cryptogram_codec = find(tlv_emv_tag_cryptogram_information_data)->codec;
    tlv_emv_cryptogram_info_t bad_info = {TLV_EMV_CRYPTOGRAM_TC, 64};
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE, tlv_codec_encode(cryptogram_codec, &bad_info, sizeof(bad_info), nullptr, 0, &written));
    bad_info = {static_cast<tlv_emv_cryptogram_type_t>(4), 0};
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE, tlv_codec_encode(cryptogram_codec, &bad_info, sizeof(bad_info), nullptr, 0, &written));
    check_vector(cryptogram_codec, tlv_emv_cryptogram_info_t{TLV_EMV_CRYPTOGRAM_RFU, 63}, {0xFF});
    const auto* list_codec = find(tlv_emv_tag_application_reference_currency_exponent)->codec;
    tlv_emv_number_list_t list = {{10, 0, 0, 0}, 1};
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE, tlv_codec_encode(list_codec, &list, sizeof(list), nullptr, 0, &written));
    list = {{0}, 5};
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE, tlv_codec_encode(list_codec, &list, sizeof(list), nullptr, 0, &written));
    list.count = 0;
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE, tlv_codec_encode(list_codec, &list, sizeof(list), nullptr, 0, &written));
    const uint8_t invalid_list[] = {0x10};
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE, tlv_codec_decode(list_codec, invalid_list, 1, &list, sizeof(list)));
    const auto invalid_account = static_cast<tlv_emv_account_type_t>(40);
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE, tlv_codec_encode(find(tlv_emv_tag_account_type)->codec, &invalid_account, sizeof(invalid_account), nullptr, 0, &written));
#endif
}



TEST(Unit_Emv, AmountCodecRejectsInvalidInputs) {
    uint64_t amount = 1000000000000ULL;
    uint8_t wire[7] = {};
    size_t written = 99;
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE, tlv_codec_encode(&tlv_emv_codec_amount, &amount, sizeof(amount), nullptr, 0, &written));
    EXPECT_EQ(0u, written);
    amount = 0;
    EXPECT_EQ(TLV_CODEC_ERR_BUFFER_TOO_SHORT, tlv_codec_encode(&tlv_emv_codec_amount, &amount, sizeof(amount), wire, 5, &written));
    EXPECT_EQ(0u, written);
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE, tlv_codec_encode(&tlv_emv_codec_amount, &amount, 1, wire, 6, &written));
    EXPECT_EQ(TLV_CODEC_ERR_BUFFER_TOO_SHORT, tlv_codec_decode(&tlv_emv_codec_amount, wire, 6, &amount, 1));
    for (size_t size : {0u, 5u, 7u})
        EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE, tlv_codec_decode(&tlv_emv_codec_amount, wire, size, &amount, sizeof(amount)));
    EXPECT_EQ(TLV_CODEC_ERR_NULL_ARG, tlv_codec_decode(&tlv_emv_codec_amount, nullptr, 6, &amount, sizeof(amount)));
    for (size_t pos = 0; pos < 6; ++pos) {
        for (unsigned digit = 10; digit <= 15; ++digit) {
            for (unsigned shift : {0u, 4u}) {
                std::memset(wire, 0, sizeof(wire));
                wire[pos] = static_cast<uint8_t>(digit << shift);
                EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE, tlv_codec_decode(&tlv_emv_codec_amount, wire, 6, &amount, sizeof(amount)));
            }
        }
    }
}

TEST(Unit_Emv, CoversContactBook3TagSet) {
    // Independent fixture transcribed from Book 3 v4.4 Annex A Table 38.
    // Repeated context-specific meanings are covered separately above.
    const unsigned expected[] = {
        0x42, 0x4F, 0x50, 0x57, 0x5A, 0x5F20, 0x5F24, 0x5F25, 0x5F28, 0x5F2A, 0x5F2D, 0x5F30,
        0x5F34, 0x5F36, 0x5F50, 0x5F53, 0x5F54, 0x5F55, 0x5F56, 0x5F57, 0x61, 0x6F, 0x70, 0x71,
        0x72, 0x73, 0x77, 0x7F60, 0x80, 0x81, 0x82, 0x83, 0x84, 0x86, 0x87, 0x88,
        0x89, 0x8A, 0x8C, 0x8D, 0x8E, 0x8F, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95,
        0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9F01, 0x9F02, 0x9F03, 0x9F04, 0x9F05,
        0x9F06, 0x9F07, 0x9F08, 0x9F09, 0x9F0A, 0x9F0B, 0x9F0C, 0x9F0D, 0x9F0E, 0x9F0F, 0x9F10, 0x9F11,
        0x9F12, 0x9F13, 0x9F14, 0x9F15, 0x9F16, 0x9F17, 0x9F18, 0x9F19, 0x9F1A, 0x9F1B, 0x9F1C, 0x9F1D,
        0x9F1E, 0x9F1F, 0x9F20, 0x9F21, 0x9F22, 0x9F23, 0x9F24, 0x9F25, 0x9F26, 0x9F27, 0x9F2D, 0x9F2E,
        0x9F2F, 0x9F30, 0x9F31, 0x9F32, 0x9F33, 0x9F34, 0x9F35, 0x9F36, 0x9F37, 0x9F38, 0x9F39, 0x9F3A,
        0x9F3B, 0x9F3C, 0x9F3D, 0x9F40, 0x9F41, 0x9F42, 0x9F43, 0x9F44, 0x9F45, 0x9F46, 0x9F47, 0x9F48,
        0x9F49, 0x9F4A, 0x9F4B, 0x9F4C, 0x9F4D, 0x9F4E, 0x9F4F, 0xA1, 0xA5, 0xBF0C, 0xBF4A, 0xBF4B,
        0xBF4C, 0xBF4D, 0xBF4E, 0xDF50, 0xDF51, 0xDF52, 0xDF53, 0xDF54,
        // Additional nested tags in Annex C Tables 48/51/52.
        0x02, 0x85, 0xA2, 0xB1
    };
    std::set<unsigned> actual;
    for (int c = 0; c < TLV_EMV_CONTEXT_COUNT; ++c) {
        const auto* schema = tlv_emv_schema_for(static_cast<tlv_emv_context_t>(c));
        for (size_t i = 0; i < schema->count; ++i) {
            const auto& tag = schema->entries[i].tag;
            ASSERT_LE(tag.size, 2u);
            unsigned number = tag.data[0];
#if TLV_TAG_MAX_SIZE >= 2
            if (tag.size == 2) number = (number << 8) | tag.data[1];
#endif
            actual.insert(number);
        }
    }
    std::set<unsigned> wanted;
    for (unsigned tag : expected) {
        if (TLV_TAG_MAX_SIZE >= 2 || tag <= 255) wanted.insert(tag);
    }
    EXPECT_EQ(wanted, actual);
}
