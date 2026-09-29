#include "tlv/builtins/emv/presentation.h"
#include "tlv/builtins/emv/format.h"
#include "tlv/builtins/emv/emv.h"
#include "tlv/reader/reader.h"
#include "tlv/reader/walker.h"
#include "tlv/writer/writer.h"
#include "tlv/query/query.h"
#include "tlv/config.h"
#if OPENTLV_DOCUMENT
#include "tlv/document/document.h"
#include <memory>
#endif
#include <gtest/gtest.h>
#include <cstring>
#include <set>
#include <vector>

namespace {
const tlv_emv_definition_t* find(tlv_tag_t tag, tlv_emv_context_t context = TLV_EMV_CONTEXT_BASE) {
    return tlv_emv_find(context, &tag);
}

template <class T>
void check_vector(const tlv_codec_t* codec, const T& expected, std::initializer_list<uint8_t> raw) {
    ASSERT_NE(nullptr, codec);
    const std::vector<uint8_t> bytes(raw);
    T                          decoded{};
    ASSERT_EQ(TLV_CODEC_OK,
              tlv_codec_decode(codec, bytes.data(), bytes.size(), &decoded, sizeof(decoded)));
    uint8_t encoded[16] = {};
    size_t  count = 99;
    ASSERT_EQ(TLV_CODEC_OK,
              tlv_codec_encode(codec, &expected, sizeof(expected), nullptr, 0, &count));
    ASSERT_EQ(bytes.size(), count);
    ASSERT_EQ(TLV_CODEC_OK,
              tlv_codec_encode(codec, &decoded, sizeof(decoded), encoded, sizeof(encoded), &count));
    EXPECT_EQ(bytes.size(), count);
    EXPECT_EQ(0, std::memcmp(encoded, bytes.data(), count));
    ASSERT_EQ(TLV_CODEC_OK, tlv_codec_encode(codec, &expected, sizeof(expected), encoded,
                                             sizeof(encoded), &count));
    EXPECT_EQ(0, std::memcmp(encoded, bytes.data(), count));
    EXPECT_EQ(TLV_CODEC_ERR_BUFFER_TOO_SHORT,
              tlv_codec_decode(codec, bytes.data(), bytes.size(), &decoded, sizeof(decoded) - 1));
    EXPECT_EQ(TLV_CODEC_ERR_BUFFER_TOO_SHORT, tlv_codec_encode(codec, &expected, sizeof(expected),
                                                               encoded, bytes.size() - 1, &count));
    EXPECT_EQ(0u, count);
}
} // namespace

TEST(Integration_Tlv_Emv, CallerSelectsAmountCodecFromParsedIdentifier) {
    const std::vector<std::vector<uint8_t>> encodings{{0x9F, 0x02, 0x06, 0, 0, 0, 0, 0x12, 0x34},
                                                      {0x81, 0x04, 0, 0, 0x04, 0xD2}};
    for (const auto& wire : encodings) {
        tlv_element_t element{};
        size_t        consumed = 0;
        ASSERT_EQ(TLV_OK, tlv_read(wire.data(), wire.size(), &tlv_format_emv, &element, &consumed));
        ASSERT_EQ(wire.size(), consumed);
        const auto* entry = tlv_emv_find(TLV_EMV_CONTEXT_BASE, &element.tag);
        ASSERT_NE(nullptr, entry);
        ASSERT_NE(nullptr, entry->codec);
        ASSERT_EQ(TLV_EMV_VALUE_NUMBER, tlv_emv_builtin_value_kind(entry));
        size_t size = 0;
        ASSERT_EQ(TLV_OK, tlv_size_to_native(element.value.size, &size));
        uint64_t decoded = 0;
        ASSERT_EQ(TLV_CODEC_OK, tlv_codec_decode(entry->codec, element.value.data, size, &decoded,
                                                 sizeof(decoded)));
        EXPECT_EQ(UINT64_C(1234), decoded);
        // The already selected codec also operates on standalone Value bytes.
        std::vector<uint8_t> value(element.value.data, element.value.data + size);
        decoded = 0;
        ASSERT_EQ(TLV_CODEC_OK, tlv_codec_decode(entry->codec, value.data(), value.size(), &decoded,
                                                 sizeof(decoded)));
        EXPECT_EQ(UINT64_C(1234), decoded);
    }
}

TEST(Integration_Tlv_Emv, AllDefinitionsUseEmvFramingAndSchemas) {
    for (int ctx = 0; ctx < TLV_EMV_CONTEXT_COUNT; ++ctx) {
        auto        context = static_cast<tlv_emv_context_t>(ctx);
        const auto* schema = tlv_emv_schema_for(context);
        ASSERT_NE(nullptr, schema);
        std::set<unsigned> unique;
        for (size_t i = 0; i < schema->count; ++i) {
            const auto& entry = schema->entries[i];
            unsigned    tag = entry.tag.data[0];
            if (entry.tag.size == 2) tag = (tag << 8) | entry.tag.data[1];
            ASSERT_TRUE(unique.insert(tag).second) << ctx << ": duplicate tag " << tag;
            const auto* definition = tlv_emv_find(context, &entry.tag);
            ASSERT_NE(nullptr, definition);
            EXPECT_EQ(&entry, definition->schema);
            EXPECT_NE(nullptr, tlv_emv_symbol(definition));
            EXPECT_EQ(tlv_emv_builtin_value_kind(definition) > TLV_EMV_VALUE_TEMPLATE,
                      definition->codec != nullptr);
            EXPECT_EQ(TLV_OK, tlv_emv_validate_length(definition, entry.min_length));
            EXPECT_EQ(TLV_OK, tlv_emv_validate_length(definition, entry.max_length));
            if (entry.min_length)
                EXPECT_EQ(TLV_ERR_INVALID_LENGTH,
                          tlv_emv_validate_length(definition, entry.min_length - 1));
            if (entry.max_length != SIZE_MAX)
                EXPECT_EQ(TLV_ERR_INVALID_LENGTH,
                          tlv_emv_validate_length(definition, entry.max_length + 1));

            const size_t length =
                entry.max_length == SIZE_MAX ? entry.min_length : entry.max_length;
            std::vector<uint8_t> value(length, 0x5A), wire(length + 16);
            tlv_writer_t         writer;
            ASSERT_EQ(TLV_OK, tlv_writer_init(&writer, wire.data(), wire.size(), &tlv_format_emv));
            ASSERT_EQ(TLV_OK, tlv_writer_write(&writer, entry.tag, value.data(), length));
            EXPECT_EQ(0, std::memcmp(wire.data(), entry.tag.data, entry.tag.size));
            tlv_reader_t reader;
            ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, wire.data(), writer.pos, &tlv_format_emv));
            tlv_element_t element;
            ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &element));
            EXPECT_TRUE(tlv_reader_at_end(&reader));
            EXPECT_EQ(&entry, tlv_schema_find(schema, &element.tag));
            EXPECT_EQ(length, element.value.size);
            EXPECT_EQ(wire.data() + writer.pos - length, element.value.data);
            if (length) EXPECT_EQ(0, std::memcmp(value.data(), element.value.data, length));
        }
    }
}

TEST(Integration_Tlv_Emv, NumbersFlagsAndDecimalConstraints) {
    check_vector<uint64_t>(find(tlv_emv_tag_amount_authorised_binary)->codec, 123456,
                           {0, 1, 0xE2, 0x40});
    check_vector<uint64_t>(find(tlv_emv_tag_tvr)->codec, UINT64_C(0x8040201008),
                           {0x80, 0x40, 0x20, 0x10, 8});
    check_vector<uint64_t>(find(tlv_emv_tag_aip)->codec,
                           TLV_EMV_AIP_SDA_SUPPORTED | TLV_EMV_AIP_CDA_SUPPORTED, {0x41, 0});
    check_vector<uint64_t>(find(tlv_emv_tag_transaction_type)->codec, 20, {0x20});
    check_vector<uint64_t>(find(tlv_emv_tag_atc)->codec, 258, {1, 2});
    check_vector<uint64_t>(find(tlv_emv_tag_transaction_currency_code)->codec, 978, {0x09, 0x78});
    check_vector<uint64_t>(find(tlv_emv_tag_issuer_public_key_exponent)->codec, 65537, {1, 0, 1});
    check_vector<uint64_t>(find(tlv_emv_tag_transaction_sequence_counter)->codec, 12345,
                           {1, 0x23, 0x45});
    const uint8_t invalid_currency[] = {0x19, 0x78};
    uint64_t      number;
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
              tlv_codec_decode(find(tlv_emv_tag_transaction_currency_code)->codec, invalid_currency,
                               2, &number, sizeof(number)));
    const uint8_t invalid_exponent[] = {0x10};
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
              tlv_codec_decode(find(tlv_emv_tag_application_currency_exponent)->codec,
                               invalid_exponent, 1, &number, sizeof(number)));
    number = 1000;
    size_t written;
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
              tlv_codec_encode(find(tlv_emv_tag_transaction_currency_code)->codec, &number,
                               sizeof(number), nullptr, 0, &written));
}

TEST(Integration_Tlv_Emv, PanPreservesLeadingZeroesAndStripsOnlyTrailingPadding) {
    const auto*   codec = find(tlv_emv_tag_pan)->codec;
    const uint8_t raw[] = {0x00, 0x12, 0x34, 0x5F, 0xFF};
    char          digits[20];
    ASSERT_EQ(TLV_CODEC_OK, tlv_codec_decode(codec, raw, sizeof(raw), digits, sizeof(digits)));
    EXPECT_STREQ("0012345", digits);
    uint8_t out[10];
    size_t  written;
    ASSERT_EQ(TLV_CODEC_OK,
              tlv_codec_encode(codec, digits, std::strlen(digits), nullptr, 0, &written));
    EXPECT_EQ(4u, written);
    ASSERT_EQ(TLV_CODEC_OK,
              tlv_codec_encode(codec, digits, std::strlen(digits), out, sizeof(out), &written));
    EXPECT_EQ(0, std::memcmp(raw, out, 4));
    EXPECT_EQ(TLV_CODEC_ERR_BUFFER_TOO_SHORT, tlv_codec_decode(codec, raw, sizeof(raw), digits, 7));
    EXPECT_EQ(TLV_CODEC_ERR_BUFFER_TOO_SHORT, tlv_codec_encode(codec, "123", 3, out, 1, &written));
    const uint8_t bad[][2] = {{0x1F, 0x23}, {0x1A, 0x23}, {0xFF, 0xFF}};
    for (const auto& bytes : bad)
        EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
                  tlv_codec_decode(codec, bytes, 2, digits, sizeof(digits)));
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE, tlv_codec_encode(codec, "", 0, nullptr, 0, &written));
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE, tlv_codec_encode(codec, "12F", 3, nullptr, 0, &written));
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
              tlv_codec_encode(codec, "12345678901234567890", 20, nullptr, 0, &written));
}

TEST(Integration_Tlv_Emv, DatesTimesAndEnums) {
    check_vector(find(tlv_emv_tag_transaction_date)->codec, tlv_emv_date_t{24, 2, 29},
                 {0x24, 0x02, 0x29});
    uint8_t        invalid_date[] = {0x23, 0x02, 0x29};
    tlv_emv_date_t date;
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
              tlv_codec_decode(find(tlv_emv_tag_transaction_date)->codec, invalid_date, 3, &date,
                               sizeof(date)));
    check_vector(find(tlv_emv_tag_biometric_type, TLV_EMV_CONTEXT_BHT)->codec,
                 TLV_EMV_BIOMETRIC_PALM, {2, 0, 0});
    check_vector(find(tlv_emv_tag_transaction_time)->codec, tlv_emv_time_t{23, 59, 58},
                 {0x23, 0x59, 0x58});
    check_vector(find(tlv_emv_tag_account_type)->codec, TLV_EMV_ACCOUNT_CREDIT, {0x30});
    check_vector(find(tlv_emv_tag_cryptogram_information_data)->codec,
                 tlv_emv_cryptogram_info_t{TLV_EMV_CRYPTOGRAM_ARQC, 0x15}, {0x95});
    const uint8_t          bad_account[] = {0x40};
    tlv_emv_account_type_t account;
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
              tlv_codec_decode(find(tlv_emv_tag_account_type)->codec, bad_account, 1, &account,
                               sizeof(account)));
}

TEST(Integration_Tlv_Emv, CurrencyListsAreNotSingleNumbers) {
    check_vector(find(tlv_emv_tag_application_reference_currency)->codec,
                 tlv_emv_number_list_t{{978, 840, 0, 0}, 2}, {0x09, 0x78, 0x08, 0x40});
    check_vector(find(tlv_emv_tag_application_reference_currency_exponent)->codec,
                 tlv_emv_number_list_t{{2, 0, 3, 0}, 3}, {2, 0, 3});
    const uint8_t         odd[] = {0x09, 0x78, 0};
    tlv_emv_number_list_t list;
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
              tlv_codec_decode(find(tlv_emv_tag_application_reference_currency)->codec, odd, 3,
                               &list, sizeof(list)));
}

TEST(Integration_Tlv_Emv, FramingSchemaAndValueValidationAreIndependent) {
    const uint8_t wire[] = {0x9F, 0x02, 6, 0, 0, 0, 0, 0, 0xFA, 0x9F, 0x02, 0, 0xDF, 0x01, 0};
    tlv_reader_t  reader;
    ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, wire, sizeof(wire), &tlv_format_emv));
    tlv_element_t element;
    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &element));
    ASSERT_EQ(TLV_OK, tlv_schema_validate_length(tlv_schema_find(&tlv_emv_schema, &element.tag),
                                                 element.value.size));
    uint64_t amount;
    EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE,
              tlv_codec_decode(&tlv_emv_codec_amount, element.value.data, element.value.size,
                               &amount, sizeof(amount)));
    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &element));
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH,
              tlv_schema_validate_length(tlv_schema_find(&tlv_emv_schema, &element.tag),
                                         element.value.size));
    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &element));
    EXPECT_EQ(nullptr, tlv_schema_find(&tlv_emv_schema, &element.tag));
}

TEST(Integration_Tlv_Emv, SemanticTemplateDoesNotChangeWireConstructedBit) {
    // 9F31 is a semantic template despite its primitive wire bit.
    const uint8_t wire[] = {0x9f, 0x31, 3, 0x7f, 0x60, 0};
    tlv_decoded_t outer{};
    ASSERT_EQ(TLV_OK, tlv_format_decode(&tlv_format_emv, wire, sizeof(wire), &outer, nullptr));
    EXPECT_FALSE(tlv_format_emv.is_constructed(tlv_format_emv.context, &outer.element.tag));
    const auto* definition = tlv_emv_find(TLV_EMV_CONTEXT_BASE, &outer.element.tag);
    ASSERT_NE(nullptr, definition);
    EXPECT_EQ(TLV_EMV_VALUE_TEMPLATE, tlv_emv_builtin_value_kind(definition));
    EXPECT_EQ(TLV_EMV_CONTEXT_BASE,
              tlv_emv_child_context(TLV_EMV_CONTEXT_BASE, &outer.element.tag));
    size_t visits = 0;
    auto   visitor = [](const tlv_element_t*, size_t, size_t, void* context) {
        ++*static_cast<size_t*>(context);
        return TLV_VISIT_CONTINUE;
    };
    ASSERT_EQ(TLV_OK,
              tlv_walk_tree(wire, sizeof(wire), &tlv_format_emv, 8, 8, visitor, &visits, nullptr));
    EXPECT_EQ(1u, visits);
    // The application explicitly opens the value using its semantic context.
    tlv_decoded_t child{};
    ASSERT_EQ(TLV_OK, tlv_format_decode(&tlv_format_emv, outer.element.value.data, sizeof(wire) - 3,
                                        &child, nullptr));
    EXPECT_EQ(TLV_EMV_CONTEXT_BIT, tlv_emv_child_context(TLV_EMV_CONTEXT_BASE, &child.element.tag));
}

TEST(Integration_Tlv_Emv, GenericQueryAndDocumentUseEmvFraming) {
    const uint8_t wire[] = {0x70, 4, 0x9f, 2, 1, 0x42};
    tlv_query_t   query{};
    ASSERT_EQ(TLV_OK, tlv_query_parse("70/9F02", &query, nullptr));
    size_t visits = 0;
    auto   visitor = [](const tlv_element_t* element, size_t depth, size_t offset, void* context) {
        EXPECT_EQ(1u, depth);
        EXPECT_EQ(2u, offset);
        EXPECT_EQ(1u, element->value.size);
        EXPECT_EQ(0x42, element->value.data[0]);
        ++*static_cast<size_t*>(context);
        return TLV_VISIT_CONTINUE;
    };
    ASSERT_EQ(TLV_OK, tlv_query_walk(wire, sizeof(wire), &tlv_format_emv, &query, 8, 8, visitor,
                                     &visits, nullptr));
    EXPECT_EQ(1u, visits);
#if OPENTLV_DOCUMENT
    tlv_document_options_t options{};
    ASSERT_EQ(TLV_OK, tlv_document_options_init(&options, &tlv_format_emv));
    tlv_document_t* raw = nullptr;
    ASSERT_EQ(TLV_OK, tlv_document_parse(wire, sizeof(wire), &options, &raw, nullptr));
    std::unique_ptr<tlv_document_t, decltype(&tlv_document_free)> doc(raw, tlv_document_free);
    ASSERT_NE(nullptr, tlv_document_find_path(doc.get(), &query));
    uint8_t output[sizeof(wire)] = {};
    size_t  written = 0;
    ASSERT_EQ(TLV_OK, tlv_document_encode(doc.get(), output, sizeof(output), &written));
    EXPECT_EQ(sizeof(wire), written);
    EXPECT_EQ(0, std::memcmp(wire, output, written));
#endif
}

TEST(Integration_Tlv_Emv, AmountCodecKnownVectorsAndLimits) {
    const uint64_t amounts[] = {0, 123456789012ULL, 999999999999ULL};
    const uint8_t  vectors[][6] = {
        {0}, {0x12, 0x34, 0x56, 0x78, 0x90, 0x12}, {0x99, 0x99, 0x99, 0x99, 0x99, 0x99}};
    for (size_t i = 0; i < 3; ++i) {
        uint8_t wire[6];
        size_t  written = 99;
        ASSERT_EQ(TLV_CODEC_OK, tlv_codec_encode(&tlv_emv_codec_amount, &amounts[i],
                                                 sizeof(uint64_t), nullptr, 0, &written));
        EXPECT_EQ(6u, written);
        ASSERT_EQ(TLV_CODEC_OK, tlv_codec_encode(&tlv_emv_codec_amount, &amounts[i],
                                                 sizeof(uint64_t), wire, sizeof(wire), &written));
        EXPECT_EQ(0, std::memcmp(vectors[i], wire, 6));
        uint64_t decoded = 1;
        ASSERT_EQ(TLV_CODEC_OK,
                  tlv_codec_decode(&tlv_emv_codec_amount, wire, 6, &decoded, sizeof(decoded)));
        EXPECT_EQ(amounts[i], decoded);
    }
}
