// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "../../diagnostic_assertions.h"
#include "tlv/config.h"
#include "tlv/reader/reader.h"
#include "tlv/writer/tree.h"
#include "tlv/formats/compose.h"
#include "tlv/formats/escaped.h"
#include "tlv/formats/fixed.h"
#include "tlv/formats/packed.h"
#include "tlv/formats/variable.h"
#if OPENTLV_FORMAT_BER
#include "tlv/builtins/asn1/ber.h"
#endif
#if OPENTLV_FORMAT_CER
#include "tlv/builtins/asn1/cer.h"
#include "tlv/builtins/asn1/cer_validation.h"
#endif
#if OPENTLV_FORMAT_DER
#include "tlv/builtins/asn1/der.h"
#include "tlv/builtins/asn1/der_validation.h"
#endif
#if OPENTLV_FORMAT_BER && OPENTLV_EMV
#include "tlv/builtins/emv/format.h"
#endif
#if OPENTLV_BLUETOOTH
#include "tlv/builtins/bluetooth/bluetooth_ltv.h"
#endif
#if OPENTLV_DHCP
#include "tlv/builtins/dhcp/dhcpv4.h"
#endif
#if OPENTLV_LLDP
#include "tlv/builtins/lldp/lldp.h"
#endif
#if OPENTLV_NFC
#include "tlv/builtins/nfc/type2.h"
#endif
#include <gtest/gtest.h>
#include <string>
#include <utility>
#include <vector>

// End, truncation, resumable shortage and output capacity are distinct results
// for every Format that the incremental Reader can drive.
namespace {
struct Case {
    std::string          name;
    const tlv_format_t*  format;
    tlv_tag_t            tag;
    std::vector<uint8_t> value;
};

const std::vector<uint8_t> octets = {0xA1, 0xA2, 0xA3};

void check_reader(const Case& c, const std::vector<uint8_t>& wire, size_t cut, int final_input) {
    tlv_reader_t reader;
    ASSERT_EQ(TLV_OK,
              tlv_reader_init_incremental(&reader, cut ? wire.data() : nullptr, cut, c.format));
    ASSERT_EQ(TLV_OK,
              tlv_reader_set_input(&reader, cut ? wire.data() : nullptr, cut, 0, final_input));
    tlv_element_t           element = {TLV_TAG(0xEE), {nullptr, 42}};
    tlv_reader_diagnostic_t diagnostic{};
    const tlv_result_t      expected = !final_input ? TLV_NEED_MORE_DATA
                                       : cut        ? TLV_ERR_TRUNCATED
                                                    : TLV_END;
    EXPECT_EQ(expected, TLV_DIAGNOSTIC_RESULT(
                            diagnostic, tlv_reader_next_diag(&reader, &element, &diagnostic)));
    EXPECT_EQ(expected, diagnostic.diagnostic.code);
    EXPECT_EQ(expected == TLV_ERR_TRUNCATED ? TLV_DIAGNOSTIC_SEVERITY_ERROR
                                            : TLV_DIAGNOSTIC_SEVERITY_INFO,
              diagnostic.diagnostic.severity);
    EXPECT_EQ(42u, element.value.size);
    EXPECT_EQ(0u, tlv_reader_consumed(&reader));
    if (expected == TLV_ERR_TRUNCATED) {
        EXPECT_EQ(TLV_LOCATION_INPUT, diagnostic.diagnostic.location.domain);
        EXPECT_NE(TLV_LOCATION_UNKNOWN, diagnostic.diagnostic.location.kind);
        EXPECT_LE(diagnostic.diagnostic.location.end, cut);
    }
}

/* A non-final cut pauses without consuming; extending the same window to the
 * complete element and declaring EOF publishes it, after which iteration ends. */
void check_resume(const Case& c, const std::vector<uint8_t>& wire, const tlv_decoded_t& expected,
                  size_t cut) {
    tlv_reader_t reader;
    ASSERT_EQ(TLV_OK,
              tlv_reader_init_incremental(&reader, cut ? wire.data() : nullptr, cut, c.format));
    tlv_element_t element{};
    ASSERT_EQ(TLV_NEED_MORE_DATA, tlv_reader_next(&reader, &element));
    ASSERT_EQ(TLV_OK, tlv_reader_set_input(&reader, wire.data(), wire.size(), 0, 1));
    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &element));
    EXPECT_EQ(wire.size(), tlv_reader_consumed(&reader));
    EXPECT_EQ(expected.element.tag.size, element.tag.size);
    EXPECT_EQ(expected.element.value.size, element.value.size);
    EXPECT_EQ(wire.data() + expected.source.value.offset, element.value.data);
    EXPECT_EQ(TLV_END, tlv_reader_next(&reader, &element));
}

void check_format(const Case& c) {
    SCOPED_TRACE(c.name);
    const tlv_element_t element = {c.tag, {c.value.data(), c.value.size()}};
    size_t              total = 0;
    ASSERT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
              tlv_format_encode(c.format, &element, nullptr, 0, &total, nullptr));
    std::vector<uint8_t> wire(total);
    size_t               written = 0;
    ASSERT_EQ(TLV_OK,
              tlv_format_encode(c.format, &element, wire.data(), wire.size(), &written, nullptr));
    ASSERT_EQ(total, written);

    /* Output capacity is never reported as truncation. */
    std::vector<uint8_t> small(total - 1, 0xCC);
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
              tlv_format_encode(c.format, &element, small.data(), small.size(), &written, nullptr));

    tlv_element_t read{};
    size_t        consumed = 7;
    EXPECT_EQ(TLV_END, tlv_read(nullptr, 0, c.format, &read, &consumed));
    EXPECT_EQ(7u, consumed);
    tlv_decoded_t decoded{};
    ASSERT_EQ(TLV_OK, tlv_format_decode(c.format, wire.data(), wire.size(), &decoded, nullptr));
    const size_t value_begin = decoded.source.value.offset;

    for (size_t cut = 0; cut < total; ++cut) {
        SCOPED_TRACE(cut);
        check_reader(c, wire, cut, 1);
        check_reader(c, wire, cut, 0);
        check_resume(c, wire, decoded, cut);
        if (!cut) continue;
        EXPECT_EQ(TLV_ERR_TRUNCATED, tlv_read(wire.data(), cut, c.format, &read, &consumed));
        tlv_reader_diagnostic_t diagnostic{};
        EXPECT_EQ(TLV_ERR_TRUNCATED,
                  TLV_DIAGNOSTIC_RESULT(diagnostic, tlv_read_diag(wire.data(), cut, c.format, &read,
                                                                  &consumed, &diagnostic)));
        /* A header cut is located in the header; a later cut in the Value or trailer,
         * possibly inside a nested child that the Format scans. */
        const auto operation = diagnostic.detail.operation;
        if (cut < value_begin) {
            EXPECT_NE(TLV_READER_OP_VALUE, operation);
            EXPECT_NE(TLV_READER_OP_TRAILER, operation);
            EXPECT_LT(diagnostic.diagnostic.location.begin, value_begin);
        } else {
            EXPECT_GE(diagnostic.diagnostic.location.begin, value_begin);
        }
    }
}

const uint8_t two_byte_tag[] = {0x9F, 0x21};
const uint8_t short_tag[] = {0x0C};
} // namespace

TEST(Unit_Tlv_ResultTaxonomy, ConfigurableFormatsSeparateEndTruncationAndCapacity) {
    const tlv_fixed_format_t fixed_config = {
        {2}, {2, TLV_BYTE_ORDER_BIG_ENDIAN}, TLV_ELEMENT_ORDER_TLV, TLV_LENGTH_SCOPE_VALUE};
    tlv_format_t fixed{};
    ASSERT_EQ(TLV_OK, tlv_fixed_format_init(&fixed, &fixed_config));
    const uint8_t fixed_tag[] = {0x12, 0x34};
    check_format({"fixed", &fixed, tlv_tag(fixed_tag, sizeof fixed_tag), octets});

    const tlv_variable_format_t variable_config = {{0x1F, 0x1F, 0x80, 0x7F, 16, nullptr},
                                                   {0x80, 0x7F, TLV_BYTE_ORDER_BIG_ENDIAN, nullptr},
                                                   TLV_ELEMENT_ORDER_TLV,
                                                   TLV_LENGTH_SCOPE_VALUE,
                                                   nullptr};
    tlv_format_t                variable{};
    ASSERT_EQ(TLV_OK, tlv_variable_format_init(&variable, &variable_config));
    check_format({"variable", &variable, tlv_tag(two_byte_tag, sizeof two_byte_tag), octets});

    const tlv_escaped_format_t escaped_config{{2},
                                              {0x80, 2, TLV_BYTE_ORDER_LITTLE_ENDIAN, 0, 65535},
                                              TLV_ELEMENT_ORDER_LTV,
                                              TLV_LENGTH_SCOPE_TAG_AND_VALUE,
                                              nullptr,
                                              0};
    tlv_format_t               escaped{};
    ASSERT_EQ(TLV_OK, tlv_escaped_format_init(&escaped, &escaped_config));
    const uint8_t escaped_tag[] = {0xAB, 0xCD};
    check_format({"escaped", &escaped, tlv_tag(escaped_tag, sizeof escaped_tag), octets});

    static const uint8_t      tags[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    const tlv_packed_layout_t packed_config = {2,
                                               {2, 12, 4, TLV_BYTE_ORDER_BIG_ENDIAN},
                                               {2, 0, 12, TLV_BYTE_ORDER_BIG_ENDIAN},
                                               TLV_LENGTH_SCOPE_VALUE,
                                               tags,
                                               1,
                                               sizeof(tags)};
    const tlv_format_t        packed = {&packed_config, tlv_packed_decode, tlv_packed_measure,
                                        tlv_packed_encode, nullptr};
    check_format({"packed", &packed, tlv_tag(tags + 11, 1), octets});
}

TEST(Unit_Tlv_ResultTaxonomy, BuiltinFormatsSeparateEndTruncationAndCapacity) {
    std::vector<Case> cases;
#if OPENTLV_FORMAT_BER
    cases.push_back({"ber", &tlv_format_ber, tlv_tag(two_byte_tag, sizeof two_byte_tag), octets});
    // Indefinite length frames encoded children and ends with an EOC trailer.
    static const uint8_t constructed_tag[] = {0xBF, 0x21};
    cases.push_back({"ber_indefinite",
                     &tlv_format_ber_indefinite,
                     tlv_tag(constructed_tag, sizeof constructed_tag),
                     {0x04, 0x01, 0xAA}});
#endif
#if OPENTLV_FORMAT_CER
    cases.push_back({"cer", &tlv_format_cer, tlv_tag(two_byte_tag, sizeof two_byte_tag), octets});
#endif
#if OPENTLV_FORMAT_DER
    cases.push_back({"der", &tlv_format_der, tlv_tag(two_byte_tag, sizeof two_byte_tag), octets});
#endif
#if OPENTLV_FORMAT_BER && OPENTLV_EMV
    cases.push_back({"emv", &tlv_format_emv, tlv_tag(two_byte_tag, sizeof two_byte_tag), octets});
#endif
#if OPENTLV_BLUETOOTH
    cases.push_back({"bluetooth_ltv", &tlv_format_bluetooth_ltv, tlv_tag(short_tag, 1), octets});
#endif
#if OPENTLV_DHCP
    cases.push_back({"dhcpv4", &tlv_format_dhcpv4, tlv_tag(short_tag, 1), octets});
#endif
#if OPENTLV_LLDP
    cases.push_back({"lldp", &tlv_format_lldp, tlv_tag(short_tag, 1), octets});
#endif
#if OPENTLV_NFC
    static const uint8_t ndef[] = {0x03};
    cases.push_back({"nfc_type2", &tlv_format_nfc_type2, tlv_tag(ndef, 1), octets});
#endif
    for (const auto& c : cases) check_format(c);
}

#if OPENTLV_FORMAT_DER || OPENTLV_FORMAT_CER
TEST(Unit_Tlv_ResultTaxonomy, ValidatingReadersReportEndWithoutFailureSeverity) {
    const uint8_t truncated[] = {0x04, 2, 0};
    using read_fn =
        tlv_result_t (*)(const uint8_t*, size_t, tlv_element_t*, size_t*, tlv_diagnostic_t*);
    std::vector<std::pair<std::string, read_fn>> readers;
#if OPENTLV_FORMAT_DER
    readers.push_back({"der", [](const uint8_t* data, size_t size, tlv_element_t* element,
                                 size_t* consumed, tlv_diagnostic_t* diagnostic) {
                           return tlv_der_read(data, size, nullptr, element, consumed, diagnostic);
                       }});
#endif
#if OPENTLV_FORMAT_CER
    readers.push_back({"cer", [](const uint8_t* data, size_t size, tlv_element_t* element,
                                 size_t* consumed, tlv_diagnostic_t* diagnostic) {
                           return tlv_cer_read(data, size, nullptr, element, consumed, diagnostic);
                       }});
#endif
    for (const auto& reader : readers) {
        SCOPED_TRACE(reader.first);
        tlv_element_t    element{};
        size_t           consumed = 7;
        tlv_diagnostic_t diagnostic{};
        EXPECT_EQ(TLV_END, reader.second(nullptr, 0, &element, &consumed, &diagnostic));
        EXPECT_EQ(TLV_END, diagnostic.code);
        EXPECT_EQ(TLV_DIAGNOSTIC_SEVERITY_INFO, diagnostic.severity);
        EXPECT_EQ(7u, consumed);
        EXPECT_EQ(TLV_ERR_TRUNCATED,
                  reader.second(truncated, sizeof truncated, &element, &consumed, &diagnostic));
        EXPECT_EQ(TLV_ERR_TRUNCATED, diagnostic.code);
        EXPECT_EQ(TLV_DIAGNOSTIC_SEVERITY_ERROR, diagnostic.severity);
        EXPECT_EQ(TLV_LOCATION_INPUT, diagnostic.location.domain);
        EXPECT_EQ(7u, consumed);
    }
}
#endif

TEST(Unit_Tlv_ResultTaxonomy, DecodersCannotReturnControlCapacityOrUnknownResults) {
    for (tlv_result_t reported :
         {TLV_END, TLV_NEED_MORE_DATA, TLV_ERR_BUFFER_TOO_SHORT, static_cast<tlv_result_t>(23)}) {
        SCOPED_TRACE(reported);
        tlv_format_t format{};
        format.context = &reported;
        format.decode = [](const void* context, const uint8_t*, size_t, tlv_decoded_t*,
                           tlv_format_error_t*) {
            return *static_cast<const tlv_result_t*>(context);
        };
        const uint8_t wire[] = {1};
        tlv_element_t element{};
        size_t        consumed = 0;
        EXPECT_EQ(TLV_ERR_CALLBACK, tlv_read(wire, sizeof wire, &format, &element, &consumed));
        /* Not even a non-final Reader reinterprets them as resumable or as end of input. */
        tlv_reader_t reader;
        ASSERT_EQ(TLV_OK, tlv_reader_init_incremental(&reader, wire, sizeof wire, &format));
        EXPECT_EQ(TLV_ERR_CALLBACK, tlv_reader_next(&reader, &element));
        EXPECT_EQ(0u, tlv_reader_consumed(&reader));
    }
}

TEST(Unit_Tlv_ResultTaxonomy, CompositionReadCallbacksCannotReportCapacity) {
    /* A Format written for the old contract signals incomplete input as capacity. */
    const tlv_field_composition_t layout = {
        nullptr,
        [](const void*, const uint8_t* data, size_t size, tlv_tag_t* tag, size_t* used) {
            if (!size) return TLV_ERR_TRUNCATED;
            *tag = tlv_tag(data, 1);
            *used = 1;
            return TLV_OK;
        },
        [](const void*, const uint8_t*, size_t, tlv_size_t*, size_t*) {
            return TLV_ERR_BUFFER_TOO_SHORT;
        },
        nullptr,
        nullptr,
        nullptr,
        TLV_ELEMENT_ORDER_TLV,
        TLV_LENGTH_SCOPE_VALUE};
    const uint8_t      wire[] = {1};
    tlv_decoded_t      decoded{};
    tlv_format_error_t error{};
    EXPECT_EQ(TLV_ERR_CALLBACK, tlv_fields_decode(&layout, wire, sizeof wire, &decoded, &error));
    const tlv_format_t format = {&layout, tlv_fields_decode, nullptr, nullptr, nullptr};
    tlv_reader_t       reader;
    ASSERT_EQ(TLV_OK, tlv_reader_init_incremental(&reader, wire, sizeof wire, &format));
    tlv_element_t element{};
    EXPECT_EQ(TLV_ERR_CALLBACK, tlv_reader_next(&reader, &element));
}

TEST(Unit_Tlv_ResultTaxonomy, IterationSourcesMayEndButNotPauseOrInventResults) {
    const tlv_fixed_format_t config = {
        {1}, {1, TLV_BYTE_ORDER_BIG_ENDIAN}, TLV_ELEMENT_ORDER_TLV, TLV_LENGTH_SCOPE_VALUE};
    tlv_format_t format{};
    ASSERT_EQ(TLV_OK, tlv_fixed_format_init(&format, &config));
    struct Source {
        tlv_result_t finish;
        int          calls;
    };
    for (tlv_result_t finish : {TLV_END, TLV_NEED_MORE_DATA, static_cast<tlv_result_t>(23)}) {
        SCOPED_TRACE(finish);
        Source source = {finish, 0};
        auto   next = [](void* context, tlv_tree_event_t* event) -> tlv_result_t {
            static const uint8_t value[] = {'A'};
            auto&                s = *static_cast<Source*>(context);
            if (s.calls++) return s.finish;
            *event = tlv_tree_event_t{};
            event->kind = TLV_TREE_ELEMENT;
            event->element = {TLV_TAG(0x01), {value, sizeof value}};
            return TLV_OK;
        };
        tlv_tree_writer_frame_t     frames[4];
        uint8_t                     data[16];
        uint8_t                     scratch[16];
        tlv_tree_writer_workspace_t workspace = {frames,         4, data, sizeof data, scratch,
                                                 sizeof scratch, 0, 0};
        size_t                      size = 99;
        const tlv_result_t rc = tlv_tree_writer_measure_events(&format, next, &source, &workspace,
                                                               4, 8, &size, nullptr);
        if (finish == TLV_END) {
            EXPECT_EQ(TLV_OK, rc);
            EXPECT_EQ(3u, size);
        } else {
            EXPECT_EQ(TLV_ERR_CALLBACK, rc);
            EXPECT_EQ(99u, size);
        }
    }
}

TEST(Unit_Tlv_ResultTaxonomy, NewResultsHaveDistinctDescriptions) {
    EXPECT_STREQ("end of iteration", tlv_strerror(TLV_END));
    EXPECT_STREQ("truncated input", tlv_strerror(TLV_ERR_TRUNCATED));
    EXPECT_STREQ("syntax error", tlv_strerror(TLV_ERR_SYNTAX));
    EXPECT_STRNE(tlv_strerror(TLV_ERR_TRUNCATED), tlv_strerror(TLV_ERR_BUFFER_TOO_SHORT));
}
