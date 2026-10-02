// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/builtins/emv/format.h"
#include "tlv/builtins/asn1/ber.h"
#include "tlv/reader/reader.h"
#include "tlv/writer/writer.h"
#include <gtest/gtest.h>
#include <cstring>
#include <vector>

TEST(Unit_Tlv_EmvFormat, EverySupportedIdentifierRetainsByteIdentity) {
    for (unsigned first = 1; first <= 255; ++first) {
        const bool escaped = (first & 0x1f) == 0x1f;
        for (unsigned second = 1; second <= (escaped ? 127u : 1u); ++second) {
            std::vector<uint8_t> wire{static_cast<uint8_t>(first)};
            if (escaped) wire.push_back(static_cast<uint8_t>(second));
            const size_t width = wire.size();
            wire.push_back(0);
            tlv_decoded_t decoded{};
            ASSERT_EQ(TLV_OK, tlv_format_decode(&tlv_format_emv, wire.data(), wire.size(), &decoded,
                                                nullptr));
            EXPECT_EQ(width, decoded.element.tag.size);
            EXPECT_EQ(wire.data(), decoded.element.tag.data);
            EXPECT_EQ(wire.data() + wire.size(), decoded.element.value.data);
            EXPECT_EQ((first & 0x20) != 0, tlv_format_emv.is_constructed(
                                               tlv_format_emv.context, &decoded.element.tag) != 0);
            uint8_t out[3] = {};
            size_t  written = 0;
            ASSERT_EQ(TLV_OK, tlv_format_encode(&tlv_format_emv, &decoded.element, out, sizeof(out),
                                                &written, nullptr));
            EXPECT_EQ(wire.size(), written);
            EXPECT_EQ(0, std::memcmp(wire.data(), out, written));
        }
    }
}

TEST(Unit_Tlv_EmvFormat, RejectsInvalidIdentifiersOnReadAndWrite) {
    const std::vector<std::vector<uint8_t>> tags = {
        {0}, {0x9f, 0}, {0x9f, 0x80}, {0x9f, 0x81, 1}, {0x5a, 1}};
    for (const auto& tag : tags) {
        tlv_element_t  element{tlv_tag(tag.data(), tag.size()), {nullptr, 0}};
        tlv_encoding_t encoding{};
        EXPECT_NE(TLV_OK, tlv_format_measure(&tlv_format_emv, &element, &encoding, nullptr));
        // An extra byte after a complete one-byte tag is a length, not a bad tag.
        if (tag == std::vector<uint8_t>({0x5a, 1})) continue;
        auto wire = tag;
        wire.push_back(0);
        tlv_decoded_t decoded{};
        EXPECT_NE(TLV_OK,
                  tlv_format_decode(&tlv_format_emv, wire.data(), wire.size(), &decoded, nullptr));
    }
    const uint8_t incomplete[] = {0x9f};
    tlv_decoded_t decoded{};
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_format_decode(&tlv_format_emv, incomplete,
                                                          sizeof(incomplete), &decoded, nullptr));
}

TEST(Unit_Tlv_EmvFormat, LengthBoundariesLayoutAndEveryTruncation) {
    for (size_t length : {0u, 1u, 127u, 128u, 255u, 256u, 65535u}) {
        const uint8_t        tag[] = {0x86};
        std::vector<uint8_t> value(length, 0xa5), wire(length + 4);
        tlv_element_t        element{tlv_tag(tag, 1), {value.data(), length}};
        size_t               written = 0;
        ASSERT_EQ(TLV_OK, tlv_format_encode(&tlv_format_emv, &element, wire.data(), wire.size(),
                                            &written, nullptr));
        wire.resize(written);
        const size_t count_size = length < 128 ? 1 : length < 256 ? 2 : 3;
        EXPECT_EQ(1 + count_size + length, written);
        EXPECT_EQ(length < 128 ? length : length < 256 ? 0x81u : 0x82u, wire[1]);
        tlv_decoded_t decoded{};
        ASSERT_EQ(TLV_OK,
                  tlv_format_decode(&tlv_format_emv, wire.data(), wire.size(), &decoded, nullptr));
        EXPECT_EQ(1u, decoded.source.tag.size);
        EXPECT_EQ(count_size, decoded.source.length.size);
        EXPECT_EQ(1 + count_size, decoded.source.value.offset);
        EXPECT_EQ(length, decoded.element.value.size);
        EXPECT_EQ(0u, decoded.source.trailer.size);
        for (size_t size = 1; size < wire.size(); ++size) {
            EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
                      tlv_format_decode(&tlv_format_emv, wire.data(), size, &decoded, nullptr));
        }
    }
}

TEST(Unit_Tlv_EmvFormat, RejectsIndefiniteAndOversizedLengthsWithoutAdvancingReader) {
    for (uint8_t tag : {0x5a, 0x70}) {
        for (unsigned prefix = 0x80; prefix <= 255; ++prefix) {
            if (prefix == 0x81 || prefix == 0x82) continue;
            const uint8_t wire[] = {tag, static_cast<uint8_t>(prefix), 0, 0, 0};
            tlv_reader_t  reader{};
            ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, wire, sizeof(wire), &tlv_format_emv));
            tlv_element_t element{};
            EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_reader_next(&reader, &element));
            EXPECT_EQ(0u, reader.pos);
        }
    }
    const uint8_t  tag[] = {0x86};
    tlv_element_t  element{tlv_tag(tag, 1), {nullptr, 65536}};
    tlv_encoding_t encoding{};
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH,
              tlv_format_measure(&tlv_format_emv, &element, &encoding, nullptr));
}

TEST(Unit_Tlv_EmvFormat, PreservationKeepsNonminimalLengthWhileWriterRegenerates) {
    const uint8_t wire[] = {0x9f, 0x02, 0x82, 0, 1, 0x42};
    tlv_decoded_t decoded{};
    ASSERT_EQ(TLV_OK, tlv_format_decode(&tlv_format_emv, wire, sizeof(wire), &decoded, nullptr));
    uint8_t out[sizeof(wire)] = {};
    size_t  written = 0;
    ASSERT_EQ(TLV_OK,
              tlv_source_preserve(&decoded.source, &decoded.element, out, sizeof(out), &written));
    EXPECT_EQ(sizeof(wire), written);
    EXPECT_EQ(0, std::memcmp(wire, out, written));
    ASSERT_EQ(TLV_OK, tlv_format_encode(&tlv_format_emv, &decoded.element, out, sizeof(out),
                                        &written, nullptr));
    const uint8_t canonical[] = {0x9f, 2, 1, 0x42};
    EXPECT_EQ(sizeof(canonical), written);
    EXPECT_EQ(0, std::memcmp(canonical, out, written));
    const uint8_t changed = 0x43;
    decoded.element.value.data = &changed;
    EXPECT_NE(TLV_OK,
              tlv_source_preserve(&decoded.source, &decoded.element, out, sizeof(out), &written));
}

TEST(Unit_Tlv_EmvFormat, WriterFailuresLeaveCursorAndDestinationUnchanged) {
    const uint8_t invalid[] = {0x9f, 0x81, 1};
    const uint8_t valid[] = {0x5a};
    uint8_t       out[] = {0xaa, 0xaa, 0xaa};
    tlv_writer_t  writer{};
    ASSERT_EQ(TLV_OK, tlv_writer_init(&writer, out, sizeof(out), &tlv_format_emv));
    EXPECT_NE(TLV_OK, tlv_writer_write(&writer, tlv_tag(invalid, sizeof(invalid)), nullptr, 0));
    const uint8_t value[] = {1, 2};
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
              tlv_writer_write(&writer, tlv_tag(valid, 1), value, sizeof(value)));
    EXPECT_EQ(0u, writer.pos);
    EXPECT_EQ((std::vector<uint8_t>{0xaa, 0xaa, 0xaa}),
              std::vector<uint8_t>(out, out + sizeof(out)));
}

TEST(Unit_Tlv_EmvFormat, BerAndEmvHaveIndependentValidityPolicies) {
    tlv_decoded_t decoded{};
    const uint8_t indefinite[] = {0x70, 0x80, 0, 0};
    EXPECT_EQ(TLV_OK, tlv_format_decode(&tlv_format_ber, indefinite, sizeof(indefinite), &decoded,
                                        nullptr));
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_format_decode(&tlv_format_emv, indefinite,
                                                        sizeof(indefinite), &decoded, nullptr));
    const uint8_t universal_zero_constructed[] = {0x20, 0};
    EXPECT_EQ(TLV_ERR_INVALID_TAG,
              tlv_format_decode(&tlv_format_ber, universal_zero_constructed, 2, &decoded, nullptr));
    EXPECT_EQ(TLV_OK,
              tlv_format_decode(&tlv_format_emv, universal_zero_constructed, 2, &decoded, nullptr));
    const uint8_t eoc[] = {0, 0};
    EXPECT_EQ(TLV_ERR_INVALID_TAG, tlv_format_decode(&tlv_format_emv, eoc, 2, &decoded, nullptr));
    // Opaque values may contain zero bytes or malformed nested framing.
    const uint8_t opaque[] = {0x70, 2, 0, 0};
    EXPECT_EQ(TLV_OK,
              tlv_format_decode(&tlv_format_emv, opaque, sizeof(opaque), &decoded, nullptr));
}
