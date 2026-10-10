// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "visitor_input.h"
// Conformance tests for the Bluetooth LTV (Length | Type | Value) format. Every case goes through
// the generic reader, writer and Tree Reader; there is no Bluetooth-specific parsing path here.
#include "tlv/builtins/bluetooth/bluetooth_ltv.h"
#include "tlv/reader/reader.h"
#include "tlv/reader/visitor.h"
#include "tlv/writer/writer.h"
#include <gtest/gtest.h>
#include <cstdint>
#include <cstring>
#include <vector>

namespace {
const auto& reader_format = tlv_format_bluetooth_ltv;
const auto& writer_format = tlv_format_bluetooth_ltv;

using Bytes = std::vector<uint8_t>;

struct Element {
    uint8_t type;
    Bytes   value;
};

// Advertising data: Flags, Complete 16-bit Service UUIDs (Battery, Device Information), TX Power
// Level and Complete Local Name "Sensor".
const Bytes advertising_data = {0x02, 0x01, 0x06, 0x05, 0x03, 0x0F, 0x18, 0x0A, 0x18, 0x02,
                                0x0A, 0x04, 0x07, 0x09, 'S',  'e',  'n',  's',  'o',  'r'};

// An iBeacon frame: Flags followed by Manufacturer Specific Data (Apple, 0x004C).
const Bytes ibeacon = {0x02, 0x01, 0x06, 0x1A, 0xFF, 0x4C, 0x00, 0x02, 0x15, 0xE2,
                       0xC5, 0x6D, 0xB5, 0xDF, 0xFB, 0x48, 0xD2, 0xB0, 0x60, 0xD0,
                       0xF5, 0xA7, 0x10, 0x96, 0xE0, 0x00, 0x01, 0x00, 0x02, 0xC5};

// Scan response: Shortened Local Name, Complete 128-bit Service UUIDs, an unassigned type (0xFE)
// and Service Data (16-bit UUID).
const Bytes scan_response = {0x05, 0x08, 'T',  'e',  's',  't',  0x11, 0x07, 0x00, 0x11, 0x22,
                             0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
                             0xEE, 0xFF, 0x02, 0xFE, 0x7F, 0x05, 0x16, 0x0F, 0x18, 0x64, 0x01};

std::vector<Element> read_all(const Bytes& data, tlv_result_t* final_result = nullptr) {
    // Exact-size storage lets a sanitizer catch any read past the declared boundary.
    std::vector<uint8_t> exact(data);
    tlv_reader_t         reader;
    std::vector<Element> elements;
    EXPECT_EQ(TLV_OK, tlv_reader_init(&reader, exact.data(), exact.size(), &reader_format));
    tlv_result_t rc = TLV_OK;
    while (!tlv_reader_at_end(&reader)) {
        tlv_element_t element;
        rc = tlv_reader_next(&reader, &element);
        if (rc != TLV_OK) break;
        EXPECT_EQ(1, element.tag.size);
        EXPECT_GE(element.value.data, exact.data() + 2);
        EXPECT_LE(element.value.data + element.value.size, exact.data() + exact.size());
        elements.push_back({element.tag.data[0],
                            Bytes(element.value.data, element.value.data + element.value.size)});
    }
    if (final_result) *final_result = rc;
    return elements;
}

Bytes encode_all(const std::vector<Element>& elements) {
    size_t total = 0;
    for (const Element& e : elements) {
        size_t size = 0;
        EXPECT_EQ(TLV_OK,
                  tlv_encoded_size(tlv_tag(&e.type, 1), e.value.size(), &writer_format, &size));
        total += size;
    }
    Bytes        out(total);
    tlv_writer_t writer;
    EXPECT_EQ(TLV_OK, tlv_writer_init(&writer, out.data(), out.size(), &writer_format));
    for (const Element& e : elements)
        EXPECT_EQ(TLV_OK,
                  tlv_writer_write(&writer, tlv_tag(&e.type, 1), e.value.data(), e.value.size()));
    EXPECT_EQ(total, tlv_writer_size(&writer));
    return out;
}

struct VisitLog {
    size_t              count = 0;
    size_t              stop_after = 0;
    std::vector<size_t> offsets;
};

tlv_visit_result_t log_visit(const tlv_element_t*, size_t depth, size_t offset, void* context) {
    auto* log = static_cast<VisitLog*>(context);
    EXPECT_EQ(0u, depth);
    log->offsets.push_back(offset);
    ++log->count;
    return log->stop_after && log->count == log->stop_after ? TLV_VISIT_STOP : TLV_VISIT_CONTINUE;
}
} // namespace

TEST(Unit_Tlv_BluetoothLtvConformance, DecodesAdvertisingVector) {
    tlv_result_t rc = TLV_ERR_INVALID_ARG;
    const auto   elements = read_all(advertising_data, &rc);
    EXPECT_EQ(TLV_OK, rc);
    ASSERT_EQ(4u, elements.size());
    EXPECT_EQ(0x01, elements[0].type);
    EXPECT_EQ(Bytes({0x06}), elements[0].value);
    EXPECT_EQ(0x03, elements[1].type);
    EXPECT_EQ(Bytes({0x0F, 0x18, 0x0A, 0x18}), elements[1].value);
    EXPECT_EQ(0x0A, elements[2].type);
    EXPECT_EQ(Bytes({0x04}), elements[2].value);
    EXPECT_EQ(0x09, elements[3].type);
    EXPECT_EQ(Bytes({'S', 'e', 'n', 's', 'o', 'r'}), elements[3].value);
}

TEST(Unit_Tlv_BluetoothLtvConformance, DecodesIBeaconVector) {
    const auto elements = read_all(ibeacon);
    ASSERT_EQ(2u, elements.size());
    EXPECT_EQ(0xFF, elements[1].type);
    // Company identifier, iBeacon type and length, 16-byte UUID, major, minor, measured power.
    ASSERT_EQ(25u, elements[1].value.size());
    EXPECT_EQ(Bytes({0x4C, 0x00, 0x02, 0x15}),
              Bytes(elements[1].value.begin(), elements[1].value.begin() + 4));
    EXPECT_EQ(0xC5, elements[1].value.back());
}

TEST(Unit_Tlv_BluetoothLtvConformance, DecodesScanResponseWithUnassignedType) {
    const auto elements = read_all(scan_response);
    ASSERT_EQ(4u, elements.size());
    EXPECT_EQ(0x08, elements[0].type);
    EXPECT_EQ(16u, elements[1].value.size());
    // Types the library has no knowledge of are still structurally valid entries.
    EXPECT_EQ(0xFE, elements[2].type);
    EXPECT_EQ(Bytes({0x7F}), elements[2].value);
    EXPECT_EQ(0x16, elements[3].type);
}

TEST(Unit_Tlv_BluetoothLtvConformance, ReEncodingVectorsIsByteIdentical) {
    for (const Bytes* vector : {&advertising_data, &ibeacon, &scan_response})
        EXPECT_EQ(*vector, encode_all(read_all(*vector)));
}

TEST(Unit_Tlv_BluetoothLtvConformance, CopyElementReproducesEachElement) {
    tlv_reader_t reader;
    ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, ibeacon.data(), ibeacon.size(), &reader_format));
    Bytes        out(ibeacon.size());
    tlv_writer_t writer;
    ASSERT_EQ(TLV_OK, tlv_writer_init(&writer, out.data(), out.size(), &writer_format));
    tlv_element_t element;
    while (tlv_reader_next(&reader, &element) == TLV_OK)
        ASSERT_EQ(TLV_OK, tlv_writer_copy_element(&writer, &element));
    EXPECT_EQ(ibeacon.size(), tlv_writer_size(&writer));
    EXPECT_EQ(ibeacon, out);
}

TEST(Unit_Tlv_BluetoothLtvConformance, EveryTypeByteIsStructurallyValid) {
    for (unsigned type = 0; type < 256; ++type) {
        const Bytes   data = {0x03, static_cast<uint8_t>(type), 0xAA, 0xBB};
        tlv_element_t element;
        size_t        consumed = 0;
        ASSERT_EQ(TLV_OK, tlv_read(data.data(), data.size(), &reader_format, &element, &consumed))
            << type;
        EXPECT_EQ(4u, consumed);
        EXPECT_EQ(type, element.tag.data[0]);
        EXPECT_EQ(2u, element.value.size);
    }
}

TEST(Unit_Tlv_BluetoothLtvConformance, LengthByteAgainstEveryBufferSize) {
    // Exhaustive over the length byte and the number of bytes actually available.
    for (unsigned length = 0; length < 256; ++length) {
        for (size_t size = 0; size <= 258; ++size) {
            Bytes data(size, 0xA5);
            if (size) data[0] = static_cast<uint8_t>(length);
            tlv_element_t element;
            size_t        consumed = 7;
            const auto rc = tlv_read(data.data(), data.size(), &reader_format, &element, &consumed);
            if (!size) {
                EXPECT_EQ(TLV_END, rc);
            } else if (!length) {
                EXPECT_EQ(TLV_ERR_INVALID_LENGTH, rc);
            } else if (length > size - 1) {
                EXPECT_EQ(TLV_ERR_TRUNCATED, rc) << length << "/" << size;
            } else {
                ASSERT_EQ(TLV_OK, rc) << length << "/" << size;
                EXPECT_EQ(length + 1u, consumed);
                EXPECT_EQ(length - 1u, element.value.size);
                EXPECT_LE(element.value.data + element.value.size, data.data() + size);
                continue;
            }
            EXPECT_EQ(7u, consumed);
        }
    }
}

TEST(Unit_Tlv_BluetoothLtvConformance, BoundaryValueLengthsRoundTrip) {
    for (size_t length : {0u, 1u, 2u, 127u, 128u, 253u, 254u}) {
        Bytes value(length);
        for (size_t i = 0; i < length; ++i) value[i] = static_cast<uint8_t>(i * 7 + 1);
        const Bytes encoded = encode_all({{0x2D, value}});
        ASSERT_EQ(length + 2, encoded.size());
        EXPECT_EQ(length + 1, encoded[0]);
        const auto decoded = read_all(encoded);
        ASSERT_EQ(1u, decoded.size());
        EXPECT_EQ(0x2D, decoded[0].type);
        EXPECT_EQ(value, decoded[0].value);
    }
}

TEST(Unit_Tlv_BluetoothLtvConformance, EncodingRejectsValuesAboveMaximum) {
    const Bytes     value(256, 0x11);
    Bytes           out(300, 0xEE);
    size_t          written = 0, size = 99;
    const tlv_tag_t tag = TLV_TAG(0x09);
    for (size_t length : {255u, 256u}) {
        EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_encoded_size(tag, length, &writer_format, &size));
        EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_write(out.data(), out.size(), &writer_format, tag,
                                                    value.data(), length, &written));
    }
    EXPECT_EQ(sizeof(size_t) == sizeof(tlv_size_t) ? TLV_ERR_OVERFLOW : TLV_ERR_INVALID_LENGTH,
              tlv_encoded_size(tag, SIZE_MAX, &writer_format, &size));
    for (uint8_t b : out) EXPECT_EQ(0xEE, b);
}

TEST(Unit_Tlv_BluetoothLtvConformance, StreamRoundTripAcrossManyElements) {
    // Deterministic pseudo-random stream covering every value length and type byte in turn.
    std::vector<Element> elements;
    uint32_t             state = 12345;
    for (unsigned i = 0; i < 300; ++i) {
        state = state * 1664525u + 1013904223u;
        Bytes value((i % 255));
        for (auto& b : value) {
            state = state * 1664525u + 1013904223u;
            b = static_cast<uint8_t>(state >> 24);
        }
        elements.push_back({static_cast<uint8_t>(i), value});
    }
    const Bytes  encoded = encode_all(elements);
    tlv_result_t rc = TLV_ERR_INVALID_ARG;
    const auto   decoded = read_all(encoded, &rc);
    EXPECT_EQ(TLV_OK, rc);
    ASSERT_EQ(elements.size(), decoded.size());
    for (size_t i = 0; i < elements.size(); ++i) {
        EXPECT_EQ(elements[i].type, decoded[i].type) << i;
        EXPECT_EQ(elements[i].value, decoded[i].value) << i;
    }
}

TEST(Unit_Tlv_BluetoothLtvConformance, EveryTruncationOfAStreamStopsAtElementBoundary) {
    for (const Bytes* vector : {&advertising_data, &ibeacon, &scan_response}) {
        // Offsets at which an element ends in the full stream.
        std::vector<size_t> ends;
        for (size_t pos = 0; pos < vector->size(); pos += (*vector)[pos] + 1u)
            ends.push_back(pos + (*vector)[pos] + 1u);
        for (size_t cut = 0; cut <= vector->size(); ++cut) {
            const Bytes  prefix(vector->begin(), vector->begin() + cut);
            tlv_result_t rc = TLV_ERR_INVALID_ARG;
            const auto   elements = read_all(prefix, &rc);
            size_t       complete = 0;
            bool         on_boundary = cut == 0;
            for (size_t end : ends) {
                if (end <= cut) ++complete;
                if (end == cut) on_boundary = true;
            }
            EXPECT_EQ(complete, elements.size()) << cut;
            // The reader is only exhausted on a boundary; an incomplete tail is never accepted.
            EXPECT_EQ(on_boundary ? TLV_OK : TLV_ERR_TRUNCATED, rc) << cut;
        }
    }
}

TEST(Unit_Tlv_BluetoothLtvConformance, LengthOverrunningTheBufferIsRejected) {
    // The second element declares more bytes than remain, although the first one is fine.
    const Bytes  data = {0x02, 0x01, 0x06, 0x0A, 0x09, 'H', 'i'};
    tlv_result_t rc = TLV_OK;
    const auto   elements = read_all(data, &rc);
    EXPECT_EQ(1u, elements.size());
    EXPECT_EQ(TLV_ERR_TRUNCATED, rc);
    const Bytes maximum_declared = {0xFF, 0x09, 0x01};
    read_all(maximum_declared, &rc);
    EXPECT_EQ(TLV_ERR_TRUNCATED, rc);
}

TEST(Unit_Tlv_BluetoothLtvConformance, ZeroLengthEndsParsingLikePadding) {
    // Bluetooth data is padded with zero bytes; the library reports that as an invalid length
    // at the padding offset instead of guessing, leaving the earlier elements readable.
    const Bytes  data = {0x02, 0x01, 0x06, 0x00, 0x00, 0x00};
    tlv_result_t rc = TLV_OK;
    const auto   elements = read_all(data, &rc);
    EXPECT_EQ(1u, elements.size());
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, rc);

    tlv_reader_t  reader;
    tlv_element_t element;
    ASSERT_EQ(TLV_OK, tlv_reader_init(&reader, data.data(), data.size(), &reader_format));
    ASSERT_EQ(TLV_OK, tlv_reader_next(&reader, &element));
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_reader_next(&reader, &element));
    // A failed read does not advance the reader, so the error is stable.
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_reader_next(&reader, &element));
    EXPECT_FALSE(tlv_reader_at_end(&reader));
}

TEST(Unit_Tlv_BluetoothLtvConformance, VisitorReportsElementOffsets) {
    VisitLog log;
    size_t   error_offset = 99;
    ASSERT_EQ(TLV_OK,
              visit_tree_input(advertising_data.data(), advertising_data.size(), &reader_format,
                               TLV_TREE_DEFAULT_DEPTH, 100, log_visit, &log, &error_offset));
    EXPECT_EQ(std::vector<size_t>({0, 3, 9, 12}), log.offsets);
    EXPECT_EQ(99u, error_offset);

    VisitLog stopped;
    stopped.stop_after = 2;
    EXPECT_EQ(TLV_OK,
              visit_tree_input(advertising_data.data(), advertising_data.size(), &reader_format,
                               TLV_TREE_DEFAULT_DEPTH, 100, log_visit, &stopped, nullptr));
    EXPECT_EQ(2u, stopped.count);
}

TEST(Unit_Tlv_BluetoothLtvConformance, VisitorReportsOffsetOfMalformedElement) {
    // Element offsets 0, 3, then an element at 6 that overruns the buffer.
    const Bytes data = {0x02, 0x01, 0x06, 0x02, 0x0A, 0x04, 0x09, 0x09, 'H'};
    VisitLog    log;
    size_t      error_offset = 0;
    EXPECT_EQ(TLV_ERR_TRUNCATED,
              visit_tree_input(data.data(), data.size(), &reader_format, TLV_TREE_DEFAULT_DEPTH,
                               100, log_visit, &log, &error_offset));
    EXPECT_EQ(6u, error_offset);
    EXPECT_EQ(2u, log.count);

    const Bytes zero = {0x02, 0x01, 0x06, 0x00};
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH,
              visit_tree_input(zero.data(), zero.size(), &reader_format, TLV_TREE_DEFAULT_DEPTH,
                               100, nullptr, nullptr, &error_offset));
    EXPECT_EQ(3u, error_offset);
}

TEST(Unit_Tlv_BluetoothLtvConformance, VisitorEnforcesElementLimit) {
    size_t error_offset = 0;
    EXPECT_EQ(TLV_ERR_LIMIT,
              visit_tree_input(advertising_data.data(), advertising_data.size(), &reader_format,
                               TLV_TREE_DEFAULT_DEPTH, 3, nullptr, nullptr, &error_offset));
    EXPECT_EQ(TLV_OK,
              visit_tree_input(advertising_data.data(), advertising_data.size(), &reader_format,
                               TLV_TREE_DEFAULT_DEPTH, 4, nullptr, nullptr, nullptr));
}
