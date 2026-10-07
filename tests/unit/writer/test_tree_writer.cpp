// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv++/native.hpp"
#include "controlled_format.h"
#include "tlv++/writer/tree.hpp"
#include "tlv++/reader/tree.hpp"
#include "tlv++/writer/writer.hpp"
#include <gtest/gtest.h>
#include <vector>
#include <cstring>

namespace {
int constructed(const void*, const tlv_tag_t* tag) {
    return tag->size && tag->data[0] >= 0x80;
}
const tlv_format_t format = {&controlled::format_layout, tlv_fields_decode, tlv_fields_measure,
                             tlv_fields_encode, constructed};
} // namespace

TEST(Unit_Tlvpp_TreeWriterParity, MeasurementStagesCanonicalEncoding) {
    uint8_t                    data[32]{}, scratch[32]{};
    tlv::tree_writer_frame     frames[4]{};
    tlv::tree_writer_workspace workspace{frames, 4, data, 32, scratch, 32, 0, 0};
    const uint8_t              tags[] = {0xE1, 1, 0xE2};
    size_t                     index = 0;
    auto                       next = [&](tlv::element_view& element, size_t& depth,
                                          bool& parent) -> tlv::expected<bool, tlv::error> {
        if (index == 3) return false;
        element = {tlv::tag(tlv::bytes(reinterpret_cast<const tlv::byte*>(tags + index), 1)),
                   tlv::value_view{}};
        depth = index ? 1 : 0;
        parent = index != 1;
        ++index;
        return true;
    };
    auto result = tlv::measure_tree(tlv::native::borrow_format(format), next, workspace);
    ASSERT_TRUE(result);
    ASSERT_EQ(6u, *result);
    const uint8_t expected[] = {0xE1, 4, 1, 0, 0xE2, 0};
    EXPECT_EQ(std::vector<uint8_t>(expected, expected + 6), std::vector<uint8_t>(data, data + 6));
    index = 0;
    workspace.scratch_capacity = 0;
    auto failure = tlv::measure_tree(tlv::native::borrow_format(format), next, workspace);
    ASSERT_FALSE(failure);
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, failure.error().code);
    EXPECT_EQ(4u, workspace.required_scratch);
    EXPECT_EQ(0u, workspace.required_data);
}

TEST(Unit_Tlvpp_TreeWriterParity, MeasurementPropagatesSourceError) {
    tlv::tree_writer_workspace workspace{};
    auto next = [](tlv::element_view&, size_t&, bool&) -> tlv::expected<bool, tlv::error> {
        return tlv::unexpected<tlv::error>(tlv::error::from_c(TLV_ERR_INVALID_VALUE));
    };
    auto result = tlv::measure_tree(tlv::native::borrow_format(format), next, workspace);
    ASSERT_FALSE(result);
    EXPECT_EQ(TLV_ERR_INVALID_VALUE, result.error().code);
    EXPECT_EQ(0u, workspace.required_data);
    EXPECT_EQ(0u, workspace.required_scratch);
}

TEST(Unit_Tlvpp_WriterParity, SingleWriteAndMeasurementMatchC) {
    const uint8_t           tag_bytes[] = {1};
    const uint8_t           value_bytes[] = {0x42, 0x43};
    const tlv::element_view element{
        tlv::tag(tlv::bytes(reinterpret_cast<const tlv::byte*>(tag_bytes), 1)),
        tlv::value_view(tlv::bytes(reinterpret_cast<const tlv::byte*>(value_bytes), 2))};
    uint8_t    native_output[16]{};
    tlv::byte  output[16]{};
    size_t     native_size = 0;
    const auto raw = tlv::native::descriptor(element);
    ASSERT_EQ(TLV_OK,
              tlv_write_element(native_output, sizeof(native_output), &format, &raw, &native_size));
    auto measured = tlv::encoded_size(element.tag(), element.value().size(),
                                      tlv::native::borrow_format(format));
    ASSERT_TRUE(measured);
    EXPECT_EQ(native_size, *measured);
    auto result = tlv::write(output, sizeof(output), tlv::native::borrow_format(format), element);
    ASSERT_TRUE(result);
    EXPECT_EQ(native_size, *result);
    EXPECT_EQ(0, std::memcmp(output, native_output, native_size));
    tlv::writer_diagnostic diagnostic{};
    auto                   failure =
        tlv::write(output, 1, tlv::native::borrow_format(format), element.tag(),
                   tlv::bytes(reinterpret_cast<const tlv::byte*>(value_bytes), 2), &diagnostic);
    ASSERT_FALSE(failure);
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, failure.error().code);
    EXPECT_TRUE(diagnostic.has_required);
    EXPECT_EQ(native_size, diagnostic.required);
}

TEST(Unit_Tlvpp_TreeWriterParity, CanonicalEventPipelineAndMeasurement) {
    const uint8_t          input[] = {0xE1, 2, 1, 0};
    tlv::tree_frame        read_frames[1];
    tlv::tree_writer_frame write_frames[1];
    tlv::byte              output[16], scratch[16], tags[1];
    tlv::tree_reader reader(tlv::bytes(reinterpret_cast<const tlv::byte*>(input), sizeof(input)),
                            tlv::native::borrow_format(format),
                            tlv::span<tlv::tree_frame>(read_frames, 1), 1, 2);
    tlv::tree_writer writer(output, 16, tlv::native::borrow_format(format), write_frames, 1,
                            scratch, 16, 1, 2);
    ASSERT_TRUE(writer.set_tag_storage(tlv::span<tlv::byte>(tags, 1)));
    while (!reader.at_end()) {
        auto event = reader.next_event();
        ASSERT_TRUE(event);
        ASSERT_TRUE(writer.write_event(*event));
    }
    ASSERT_TRUE(writer.finish());
    ASSERT_EQ(sizeof(input), writer.size());
    EXPECT_EQ(0, std::memcmp(input, output, sizeof(input)));
    tlv::tree_reader source(tlv::bytes(reinterpret_cast<const tlv::byte*>(input), sizeof(input)),
                            tlv::native::borrow_format(format),
                            tlv::span<tlv::tree_frame>(read_frames, 1), 1, 2);
    tlv::tree_writer_workspace workspace{write_frames,
                                         1,
                                         reinterpret_cast<uint8_t*>(output),
                                         16,
                                         reinterpret_cast<uint8_t*>(scratch),
                                         16,
                                         0,
                                         0};
    auto next = [&](tlv::tree_event& event) -> tlv::expected<bool, tlv::error> {
        if (source.at_end()) return false;
        auto pulled = source.next_event();
        if (!pulled) return tlv::unexpected<tlv::error>(pulled.error());
        event = *pulled;
        return true;
    };
    auto measured =
        tlv::measure_tree_events(tlv::native::borrow_format(format), next, workspace, 1, 2);
    ASSERT_TRUE(measured);
    EXPECT_EQ(sizeof(input), *measured);
}
