// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#include <gtest/gtest.h>
#include <tlv++/tlv.hpp>
#include <tlv++/native.hpp>
#include <vector>
#include <algorithm>
#include <cstring>
#if OPENTLV_BLUETOOTH
#include <tlv/builtins/bluetooth/bluetooth_ltv.h>
#endif
#if OPENTLV_DHCP
#include <tlv/builtins/dhcp/dhcpv4.h>
#endif
#if OPENTLV_NFC
#include <tlv/builtins/nfc/type2.h>
#endif

namespace {
void check_stream(const tlv_format_t& format, const uint8_t* data, size_t size, size_t depth,
                  size_t& count, size_t& deepest) {
    size_t pos = 0;
    while (pos < size) {
        tlv_decoded_t decoded{};
        ASSERT_EQ(TLV_OK, tlv_format_decode(&format, data + pos, size - pos, &decoded, nullptr));
        ASSERT_GT(decoded.source.size, 0u);
        ++count;
        EXPECT_LE(decoded.element.value.size, 256u);
        deepest = std::max(deepest, depth);
        std::vector<uint8_t> reconstructed(decoded.source.size);
        size_t               written = 0;
        ASSERT_EQ(TLV_OK, tlv_write_element(reconstructed.data(), reconstructed.size(), &format,
                                            &decoded.element, &written));
        ASSERT_EQ(decoded.source.size, written);
        EXPECT_EQ(0, std::memcmp(data + pos, reconstructed.data(), written));
        if (format.is_constructed && format.is_constructed(format.context, &decoded.element.tag))
            check_stream(format, decoded.element.value.data,
                         static_cast<size_t>(decoded.element.value.size), depth + 1, count,
                         deepest);
        pos += decoded.source.size;
    }
    EXPECT_EQ(size, pos);
}
void exercise(const tlv_format_t& format, const tlv_generator_candidate_t* candidates, size_t n) {
    tlv_generator_options_t options{42, 0, 20, 3, 256, 2048, candidates, n};
    size_t                  workspace_size = 0;
    ASSERT_EQ(TLV_OK, tlv_generator_workspace_size(&options, &workspace_size));
    std::vector<uint8_t> workspace(workspace_size), out(2048), again(4096);
    bool                 multiple = false, nested = false;
    for (uint64_t index = 0; index < 200; ++index) {
        options.case_index = index;
        size_t written = 0, repeated = 0;
        ASSERT_EQ(TLV_OK, tlv_generate(&format, &options, out.data(), out.size(), workspace.data(),
                                       workspace.size(), &written));
        ASSERT_GT(written, 0u);
        ASSERT_LE(written, options.max_case_size);
        size_t count = 0, deepest = 0;
        check_stream(format, out.data(), written, 0, count, deepest);
        EXPECT_LE(count, options.max_elements);
        EXPECT_LE(deepest, options.max_depth);
        multiple |= count > 1;
        nested |= deepest > 0;
        ASSERT_EQ(TLV_OK, tlv_generate(&format, &options, again.data(), again.size(),
                                       workspace.data(), workspace.size(), &repeated));
        EXPECT_EQ(written, repeated);
        EXPECT_EQ(0, std::memcmp(out.data(), again.data(), written));
    }
    EXPECT_TRUE(multiple);
    if (format.is_constructed) EXPECT_TRUE(nested);
}
} // namespace
TEST(Unit_Generator, FixedAndIndependentBuiltinFamilies) {
    const uint8_t             tags[] = {1, 2, 3};
    tlv_generator_candidate_t candidates[] = {{{tags, 1}, 0, 256}, {{tags + 1, 1}, 0, 256}};
    const tlv_fixed_format_t  config{1, 2, TLV_BYTE_ORDER_BIG_ENDIAN};
    tlv_format_t              fixed{};
    ASSERT_EQ(TLV_OK, tlv_fixed_format_init(&fixed, &config));
    exercise(fixed, candidates, 2);
    fixed.is_constructed = [](const void*, const tlv_tag_t* tag) -> int {
        return tag->size == 1 && tag->data[0] == 2;
    };
    exercise(fixed, candidates, 2);
#if OPENTLV_BLUETOOTH
    exercise(tlv_format_bluetooth_ltv, candidates, 2);
#endif
#if OPENTLV_DHCP
    exercise(tlv_format_dhcpv4, candidates, 2);
#endif
#if OPENTLV_NFC
    exercise(tlv_format_nfc_type2, candidates, 2);
#endif
#if OPENTLV_FORMAT_BER
    const uint8_t                   ber_tags[] = {0x04, 0x30};
    const tlv_generator_candidate_t ber[] = {{{ber_tags, 1}, 0, 256}, {{ber_tags + 1, 1}, 0, 256}};
    exercise(tlv_format_ber, ber, 2);
#endif
}
TEST(Unit_Generator, ValidationAndImpossibleDomain) {
    const uint8_t             tag = 1;
    tlv_generator_candidate_t candidate{{&tag, 1}, 0, 10};
    tlv_generator_options_t   options{0, 0, 10, 0, 10, 64, &candidate, 1};
    const tlv_fixed_format_t  config{2, 1, TLV_BYTE_ORDER_BIG_ENDIAN};
    tlv_format_t              fixed{};
    ASSERT_EQ(TLV_OK, tlv_fixed_format_init(&fixed, &config));
    uint8_t out[64], workspace[64];
    size_t  written = 99;
    EXPECT_EQ(TLV_ERR_LIMIT, tlv_generate(&fixed, &options, out, 64, workspace, 64, &written));
    EXPECT_EQ(99u, written);
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
              tlv_generate(&fixed, &options, out, 63, workspace, 64, &written));
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
              tlv_generate(&fixed, &options, out, 64, workspace, 63, &written));
    options.max_depth = 65;
    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_generator_workspace_size(&options, &written));
    options.max_depth = 1;
    options.max_case_size = SIZE_MAX;
    EXPECT_EQ(TLV_ERR_OVERFLOW, tlv_generator_workspace_size(&options, &written));
    EXPECT_EQ(99u, written);
}
TEST(Unit_Generator, CxxFacadeAndZeroDepth) {
    const uint8_t raw = 1;
    auto          candidate = tlv::make_generator_candidate(
        tlv::tag(tlv::bytes{reinterpret_cast<const tlv::byte*>(&raw), 1}), 0, 10);
    tlv::generator_options   options{0, 7, 1, 0, 10, 64, &candidate, 1};
    const tlv_fixed_format_t config{1, 1, TLV_BYTE_ORDER_BIG_ENDIAN};
    tlv_format_t             fixed{};
    ASSERT_EQ(TLV_OK, tlv_fixed_format_init(&fixed, &config));
    auto required = tlv::generator_workspace_size(options);
    ASSERT_TRUE(required);
    uint8_t output[64], workspace[64];
    auto result = tlv::generate(tlv::native::borrow_format(fixed), options,
                                tlv::span<tlv::byte>{reinterpret_cast<tlv::byte*>(output), 64},
                                tlv::span<tlv::byte>{reinterpret_cast<tlv::byte*>(workspace), 64});
    ASSERT_TRUE(result);
    size_t count = 0, deepest = 0;
    check_stream(fixed, output, *result, 0, count, deepest);
    EXPECT_EQ(1u, count);
    const uint8_t golden[] = {1, 1, 164};
    ASSERT_EQ(sizeof(golden), *result);
    EXPECT_EQ(0, std::memcmp(output, golden, sizeof(golden)));
    EXPECT_EQ(0u, deepest);
}

TEST(Unit_Generator, SamplesValueBoundariesAndChecksLimits) {
    const uint8_t                   tag = 1;
    const tlv_generator_candidate_t candidate{{&tag, 1}, 0, 256};
    tlv_generator_options_t         options{123, 0, 1, 0, 256, 300, &candidate, 1};
    const tlv_fixed_format_t        config{1, 2, TLV_BYTE_ORDER_BIG_ENDIAN};
    tlv_format_t                    fixed{};
    ASSERT_EQ(TLV_OK, tlv_fixed_format_init(&fixed, &config));
    uint8_t output[300], workspace[300];
    bool    seen[257]{};
    for (uint64_t i = 0; i < 400; ++i) {
        options.case_index = i;
        size_t written = 0;
        ASSERT_EQ(TLV_OK, tlv_generate(&fixed, &options, output, 300, workspace, 300, &written));
        tlv_decoded_t decoded{};
        ASSERT_EQ(TLV_OK, tlv_format_decode(&fixed, output, written, &decoded, nullptr));
        ASSERT_LE(decoded.element.value.size, 256u);
        EXPECT_EQ(decoded.source.size, written);
        seen[static_cast<size_t>(decoded.element.value.size)] = true;
    }
    for (size_t n : {0u, 1u, 127u, 128u, 255u, 256u}) EXPECT_TRUE(seen[n]) << n;
    size_t size = 999;
    options.max_elements = 0;
    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_generator_workspace_size(&options, &size));
    EXPECT_EQ(999u, size);
}
#if OPENTLV_FORMAT_BER
TEST(Unit_Generator, EmptyConstructedRootAtZeroDepth) {
    const uint8_t                   tag = 0x30;
    const tlv_generator_candidate_t candidate{{&tag, 1}, 0, 10};
    tlv_generator_options_t         options{0, 0, 1, 0, 10, 64, &candidate, 1};
    uint8_t                         output[64], workspace[64];
    size_t                          written = 0;
    ASSERT_EQ(TLV_OK, tlv_generate(&tlv_format_ber, &options, output, 64, workspace, 64, &written));
    ASSERT_EQ(2u, written);
    EXPECT_EQ(0x30, output[0]);
    EXPECT_EQ(0, output[1]);
}
#endif

TEST(Unit_Generator, RejectsWriterOutputWithChangedSemantics) {
    const uint8_t                   tag = 1;
    const tlv_generator_candidate_t candidate{{&tag, 1}, 1, 10};
    const tlv_generator_options_t   options{0, 0, 4, 0, 10, 64, &candidate, 1};
    const tlv_fixed_format_t        config{1, 1, TLV_BYTE_ORDER_BIG_ENDIAN};
    tlv_format_t                    broken{};
    ASSERT_EQ(TLV_OK, tlv_fixed_format_init(&broken, &config));
    broken.encode = [](const void* context, const tlv_element_t* element, uint8_t* data,
                       size_t capacity, size_t* written, tlv_format_error_t* error) {
        tlv_format_t normal{};
        tlv_fixed_format_init(&normal, static_cast<const tlv_fixed_format_t*>(context));
        auto rc = normal.encode(context, element, data, capacity, written, error);
        if (rc == TLV_OK && element->value.size) data[*written - 1] ^= 1;
        return rc;
    };
    uint8_t output[64], workspace[64];
    size_t  written = 99;
    EXPECT_EQ(TLV_ERR_LIMIT, tlv_generate(&broken, &options, output, 64, workspace, 64, &written));
    EXPECT_EQ(99u, written);
}
