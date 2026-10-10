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
    tlv::generator       owned(tlv::native::borrow_format(format), options);
    bool                 multiple = false, nested = false;
    for (uint64_t index = 0; index < 200; ++index) {
        options.case_index = index;
        size_t written = 0, repeated = 0;
        ASSERT_EQ(TLV_OK, tlv_generate(&format, &options, out.data(), out.size(), workspace.data(),
                                       workspace.size(), &written));
        ASSERT_GT(written, 0u);
        ASSERT_LE(written, options.max_case_size);
        auto wire = owned.generate(index);
        ASSERT_TRUE(wire);
        ASSERT_EQ(written, wire->size());
        EXPECT_EQ(0, std::memcmp(out.data(), wire->data(), written));
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
    const tlv_fixed_format_t  config{
        {1}, {2, TLV_BYTE_ORDER_BIG_ENDIAN}, TLV_ELEMENT_ORDER_TLV, TLV_LENGTH_SCOPE_VALUE};
    tlv_format_t fixed{};
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
    const tlv_fixed_format_t  config{
        {2}, {1, TLV_BYTE_ORDER_BIG_ENDIAN}, TLV_ELEMENT_ORDER_TLV, TLV_LENGTH_SCOPE_VALUE};
    tlv_format_t fixed{};
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
    EXPECT_EQ(TLV_ERR_UNSUPPORTED, tlv_generator_workspace_size(&options, &written));
    options.max_depth = 1;
    options.max_case_size = SIZE_MAX;
    EXPECT_EQ(TLV_ERR_OVERFLOW, tlv_generator_workspace_size(&options, &written));
    EXPECT_EQ(99u, written);
}
TEST(Unit_Generator, SeedAndCaseIndexDoNotCancel) {
    const auto     candidate = tlv::make_generator_candidate(tlv::tag_bytes<1>(), 32, 32);
    const auto     fixed = tlv::fixed_format<1, 1, tlv::byte_order::big_endian>::view();
    const uint64_t increment = UINT64_C(0x9e3779b97f4a7c15);
    const uint64_t seeds[] = {0, 42, UINT64_MAX};
    const uint64_t indices[] = {1, 2, 7, UINT64_MAX};
    for (const auto seed : seeds) {
        for (const auto index : indices) {
            SCOPED_TRACE(::testing::Message() << "seed=" << seed << " case=" << index);
            tlv::generator_options options{
                seed ^ (index * increment), 0, 1, 0, 32, 64, &candidate, 1};
            tlv::generator first(fixed, options);
            options.seed = seed;
            tlv::generator second(fixed, options);
            auto           a = first.generate(0);
            auto           b = second.generate(index);
            ASSERT_TRUE(a);
            ASSERT_TRUE(b);
            // These pairs produced the identical stream with version 1.
            EXPECT_NE(*a, *b);
            auto replay = first.generate(0);
            ASSERT_TRUE(replay);
            EXPECT_EQ(*a, *replay);
        }
    }
}
TEST(Unit_Generator, CxxFacadeAndZeroDepth) {
    const uint8_t raw = 1;
    auto          candidate = tlv::make_generator_candidate(
        tlv::tag(tlv::bytes{reinterpret_cast<const tlv::byte*>(&raw), 1}), 0, 10);
    tlv::generator_options   options{0, 7, 1, 0, 10, 64, &candidate, 1};
    const tlv_fixed_format_t config{
        {1}, {1, TLV_BYTE_ORDER_BIG_ENDIAN}, TLV_ELEMENT_ORDER_TLV, TLV_LENGTH_SCOPE_VALUE};
    tlv_format_t fixed{};
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
    const uint8_t golden[] = {1, 10, 89, 174, 39, 203, 39, 166, 132, 173, 153, 98};
    ASSERT_EQ(sizeof(golden), *result);
    EXPECT_EQ(0, std::memcmp(output, golden, sizeof(golden)));
    EXPECT_EQ(0u, deepest);
}

TEST(Unit_Generator, OwnedCxxCasesMatchNativeAndSurviveReuse) {
    const uint8_t raw = 1;
    auto          candidate = tlv::make_generator_candidate(
        tlv::tag(tlv::bytes{reinterpret_cast<const tlv::byte*>(&raw), 1}), 0, 128);
    tlv::generator_options options{};
    options.seed = 42;
    options.case_index = 999;
    options.max_elements = 10;
    options.max_depth = 0;
    options.max_value_size = 128;
    options.max_case_size = 512;
    options.candidates = &candidate;
    options.candidate_count = 1;
    const tlv_fixed_format_t config{
        {1}, {2, TLV_BYTE_ORDER_BIG_ENDIAN}, TLV_ELEMENT_ORDER_TLV, TLV_LENGTH_SCOPE_VALUE};
    tlv_format_t fixed{};
    ASSERT_EQ(TLV_OK, tlv_fixed_format_init(&fixed, &config));
    std::vector<tlv::byte> retained;
    {
        tlv::generator generator(tlv::native::borrow_format(fixed), options);
        options.seed = 0; // The wrapper owns its configuration snapshot.
        auto first = generator.generate(7);
        ASSERT_TRUE(first);
        retained = *first;
        for (uint64_t index : {7u, 19u, 0u, 7u}) {
            auto wire = generator.generate(index);
            ASSERT_TRUE(wire);
            auto native_options = options;
            native_options.seed = 42;
            native_options.case_index = index;
            size_t required = 0, written = 0;
            ASSERT_EQ(TLV_OK, tlv_generator_workspace_size(&native_options, &required));
            std::vector<uint8_t> scratch(required), native(512);
            ASSERT_EQ(TLV_OK, tlv_generate(&fixed, &native_options, native.data(), native.size(),
                                           scratch.data(), scratch.size(), &written));
            ASSERT_EQ(written, wire->size());
            EXPECT_EQ(0, std::memcmp(native.data(), wire->data(), written));
            EXPECT_EQ(retained, *first);
            if (index == 7) EXPECT_EQ(retained, *wire);
        }
    }
    EXPECT_FALSE(retained.empty());
    size_t count = 0, deepest = 0;
    check_stream(fixed, reinterpret_cast<const uint8_t*>(retained.data()), retained.size(), 0,
                 count, deepest);
}

TEST(Unit_Generator, OwnedCxxErrorsAndRepeatedCalls) {
    const uint8_t                   raw = 1;
    const tlv_generator_candidate_t candidate{{&raw, 1}, 0, 10};
    tlv::generator_options          options{0, 0, 1, 0, 10, 64, &candidate, 1};
    const tlv_fixed_format_t        config{
        {1}, {1, TLV_BYTE_ORDER_BIG_ENDIAN}, TLV_ELEMENT_ORDER_TLV, TLV_LENGTH_SCOPE_VALUE};
    tlv_format_t fixed{};
    ASSERT_EQ(TLV_OK, tlv_fixed_format_init(&fixed, &config));
    options.max_elements = 0;
    tlv::generator invalid(tlv::native::borrow_format(fixed), options);
    auto           result = invalid.generate(0);
    ASSERT_FALSE(result);
    EXPECT_EQ(tlv::errc::invalid_argument, result.error().status());
    options.max_elements = 1;
    options.max_depth = 1;
    options.max_case_size = SIZE_MAX;
    tlv::generator overflow(tlv::native::borrow_format(fixed), options);
    auto           overflow_result = overflow.generate(0);
    ASSERT_FALSE(overflow_result);
    EXPECT_EQ(tlv::errc::overflow, overflow_result.error().status());
    options.max_depth = 0;
    options.max_case_size = 1; // Too small even for an empty element.
    tlv::generator impossible(tlv::native::borrow_format(fixed), options);
    for (uint64_t index : {0u, 7u}) {
        auto impossible_result = impossible.generate(index);
        ASSERT_FALSE(impossible_result);
        EXPECT_EQ(tlv::errc::limit, impossible_result.error().status());
    }
    options.max_case_size = 64;
    tlv_format_t   unavailable{};
    tlv::generator missing(tlv::native::borrow_format(unavailable), options);
    auto           missing_result = missing.generate(0);
    ASSERT_FALSE(missing_result);
    EXPECT_EQ(tlv::errc::unsupported, missing_result.error().status());
    tlv::generator valid(tlv::native::borrow_format(fixed), options);
    EXPECT_TRUE(valid.generate(0));
    EXPECT_TRUE(valid.generate(7));
}

TEST(Unit_Generator, SamplesValueBoundariesAndChecksLimits) {
    const uint8_t                   tag = 1;
    const tlv_generator_candidate_t candidate{{&tag, 1}, 0, 256};
    tlv_generator_options_t         options{123, 0, 1, 0, 256, 300, &candidate, 1};
    const tlv_fixed_format_t        config{
        {1}, {2, TLV_BYTE_ORDER_BIG_ENDIAN}, TLV_ELEMENT_ORDER_TLV, TLV_LENGTH_SCOPE_VALUE};
    tlv_format_t fixed{};
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
    const tlv_fixed_format_t        config{
        {1}, {1, TLV_BYTE_ORDER_BIG_ENDIAN}, TLV_ELEMENT_ORDER_TLV, TLV_LENGTH_SCOPE_VALUE};
    tlv_format_t broken{};
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
    EXPECT_EQ(TLV_ERR_CALLBACK,
              tlv_generate(&broken, &options, output, 64, workspace, 64, &written));
    EXPECT_EQ(99u, written);
}

namespace {
class GeneratorResults : public ::testing::Test {
protected:
    const uint8_t             tag = 1;
    tlv_generator_candidate_t candidate{{&tag, 1}, 0, 10};
    tlv_generator_options_t   options{0, 0, 1, 0, 10, 64, &candidate, 1};
    const tlv_fixed_format_t  config{
        {1}, {1, TLV_BYTE_ORDER_BIG_ENDIAN}, TLV_ELEMENT_ORDER_TLV, TLV_LENGTH_SCOPE_VALUE};
    tlv_format_t format{};

    void SetUp() override {
        ASSERT_EQ(TLV_OK, tlv_fixed_format_init(&format, &config));
    }

    void expect_result(tlv_result_t expected) {
        // All three entry points must agree, including combined-invalid inputs.
        uint8_t output[64], workspace[64];
        size_t  written = 99;
        auto    rc = tlv_generate(&format, &options, output, sizeof(output), workspace,
                                  sizeof(workspace), &written);
        EXPECT_EQ(expected, rc);
        if (expected != TLV_OK) EXPECT_EQ(99u, written);
        auto borrowed = tlv::generate(
            tlv::native::borrow_format(format), options,
            tlv::span<tlv::byte>{reinterpret_cast<tlv::byte*>(output), sizeof(output)},
            tlv::span<tlv::byte>{reinterpret_cast<tlv::byte*>(workspace), sizeof(workspace)});
        EXPECT_EQ(expected,
                  borrowed ? TLV_OK : static_cast<tlv_result_t>(borrowed.error().status()));
        tlv::generator generator(tlv::native::borrow_format(format), options);
        auto           owned = generator.generate(options.case_index);
        EXPECT_EQ(expected, owned ? TLV_OK : static_cast<tlv_result_t>(owned.error().status()));
        if (expected == TLV_OK && borrowed && owned) {
            EXPECT_EQ(written, *borrowed);
            ASSERT_EQ(written, owned->size());
            EXPECT_EQ(0, std::memcmp(output, owned->data(), written));
        }
    }

    void expect_workspace(tlv_result_t expected) {
        size_t size = 99;
        EXPECT_EQ(expected, tlv_generator_workspace_size(&options, &size));
        if (expected != TLV_OK) EXPECT_EQ(99u, size);
        auto result = tlv::generator_workspace_size(options);
        EXPECT_EQ(expected, result ? TLV_OK : static_cast<tlv_result_t>(result.error().status()));
    }
};
} // namespace

TEST_F(GeneratorResults, CapabilitiesAndValidationPrecedence) {
    const auto original = format;
    for (int missing = 0; missing < 4; ++missing) {
        SCOPED_TRACE(missing);
        format = original;
        if (missing == 0) format.decode = nullptr;
        if (missing == 1) format.measure = nullptr;
        if (missing == 2) format.encode = nullptr;
        if (missing == 3) format = {};
        options.max_elements = 1;
        expect_result(TLV_ERR_UNSUPPORTED);
        options.max_elements = 0;
        expect_result(TLV_ERR_UNSUPPORTED);
    }
    format = original;
    expect_result(TLV_ERR_INVALID_ARG);
    options.max_elements = 1;
    options.max_depth = 65;
    expect_workspace(TLV_ERR_UNSUPPORTED);
    expect_result(TLV_ERR_UNSUPPORTED);
    options.max_depth = SIZE_MAX;
    expect_workspace(TLV_ERR_UNSUPPORTED);
    expect_result(TLV_ERR_UNSUPPORTED);
    options.max_depth = 64;
    size_t size = 0;
    ASSERT_EQ(TLV_OK, tlv_generator_workspace_size(&options, &size));
    EXPECT_EQ(65u * options.max_case_size, size);
}

TEST_F(GeneratorResults, NullTopLevelPointersPrecedeCapabilities) {
    uint8_t output[64], workspace[64];
    size_t  written = 99;
    format = {};
    EXPECT_EQ(TLV_ERR_NULL_ARG,
              tlv_generate(nullptr, &options, output, 64, workspace, 64, &written));
    EXPECT_EQ(TLV_ERR_NULL_ARG,
              tlv_generate(&format, nullptr, output, 64, workspace, 64, &written));
    EXPECT_EQ(TLV_ERR_NULL_ARG,
              tlv_generate(&format, &options, nullptr, 64, workspace, 64, &written));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_generate(&format, &options, output, 64, nullptr, 64, &written));
    EXPECT_EQ(TLV_ERR_NULL_ARG,
              tlv_generate(&format, &options, output, 64, workspace, 64, nullptr));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_generator_workspace_size(nullptr, &written));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_generator_workspace_size(&options, nullptr));
    EXPECT_EQ(99u, written);
}

TEST_F(GeneratorResults, ContradictoryValueLimitsAndMixedDomains) {
    candidate.min_value_size = 1;
    options.max_value_size = 0;
    expect_workspace(TLV_ERR_INVALID_ARG);
    expect_result(TLV_ERR_INVALID_ARG);
    options.max_value_size = 10;
    options.max_case_size = 1;
    candidate.min_value_size = 2;
    expect_workspace(TLV_ERR_INVALID_ARG);
    expect_result(TLV_ERR_INVALID_ARG);

    // A feasible Value need not leave room for the Format's framing.
    candidate.min_value_size = 1;
    expect_workspace(TLV_OK);
    expect_result(TLV_ERR_LIMIT);

    options.max_case_size = 64;
    tlv_generator_candidate_t mixed[] = {{{&tag, 1}, 11, 20}, {{&tag, 1}, 0, 0}};
    options.candidates = mixed;
    options.candidate_count = 2;
    expect_workspace(TLV_OK);
    expect_result(TLV_OK);
    // Do not stop descriptor validation after finding a feasible candidate.
    std::swap(mixed[0], mixed[1]);
    mixed[1].min_value_size = 21;
    expect_workspace(TLV_ERR_INVALID_ARG);
    expect_result(TLV_ERR_INVALID_ARG);
    mixed[1] = {{nullptr, 1}, 0, 0};
    expect_workspace(TLV_ERR_INVALID_ARG);
    expect_result(TLV_ERR_INVALID_ARG);
}

TEST_F(GeneratorResults, OverflowAndInvalidDescriptors) {
    options.max_elements = SIZE_MAX / 64 + 1;
    expect_workspace(TLV_ERR_OVERFLOW);
    expect_result(TLV_ERR_OVERFLOW);
    options.max_elements = 1;
    options.max_case_size = SIZE_MAX;
    expect_workspace(TLV_ERR_OVERFLOW);
    expect_result(TLV_ERR_OVERFLOW);
    options.max_case_size = SIZE_MAX / 2 + 1;
    options.max_depth = 1;
    expect_workspace(TLV_ERR_OVERFLOW);
    expect_result(TLV_ERR_OVERFLOW);
    options.max_case_size = 64;
    options.max_depth = 0;
    options.candidates = nullptr;
    expect_workspace(TLV_ERR_INVALID_ARG);
    expect_result(TLV_ERR_INVALID_ARG);
    options.candidates = &candidate;
    options.candidate_count = 0;
    expect_workspace(TLV_ERR_INVALID_ARG);
    expect_result(TLV_ERR_INVALID_ARG);
}

TEST_F(GeneratorResults, CallbackFailuresFromEveryOperation) {
    const auto original = format;
    for (int operation = 0; operation < 3; ++operation) {
        SCOPED_TRACE(operation);
        format = original;
        if (operation == 0)
            format.measure = [](const void*, const tlv_element_t*, tlv_encoding_t*,
                                tlv_format_error_t*) { return TLV_ERR_CALLBACK; };
        if (operation == 1)
            format.encode = [](const void*, const tlv_element_t*, uint8_t*, size_t, size_t*,
                               tlv_format_error_t*) { return TLV_ERR_CALLBACK; };
        if (operation == 2)
            format.decode = [](const void*, const uint8_t*, size_t, tlv_decoded_t*,
                               tlv_format_error_t*) { return TLV_ERR_CALLBACK; };
        expect_result(TLV_ERR_CALLBACK);
    }
}

TEST_F(GeneratorResults, SemanticMismatchAndMalformedSuccessPayload) {
    candidate.min_value_size = 1;
    const auto original = format;
    format.encode = [](const void* context, const tlv_element_t* element, uint8_t* data,
                       size_t capacity, size_t* written, tlv_format_error_t* error) {
        tlv_format_t normal{};
        tlv_fixed_format_init(&normal, static_cast<const tlv_fixed_format_t*>(context));
        auto rc = normal.encode(context, element, data, capacity, written, error);
        if (rc == TLV_OK) data[0] ^= 1;
        return rc;
    };
    expect_result(TLV_ERR_CALLBACK);
    format = original;
    format.encode = [](const void*, const tlv_element_t*, uint8_t*, size_t, size_t* written,
                       tlv_format_error_t*) {
        *written = 0; // Success disagrees with the measured nonempty representation.
        return TLV_OK;
    };
    expect_result(TLV_ERR_CALLBACK);
    format = original;
    format.decode = [](const void*, const uint8_t*, size_t, tlv_decoded_t* decoded,
                       tlv_format_error_t*) {
        *decoded = {}; // Invalid successful source extent, caught by Format.
        return TLV_OK;
    };
    expect_result(TLV_ERR_CALLBACK);
}

TEST_F(GeneratorResults, NestedCallbackFailureAbortsWholeCase) {
    struct context {
        tlv_format_t   base;
        mutable size_t calls = 0;
    } state;
    state.base = format;
    format.context = &state;
    format.measure = [](const void* opaque, const tlv_element_t* element, tlv_encoding_t* size,
                        tlv_format_error_t* error) {
        const auto& s = *static_cast<const context*>(opaque);
        return s.base.measure(s.base.context, element, size, error);
    };
    format.decode = [](const void* opaque, const uint8_t* data, size_t size, tlv_decoded_t* decoded,
                       tlv_format_error_t* error) {
        const auto& s = *static_cast<const context*>(opaque);
        return s.base.decode(s.base.context, data, size, decoded, error);
    };
    options.max_elements = 2;
    options.max_depth = 1;
    format.is_constructed = [](const void*, const tlv_tag_t*) { return 1; };
    format.encode = [](const void* opaque, const tlv_element_t* element, uint8_t* data,
                       size_t capacity, size_t* written, tlv_format_error_t* error) {
        const auto& s = *static_cast<const context*>(opaque);
        if (++s.calls == 1) return TLV_ERR_CALLBACK;
        return s.base.encode(s.base.context, element, data, capacity, written, error);
    };
    // The root must not swallow a child failure and publish an empty Value.
    uint8_t output[64], workspace[128];
    size_t  written = 99;
    EXPECT_EQ(TLV_ERR_CALLBACK, tlv_generate(&format, &options, output, sizeof(output), workspace,
                                             sizeof(workspace), &written));
    EXPECT_EQ(99u, written);
    EXPECT_EQ(1u, state.calls);
    state.calls = 0;
    tlv::generator generator(tlv::native::borrow_format(format), options);
    auto           result = generator.generate(0);
    ASSERT_FALSE(result);
    EXPECT_EQ(tlv::errc::callback, result.error().status());
    EXPECT_EQ(1u, state.calls);
}

TEST_F(GeneratorResults, ReconstructionFilteringAndFailureAfterPartialSuccess) {
    struct context {
        tlv_format_t   base;
        mutable size_t calls = 0;
        size_t         fail_at = 0;
        bool           alternate_framing = false;
        uint8_t        semantic_tag = 1;
    } state;
    state.base = format;
    format.context = &state;
    format.measure = [](const void* opaque, const tlv_element_t* element, tlv_encoding_t* size,
                        tlv_format_error_t* error) {
        const auto& s = *static_cast<const context*>(opaque);
        return s.base.measure(s.base.context, element, size, error);
    };
    format.decode = [](const void* opaque, const uint8_t* data, size_t size, tlv_decoded_t* decoded,
                       tlv_format_error_t* error) {
        const auto& s = *static_cast<const context*>(opaque);
        auto        rc = s.base.decode(s.base.context, data, size, decoded, error);
        // This test Format gives two wire identifiers the same semantic identity.
        if (rc == TLV_OK && s.alternate_framing) {
            decoded->element.tag = {&s.semantic_tag, 1};
            decoded->source.tag_binding = TLV_TAG_BINDING_FORMAT;
        }
        return rc;
    };
    format.encode = [](const void* opaque, const tlv_element_t* element, uint8_t* data,
                       size_t capacity, size_t* written, tlv_format_error_t* error) {
        const auto& s = *static_cast<const context*>(opaque);
        if (++s.calls == s.fail_at) return TLV_ERR_CALLBACK;
        auto rc = s.base.encode(s.base.context, element, data, capacity, written, error);
        // A stable choice based on identifier storage exercises the byte-exact
        // filter without changing decoded Tag/Value semantics.
        if (rc == TLV_OK && s.alternate_framing && element->tag.data == &s.semantic_tag)
            data[0] |= 0x80;
        return rc;
    };
    candidate.max_value_size = 0;
    options.max_elements = 2;
    for (size_t fail_at : {2u, 3u, 0u}) {
        SCOPED_TRACE(fail_at);
        state.fail_at = fail_at;
        state.alternate_framing = fail_at == 0;
        bool reached = false;
        // Some seeds choose only one element. Find a two-element case to prove
        // a later callback failure discards earlier successfully accepted output.
        for (uint64_t seed = 0; seed < 32 && !reached; ++seed) {
            options.seed = seed;
            for (int facade = 0; facade < 3; ++facade) {
                state.calls = 0;
                uint8_t      output[64], workspace[64];
                size_t       written = 99;
                tlv_result_t rc;
                if (facade == 0) {
                    rc = tlv_generate(&format, &options, output, 64, workspace, 64, &written);
                    if (rc != TLV_OK) EXPECT_EQ(99u, written);
                } else if (facade == 1) {
                    auto result = tlv::generate(
                        tlv::native::borrow_format(format), options,
                        tlv::span<tlv::byte>{reinterpret_cast<tlv::byte*>(output), 64},
                        tlv::span<tlv::byte>{reinterpret_cast<tlv::byte*>(workspace), 64});
                    rc = result ? TLV_OK : static_cast<tlv_result_t>(result.error().status());
                } else {
                    tlv::generator generator(tlv::native::borrow_format(format), options);
                    auto           result = generator.generate(0);
                    rc = result ? TLV_OK : static_cast<tlv_result_t>(result.error().status());
                }
                if (fail_at == 0) {
                    EXPECT_EQ(TLV_ERR_LIMIT, rc);
                    reached = true;
                } else if (state.calls >= fail_at) {
                    EXPECT_EQ(TLV_ERR_CALLBACK, rc);
                    EXPECT_EQ(fail_at, state.calls); // Abort immediately, with no retry.
                    reached = true;
                } else {
                    EXPECT_EQ(TLV_OK, rc);
                }
            }
        }
        EXPECT_TRUE(reached);
    }
}
