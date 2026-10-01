#include "tlv++/native.hpp"
#include "tlv++/native.hpp"
#include "tlv++/tlv.hpp"
#include "controlled_format.h"

#include <gtest/gtest.h>
#include <cstring>
#include <memory>
#include <type_traits>
#include <utility>

namespace {
tlv::bytes view(const uint8_t* data, size_t size) {
    return {reinterpret_cast<const tlv::byte*>(data), size};
}

template <typename T> struct can_borrow {
    template <typename U>
    static auto check(int)
        -> decltype(tlv::native::borrow_format(std::declval<U>()), std::true_type{});
    template <typename> static std::false_type check(...);
    static const bool                          value = decltype(check<T>(0))::value;
};

static_assert(std::is_trivially_copyable<tlv::format>::value, "Format views must be cheap copies");
static_assert(!std::is_convertible<const tlv_format_t&, tlv::format>::value,
              "Native imports must be explicit");
static_assert(!std::is_convertible<tlv::format, const tlv_format_t&>::value,
              "Native exports must be explicit");
static_assert(can_borrow<tlv_format_t&>::value, "Named native descriptors can be borrowed");
static_assert(can_borrow<const tlv_format_t&>::value, "Immutable descriptors can be borrowed");
static_assert(!can_borrow<tlv_format_t&&>::value, "Temporary native descriptors must be rejected");
static_assert(!can_borrow<const tlv_format_t&&>::value, "Const temporaries must be rejected");

int constructed(const void*, const tlv_tag_t* tag) {
    return tag->size == 1 && tag->data[0] == 0xE1;
}
const tlv_format_t tree_format = {&controlled::format_layout, tlv_fields_decode, tlv_fields_measure,
                                  tlv_fields_encode, constructed};
} // namespace

TEST(Unit_Tlvpp_NativeBoundary, BorrowingPreservesDescriptorAndContextIdentity) {
    const auto format = tlv::native::borrow_format(controlled::format);
    const auto copy = format;
    EXPECT_EQ(&controlled::format, &tlv::native::descriptor(copy));
    EXPECT_EQ(&controlled::format_layout, tlv::native::descriptor(copy).context);
    EXPECT_TRUE(copy.readable());
    EXPECT_TRUE(copy.writable());
    EXPECT_FALSE(copy.has_constructed_classifier());
    EXPECT_TRUE(tlv::native::borrow_format(tree_format).has_constructed_classifier());
}

TEST(Unit_Tlvpp_NativeBoundary, TemporaryViewDoesNotShortenReaderOrSourceLifetime) {
    const uint8_t data[] = {1, 1, 42, 2, 0};
    tlv::reader   reader(view(data, sizeof(data)), tlv::native::borrow_format(controlled::format));
    auto          decoded = reader.next_source();
    ASSERT_TRUE(decoded);
    EXPECT_EQ(&controlled::format, decoded->source.format);
    EXPECT_EQ(reinterpret_cast<const tlv::byte*>(data + 2), decoded->element.value().data());
    EXPECT_EQ(42, static_cast<int>(decoded->element.value().data()[0]));
    EXPECT_EQ(3u, reader.offset());
    tlv::byte output[3]{};
    auto      preserved = tlv::preserve(decoded->source, decoded->element, output, sizeof(output));
    ASSERT_TRUE(preserved);
    EXPECT_EQ(0, std::memcmp(data, output, sizeof(output)));
    ASSERT_TRUE(reader.next());
    EXPECT_TRUE(reader.at_end());
}

TEST(Unit_Tlvpp_NativeBoundary, ReaderRetainsIncrementalAndDiagnosticContracts) {
    const uint8_t          data[] = {1, 2, 42, 43};
    const auto             format = tlv::native::borrow_format(controlled::format);
    tlv::reader            reader(view(data, 3), format, tlv::input_mode::incremental);
    tlv::reader_diagnostic diagnostic{};
    auto                   incomplete = reader.next(diagnostic);
    ASSERT_FALSE(incomplete);
    EXPECT_EQ(TLV_NEED_MORE_DATA, incomplete.error().code);
    EXPECT_EQ(0u, reader.offset());
    ASSERT_TRUE(reader.set_input(view(data, sizeof(data)), 0, tlv::input_mode::final));
    auto complete = reader.next();
    ASSERT_TRUE(complete);
    EXPECT_EQ(2u, complete->value().size());
    EXPECT_TRUE(reader.at_end());

    size_t consumed = 99;
    auto   failed = tlv::read(view(data, 3), format, consumed, &diagnostic);
    ASSERT_FALSE(failed);
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, failed.error().code);
    EXPECT_EQ(99u, consumed);
}

TEST(Unit_Tlvpp_NativeBoundary, FixedViewUsesCanonicalMeasurementAndEncoding) {
    using fixed = tlv::fixed_format<1, 1, TLV_BYTE_ORDER_BIG_ENDIAN>;
    const auto format = fixed::view();
    EXPECT_EQ(&fixed::format(), &tlv::native::descriptor(format));
    const uint8_t data[] = {7, 2, 0xAB, 0xCD};
    auto          decoded = tlv::decode(format, view(data, sizeof(data)));
    ASSERT_TRUE(decoded);
    auto measured = tlv::measure(format, decoded->element);
    ASSERT_TRUE(measured);
    auto size = tlv::encoded_size(decoded->element, format);
    ASSERT_TRUE(size);
    EXPECT_EQ(sizeof(data), *size);
    auto length_size = tlv::encoded_size(decoded->element.tag(), 2, format);
    ASSERT_TRUE(length_size);
    EXPECT_EQ(sizeof(data), *length_size);
    tlv::byte output[4]{};
    auto      encoded = tlv::encode(format, decoded->element, output, sizeof(output));
    ASSERT_TRUE(encoded);
    EXPECT_EQ(sizeof(data), *encoded);
    EXPECT_EQ(0, std::memcmp(data, output, sizeof(data)));
    auto written = tlv::write(output, sizeof(output), format, decoded->element);
    ASSERT_TRUE(written);
    EXPECT_EQ(0, std::memcmp(data, output, sizeof(data)));
    auto pair =
        tlv::write(output, sizeof(output), format, decoded->element.tag(), view(data + 2, 2));
    ASSERT_TRUE(pair);
    EXPECT_EQ(0, std::memcmp(data, output, sizeof(data)));
}

TEST(Unit_Tlvpp_NativeBoundary, TemporaryViewPreservesWriterFailureAndSourceContracts) {
    const uint8_t data[] = {1, 1, 42};
    auto decoded = tlv::decode(tlv::native::borrow_format(controlled::format), view(data, 3));
    ASSERT_TRUE(decoded);
    tlv::byte   output[6]{};
    tlv::writer writer(output, sizeof(output), tlv::native::borrow_format(controlled::format));
    ASSERT_TRUE(writer.write(decoded->element));
    ASSERT_TRUE(writer.preserve(decoded->source, decoded->element));
    EXPECT_EQ(0, std::memcmp(data, output, 3));
    EXPECT_EQ(0, std::memcmp(data, output + 3, 3));
    tlv::writer_diagnostic diagnostic{};
    auto                   failed = writer.write(decoded->element, &diagnostic);
    ASSERT_FALSE(failed);
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, failed.error().code);
    EXPECT_EQ(6u, writer.size());
    EXPECT_EQ(6u, diagnostic.diagnostic.offset);
}

TEST(Unit_Tlvpp_NativeBoundary, InvalidBorrowedDescriptorReportsEngineErrors) {
    const tlv_format_t invalid{};
    const auto         format = tlv::native::borrow_format(invalid);
    EXPECT_FALSE(format.readable());
    EXPECT_FALSE(format.writable());
    tlv::reader reader(tlv::bytes(), format);
    auto        next = reader.next();
    ASSERT_FALSE(next);
    EXPECT_EQ(TLV_ERR_NULL_ARG, next.error().code);
    tlv::writer             writer(nullptr, 0, format);
    const tlv::element_view element{tlv::tag_bytes<1>(), tlv::value_view{}};
    auto                    written = writer.write(element);
    ASSERT_FALSE(written);
    EXPECT_EQ(0u, writer.size());
}

TEST(Unit_Tlvpp_NativeBoundary, VisitorBridgeBorrowsNoncopyableAndConstCallables) {
    struct visitor {
        std::unique_ptr<size_t> count;
        visitor() : count(new size_t(0)) {}
        tlv_visit_result_t operator()(const tlv::element_view&) const {
            ++*count;
            return TLV_VISIT_CONTINUE;
        }
    };
    const uint8_t data[] = {1, 0, 2, 0};
    const visitor callback;
    tlv::reader   reader(view(data, sizeof(data)), tlv::native::borrow_format(controlled::format));
    ASSERT_TRUE(reader.visit(callback));
    EXPECT_EQ(2u, *callback.count);
}

TEST(Unit_Tlvpp_NativeBoundary, TreeAndQueryShareConstructedFormatAndCallbackBridge) {
    const uint8_t    data[] = {0xE1, 2, 1, 0};
    const auto       format = tlv::native::borrow_format(tree_format);
    tlv::tree_frame  frames[2]{};
    tlv::tree_reader reader(view(data, sizeof(data)), format, {frames, 2}, 2, 8);
    size_t           count = 0;
    auto             visitor = [&](const tlv::element_view& element, size_t depth, size_t offset) {
        EXPECT_EQ(count, depth);
        EXPECT_EQ(count * 2, offset);
        EXPECT_EQ(count ? 1 : 0xE1, static_cast<int>(element.tag().data()[0]));
        ++count;
        return TLV_VISIT_CONTINUE;
    };
    ASSERT_TRUE(reader.visit(visitor));
    EXPECT_EQ(2u, count);
    auto query = tlv::query::parse("E1/01");
    ASSERT_TRUE(query);
    count = 1;
    ASSERT_TRUE(query->visit_buffer(view(data, sizeof(data)), format, 2, 8, visitor));
    EXPECT_EQ(2u, count);

    tlv::byte              output[4]{}, scratch[4]{};
    tlv::tree_writer_frame writer_frames[2]{};
    tlv::tree_writer       writer(output, sizeof(output), format, writer_frames, 2, scratch,
                                  sizeof(scratch));
    ASSERT_TRUE(writer.begin(tlv::tag_bytes<0xE1>()));
    ASSERT_TRUE(writer.write(tlv::element_view{tlv::tag_bytes<1>(), tlv::value_view{}}));
    ASSERT_TRUE(writer.end());
    ASSERT_TRUE(writer.finish());
    EXPECT_EQ(sizeof(data), writer.size());
    EXPECT_EQ(0, std::memcmp(data, output, sizeof(data)));
}

TEST(Unit_Tlvpp_NativeBoundary, MeasurementConsumesCanonicalRecordsAndEvents) {
    const uint8_t              data[] = {0xE1, 2, 1, 0};
    const auto                 format = tlv::native::borrow_format(tree_format);
    tlv::tree_frame            read_frames[2]{};
    tlv::tree_writer_frame     write_frames[2]{};
    uint8_t                    output[4]{}, scratch[4]{};
    tlv::tree_writer_workspace workspace{write_frames, 2, output, 4, scratch, 4, 0, 0};
    tlv::tree_reader           records(view(data, sizeof(data)), format, {read_frames, 2}, 2, 8);
    auto                       next_record = [&](tlv::element_view& element, size_t& depth,
                                                 bool& parent) -> tlv::expected<bool, tlv::error> {
        if (records.at_end()) return false;
        auto item = records.next();
        if (!item) return tlv::unexpected<tlv::error>(item.error());
        element = item->element;
        depth = item->depth;
        parent = item->constructed != 0;
        return true;
    };
    auto measured = tlv::measure_tree(format, next_record, workspace);
    ASSERT_TRUE(measured);
    EXPECT_EQ(sizeof(data), *measured);
    EXPECT_EQ(0, std::memcmp(data, output, sizeof(data)));

    tlv::tree_reader events(view(data, sizeof(data)), format, {read_frames, 2}, 2, 8);
    auto             next_event = [&](tlv::tree_event& event) -> tlv::expected<bool, tlv::error> {
        if (events.at_end()) return false;
        auto item = events.next_event();
        if (!item) return tlv::unexpected<tlv::error>(item.error());
        event = *item;
        return true;
    };
    auto staged = tlv::measure_tree_events(format, next_event, workspace);
    ASSERT_TRUE(staged);
    EXPECT_EQ(sizeof(data), *staged);
    EXPECT_EQ(0, std::memcmp(data, output, sizeof(data)));
}

TEST(Unit_Tlvpp_NativeBoundary, SchemaPreservesNamedDiagnosticsThroughFormatView) {
    const auto                   format = tlv::native::borrow_format(controlled::format);
    const uint8_t                valid[] = {1, 1, 42};
    const uint8_t                invalid[] = {2, 0};
    const tlv_schema_entry_t     field{TLV_TAG(1), 1, 1, 0, "one", 0};
    const tlv_structure_rule_t   rule{&field, 1, 1, TLV_SCHEMA_PRIMITIVE, nullptr, 0};
    const tlv_structure_schema_t schema{&rule, 1, 0, nullptr, 0, TLV_SCHEMA_ORDER_ANY};
    ASSERT_TRUE(tlv::validate(view(valid, sizeof(valid)), format, schema, 0, 2));
    tlv::schema_diagnostic diagnostics[4]{};
    auto count = tlv::validate_all_diag(view(invalid, sizeof(invalid)), format, schema, 0, 2,
                                        diagnostics, 4);
    ASSERT_TRUE(count);
    EXPECT_EQ(2u, *count);
    EXPECT_EQ(TLV_SCHEMA_ISSUE_MISSING, diagnostics[0].kind);
    EXPECT_STREQ("one", diagnostics[0].field);
    EXPECT_EQ(TLV_SCHEMA_ISSUE_UNEXPECTED, diagnostics[1].kind);
}

#if OPENTLV_DOCUMENT
TEST(Unit_Tlvpp_NativeBoundary, DocumentCopiesDescriptorAndSurvivesMove) {
    const uint8_t data[] = {0xE1, 2, 1, 0};
    auto          create = [&]() -> tlv::expected<tlv::document, tlv::error> {
        const tlv_format_t   local = tree_format;
        tlv::document_format options(tlv::native::borrow_format(local));
        return tlv::document::parse(view(data, sizeof(data)), options);
    };
    auto parsed = create();
    ASSERT_TRUE(parsed);
    tlv::document moved(std::move(*parsed));
    EXPECT_EQ(2u, moved.size());
    auto format = tlv::native::borrow_format(tree_format);
    auto size = moved.encoded_size(format);
    ASSERT_TRUE(size);
    EXPECT_EQ(sizeof(data), *size);
    auto encoded = moved.encode(format);
    ASSERT_TRUE(encoded);
    EXPECT_EQ(0, std::memcmp(data, encoded->data(), sizeof(data)));
    auto root = moved.first();
    auto root_size = root.encoded_size(format);
    ASSERT_TRUE(root_size);
    EXPECT_EQ(sizeof(data), *root_size);
    auto root_encoded = root.encode(format);
    ASSERT_TRUE(root_encoded);
    EXPECT_EQ(0, std::memcmp(data, root_encoded->data(), sizeof(data)));
}
#endif

#if OPENTLV_FORMAT_BER
TEST(Unit_Tlvpp_NativeBoundary, BerNamespaceSelectsCanonicalDescriptor) {
    const uint8_t data[] = {0x5A, 2, 0x12, 0x34};
    EXPECT_EQ(&tlv_format_ber, &tlv::native::descriptor(tlv::ber::format{}));
    tlv::reader reader(view(data, sizeof(data)), tlv::ber::format{});
    auto        element = reader.next();
    ASSERT_TRUE(element);
    EXPECT_TRUE((tlv::tag_bytes<0x5A>() == element->tag()));
    EXPECT_EQ(2u, element->value().size());
    tlv::byte   output[4]{};
    tlv::writer writer(output, sizeof(output), tlv::ber::format{});
    ASSERT_TRUE(writer.write(*element));
    EXPECT_EQ(0, std::memcmp(data, output, sizeof(data)));
}
#endif
