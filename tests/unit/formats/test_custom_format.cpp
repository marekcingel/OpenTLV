#include "custom_cpp_format.hpp"
#include "tlv++/tlv.hpp"
#include <gtest/gtest.h>
#include <cstring>
#include <type_traits>

namespace {
tlv::bytes bytes(const unsigned char* data, size_t size) {
    return tlv::bytes(reinterpret_cast<const tlv::byte*>(data), size);
}
struct read_only {
    tlv::expected<tlv::decoded, tlv::format_failure> decode(tlv::bytes input) const noexcept {
        return custom_cpp_format{}.decode(input);
    }
};
struct write_only {
    tlv::expected<tlv::encoding, tlv::format_failure>
    measure(const tlv::measure_request& value) const noexcept {
        return custom_cpp_format{}.measure(value);
    }
    tlv::expected<size_t, tlv::format_failure> encode(const tlv::element_view& value,
                                                      tlv::span<tlv::byte>     out) const noexcept {
        return custom_cpp_format{}.encode(value, out);
    }
};
struct content_format : custom_cpp_format {
    tlv::expected<tlv::encoding, tlv::format_failure>
    measure(const tlv::measure_request& value) const noexcept {
        if (value.value_size && !value.content.data())
            return tlv::unexpected<tlv::format_failure>(tlv::format_failure(TLV_ERR_NULL_ARG));
        return custom_cpp_format::measure(value);
    }
};
struct logical_format {
    tlv::expected<tlv::encoding, tlv::format_failure>
    measure(const tlv::measure_request& value) const noexcept {
        if (value.value_size > TLV_SIZE_MAX - 3)
            return tlv::unexpected<tlv::format_failure>(tlv::format_failure(TLV_ERR_OVERFLOW));
        return tlv::encoding{2, value.value_size, 1, value.value_size + 3};
    }
    tlv::expected<size_t, tlv::format_failure> encode(const tlv::element_view&,
                                                      tlv::span<tlv::byte>) const noexcept {
        return tlv::unexpected<tlv::format_failure>(tlv::format_failure(TLV_ERR_INVALID_VALUE));
    }
};
struct invalid_decode : custom_cpp_format {
    tlv::expected<tlv::decoded, tlv::format_failure> decode(tlv::bytes input) const noexcept {
        auto result = custom_cpp_format::decode(input);
        if (result) result->source.tag.offset = 1;
        return result;
    }
};
struct invalid_measure : custom_cpp_format {
    tlv::expected<tlv::encoding, tlv::format_failure>
    measure(const tlv::measure_request& value) const noexcept {
        auto result = custom_cpp_format::measure(value);
        if (result) ++result->total;
        return result;
    }
};
struct invalid_encode : custom_cpp_format {
    tlv::expected<size_t, tlv::format_failure> encode(const tlv::element_view&,
                                                      tlv::span<tlv::byte>) const noexcept {
        return size_t{0};
    }
};
struct move_only_format : read_only {
    move_only_format() = default;
    move_only_format(const move_only_format&) = delete;
    move_only_format(move_only_format&&) = default;
};
struct customized_view : tlv::format {
    customized_view() : tlv::format(tlv::fixed_format<1, 1, TLV_BYTE_ORDER_BIG_ENDIAN>::view()) {}
};
struct adapted_format {
    unsigned char trailer;
};
} // namespace
namespace tlv {
template <> struct format_traits<adapted_format> {
    static expected<decoded, format_failure> decode(const adapted_format& f, bytes data) noexcept {
        custom_cpp_format impl;
        impl.trailer = f.trailer;
        return impl.decode(data);
    }
};
template <> struct format_traits<customized_view> {
    static expected<decoded, format_failure> decode(const customized_view&, bytes data) noexcept {
        return custom_cpp_format{}.decode(data);
    }
};
} // namespace tlv
static_assert(tlv::format_capabilities<custom_cpp_format>::valid, "custom contract");
static_assert(tlv::format_capabilities<read_only>::readable, "read-only contract");
static_assert(!tlv::format_capabilities<read_only>::writable, "read-only capability");
static_assert(tlv::format_capabilities<write_only>::writable, "write-only contract");
static_assert(!tlv::format_capabilities<write_only>::readable, "write-only capability");
static_assert(!std::is_copy_constructible<tlv::format_adapter<custom_cpp_format>>::value,
              "stable address");
static_assert(!std::is_move_constructible<tlv::reader<custom_cpp_format>>::value, "stable cursor");
static_assert(tlv::format_capabilities<tlv::fixed_format<1, 1, TLV_BYTE_ORDER_BIG_ENDIAN>>::valid,
              "fixed contract");
#if OPENTLV_FORMAT_BER
static_assert(tlv::format_capabilities<tlv::ber::format>::valid, "BER contract");
#endif
#if OPENTLV_FORMAT_DER
static_assert(tlv::format_capabilities<tlv::der::format>::valid, "DER contract");
#endif
#if OPENTLV_FORMAT_CER
static_assert(tlv::format_capabilities<tlv::cer::format>::valid, "CER contract");
#endif
#if OPENTLV_BLUETOOTH
static_assert(tlv::format_capabilities<tlv::bluetooth::format>::valid, "Bluetooth contract");
#endif
#if OPENTLV_EMV
static_assert(tlv::format_capabilities<tlv::emv::format>::valid, "EMV contract");
#endif
#if OPENTLV_LLDP
static_assert(tlv::format_capabilities<tlv::lldp::format>::valid, "LLDP contract");
#endif
#if OPENTLV_DHCP
static_assert(tlv::format_capabilities<tlv::dhcp::format>::valid, "DHCP contract");
#endif
#if OPENTLV_NFC
static_assert(tlv::format_capabilities<tlv::nfc::format>::valid, "NFC contract");
#endif

TEST(Unit_Tlvpp_CustomFormat, IndependentWireAndSourcePreservation) {
    const unsigned char            wire[] = {1, 1, 0x7A, 0xA5};
    tlv::reader<custom_cpp_format> reader(bytes(wire, sizeof(wire)));
    auto                           result = reader.next_source();
    ASSERT_TRUE(result);
    EXPECT_EQ(tlv::tag_bytes<1>(), result->element.tag());
    ASSERT_EQ(1u, result->element.value().size());
    EXPECT_EQ(static_cast<tlv::byte>(0x7A), result->element.value()[0]);
    EXPECT_EQ(3u, result->source.trailer.offset);
    EXPECT_EQ(1u, result->source.trailer.size);
    tlv::byte                      out[4]{};
    tlv::writer<custom_cpp_format> writer(out, sizeof(out));
    ASSERT_TRUE(writer.write(result->element));
    EXPECT_EQ(sizeof(wire), writer.size());
    EXPECT_EQ(0, std::memcmp(wire, out, sizeof(wire)));
    ASSERT_TRUE(tlv::preserve(result->source, result->element, out, sizeof(out)));
    EXPECT_EQ(0, std::memcmp(wire, out, sizeof(wire)));
}

TEST(Unit_Tlvpp_CustomFormat, ImmutableConfigurationAndTraitSpecialization) {
    custom_cpp_format config;
    config.trailer = 0xB6;
    const unsigned char            wire[] = {1, 0, 0xB6};
    tlv::reader<custom_cpp_format> reader(bytes(wire, sizeof(wire)), config);
    config.trailer = 0; // The cursor owns an immutable copy.
    ASSERT_TRUE(reader.next());
    tlv::reader<adapted_format> adapted(bytes(wire, sizeof(wire)), adapted_format{0xB6});
    ASSERT_TRUE(adapted.next());
    tlv::reader<read_only> readonly(bytes(wire, 0));
    EXPECT_TRUE(readonly.at_end());
    tlv::format_adapter<write_only> writable;
    EXPECT_FALSE(writable.view().readable());
    EXPECT_TRUE(writable.view().writable());
    EXPECT_FALSE(writable.view().has_constructed_classifier());
}

TEST(Unit_Tlvpp_CustomFormat, IncrementalAndMalformedInputDiagnostics) {
    unsigned char                  wire[] = {1, 1, 0x7A, 0xA5};
    tlv::reader<custom_cpp_format> reader(bytes(wire, 3), custom_cpp_format{},
                                          tlv::input_mode::incremental);
    tlv::reader_diagnostic         diagnostic{};
    auto                           incomplete = reader.next(diagnostic);
    ASSERT_FALSE(incomplete);
    EXPECT_EQ(TLV_NEED_MORE_DATA, incomplete.error().code);
    EXPECT_EQ(0u, reader.consumed());
    EXPECT_TRUE(diagnostic.has_required);
    EXPECT_EQ(4u, diagnostic.required);
    ASSERT_TRUE(reader.set_input(bytes(wire, 4), 0, tlv::input_mode::final));
    ASSERT_TRUE(reader.next());
    wire[3] = 0;
    tlv::reader<custom_cpp_format> malformed(bytes(wire, 4));
    auto                           invalid = malformed.next(diagnostic);
    ASSERT_FALSE(invalid);
    EXPECT_EQ(TLV_ERR_INVALID_VALUE, invalid.error().code);
    EXPECT_EQ(0u, malformed.consumed());
}

TEST(Unit_Tlvpp_CustomFormat, TreeWriterAndQueryUseCanonicalMachinery) {
    tlv::format_adapter<custom_cpp_format> format;
    const unsigned char                    wire[] = {0x81, 4, 1, 1, 0x7A, 0xA5, 0xA5};
    tlv::tree_frame                        frames[2]{};
    tlv::tree_reader                       reader(bytes(wire, sizeof(wire)), format.view(),
                                                  tlv::span<tlv::tree_frame>(frames, 2), 2, 8);
    auto                                   root = reader.next();
    ASSERT_TRUE(root);
    EXPECT_TRUE(root->constructed);
    auto child = reader.next();
    ASSERT_TRUE(child);
    EXPECT_EQ(1u, child->depth);
    EXPECT_EQ(tlv::tag_bytes<1>(), child->element.tag());
    tlv::byte              out[16]{}, scratch[16]{};
    tlv::tree_writer_frame write_frames[2]{};
    tlv::tree_writer       writer(out, sizeof(out), format.view(), write_frames, 2, scratch,
                                  sizeof(scratch));
    ASSERT_TRUE(writer.begin(tlv::tag_bytes<0x81>()));
    ASSERT_TRUE(writer.write(child->element));
    ASSERT_TRUE(writer.end());
    ASSERT_TRUE(writer.finish());
    EXPECT_EQ(sizeof(wire), writer.size());
    EXPECT_EQ(0, std::memcmp(wire, out, sizeof(wire)));
    auto query = tlv::query::parse("81/01");
    ASSERT_TRUE(query);
    size_t matches = 0;
    ASSERT_TRUE(query->visit_buffer(bytes(wire, sizeof(wire)), format.view(), 2, 8,
                                    [&](const tlv::element_view& item, size_t depth, size_t) {
                                        EXPECT_EQ(tlv::tag_bytes<1>(), item.tag());
                                        EXPECT_EQ(1u, depth);
                                        ++matches;
                                        return TLV_VISIT_CONTINUE;
                                    }));
    EXPECT_EQ(1u, matches);
}

#if OPENTLV_DOCUMENT
TEST(Unit_Tlvpp_CustomFormat, DocumentAndSelectedSubtreeKeepCustomFormat) {
    tlv::format_adapter<custom_cpp_format> format;
    const unsigned char                    wire[] = {0x81, 4, 1, 1, 0x7A, 0xA5, 0xA5};
    auto                                   document =
        tlv::document::parse(bytes(wire, sizeof(wire)), tlv::document_format(format.view()));
    ASSERT_TRUE(document);
    auto out = document->encode();
    ASSERT_TRUE(out);
    ASSERT_EQ(sizeof(wire), out->size());
    EXPECT_EQ(0, std::memcmp(wire, out->data(), sizeof(wire)));
    auto measured = document->encoded_size(format.view());
    ASSERT_TRUE(measured);
    EXPECT_EQ(sizeof(wire), *measured);
    tlv::tree_frame  frames[2]{};
    tlv::tree_reader reader(bytes(wire, sizeof(wire)), format.view(),
                            tlv::span<tlv::tree_frame>(frames, 2), 2, 8);
    ASSERT_TRUE(reader.next());
    auto builder = tlv::document_builder::current_subtree(reader);
    ASSERT_TRUE(builder);
    auto subtree = builder->consume();
    ASSERT_TRUE(subtree);
    auto encoded = subtree->encode();
    ASSERT_TRUE(encoded);
    ASSERT_EQ(sizeof(wire), encoded->size());
    EXPECT_EQ(0, std::memcmp(wire, encoded->data(), sizeof(wire)));
}
#endif

#if OPENTLV_FORMAT_BER
TEST(Unit_Tlvpp_CustomFormat, BuiltinFormatUsesTheSameTypedReaderWriter) {
    const unsigned char           wire[] = {4, 1, 0x7A};
    tlv::reader<tlv::ber::format> reader(bytes(wire, sizeof(wire)));
    auto                          item = reader.next();
    ASSERT_TRUE(item);
    tlv::byte                     out[3]{};
    tlv::writer<tlv::ber::format> writer(out, sizeof(out));
    ASSERT_TRUE(writer.write(*item));
    EXPECT_EQ(0, std::memcmp(wire, out, sizeof(wire)));
}
#endif

TEST(Unit_Tlvpp_CustomFormat, LogicalSizeOnlyMeasurementDoesNotNarrow) {
    tlv::format_adapter<logical_format> format;
    const tlv_size_t                    logical = UINT64_C(4294967296);
    auto                                measured = tlv::measure(
        format.view(), tlv::measure_request{tlv::tag_bytes<1>(), logical, tlv::bytes(nullptr, 0)});
    ASSERT_TRUE(measured);
    EXPECT_EQ(logical, measured->value);
    EXPECT_EQ(logical + 3, measured->total);
    auto overflow =
        tlv::measure(format.view(), tlv::measure_request{tlv::tag_bytes<1>(), TLV_SIZE_MAX,
                                                         tlv::bytes(nullptr, 0)});
    ASSERT_FALSE(overflow);
    EXPECT_EQ(TLV_ERR_OVERFLOW, overflow.error().code);
    const unsigned char content[] = {0};
    auto mismatch = tlv::measure(format.view(),
                                 tlv::measure_request{tlv::tag_bytes<1>(), 2, bytes(content, 1)});
    ASSERT_FALSE(mismatch);
    EXPECT_EQ(TLV_ERR_INVALID_ARG, mismatch.error().code);
}

TEST(Unit_Tlvpp_CustomFormat, CoreRejectsInvalidCallbackResults) {
    const unsigned char         wire[] = {1, 1, 0x7A, 0xA5};
    tlv::reader<invalid_decode> broken(bytes(wire, sizeof(wire)));
    auto                        decoded = broken.next_source();
    ASSERT_FALSE(decoded);
    EXPECT_EQ(TLV_ERR_INVALID_ARG, decoded.error().code);
    EXPECT_EQ(0u, broken.consumed());
    tlv::reader<custom_cpp_format> reader(bytes(wire, sizeof(wire)));
    auto                           value = reader.next();
    ASSERT_TRUE(value);
    tlv::format_adapter<invalid_measure> bad_measure;
    auto                                 measured = tlv::measure(bad_measure.view(), *value);
    ASSERT_FALSE(measured);
    EXPECT_EQ(TLV_ERR_INVALID_ARG, measured.error().code);
    tlv::byte                   out[4]{};
    tlv::writer<invalid_encode> bad_encoder(out, sizeof(out));
    auto                        encoded = bad_encoder.write(*value);
    ASSERT_FALSE(encoded);
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, encoded.error().code);
    EXPECT_EQ(0u, bad_encoder.size());
}

TEST(Unit_Tlvpp_CustomFormat, MoveOnlyConfigurationNeedsNoCopy) {
    const unsigned char           wire[] = {1, 0, 0xA5};
    tlv::reader<move_only_format> reader(bytes(wire, sizeof(wire)));
    ASSERT_TRUE(reader.next());
    tlv::format_adapter<move_only_format> adapter(move_only_format{});
    tlv::reader<>                         runtime(bytes(wire, sizeof(wire)), adapter.view());
    ASSERT_TRUE(runtime.next());
}

TEST(Unit_Tlvpp_CustomFormat, ContentDependentMeasurementReceivesReadableValue) {
    tlv::format_adapter<content_format> format;
    const unsigned char                 wire[] = {1, 1, 0x7A, 0xA5};
    tlv::reader<content_format>         reader(bytes(wire, sizeof(wire)));
    auto                                item = reader.next();
    ASSERT_TRUE(item);
    auto measured = tlv::measure(format.view(), *item);
    ASSERT_TRUE(measured);
    EXPECT_EQ(sizeof(wire), measured->total);
    auto unavailable =
        tlv::measure(format.view(), tlv::measure_request{item->tag(), 1, tlv::bytes(nullptr, 0)});
    ASSERT_FALSE(unavailable);
    EXPECT_EQ(TLV_ERR_NULL_ARG, unavailable.error().code);
    tlv::byte                   out[4]{};
    tlv::writer<content_format> writer(out, sizeof(out));
    ASSERT_TRUE(writer.write(*item));
    EXPECT_EQ(0, std::memcmp(wire, out, sizeof(wire)));
}

namespace {
template <typename F>
void builtin_round_trip(const unsigned char* wire, size_t size, tlv::tag tag) {
    tlv::reader<F> reader(bytes(wire, size));
    auto           item = reader.next();
    ASSERT_TRUE(item);
    EXPECT_EQ(tag, item->tag());
    ASSERT_EQ(1u, item->value().size());
    EXPECT_EQ(static_cast<tlv::byte>(0x7A), item->value()[0]);
    tlv::byte      out[8]{};
    tlv::writer<F> writer(out, sizeof(out));
    ASSERT_TRUE(writer.write(*item));
    EXPECT_EQ(size, writer.size());
    EXPECT_EQ(0, std::memcmp(wire, out, size));
}
} // namespace
TEST(Unit_Tlvpp_CustomFormat, ConfiguredBuiltinsUseIdenticalGenericContract) {
    const unsigned char simple[] = {1, 1, 0x7A};
    builtin_round_trip<tlv::fixed_format<1, 1, TLV_BYTE_ORDER_BIG_ENDIAN>>(simple, sizeof(simple),
                                                                           tlv::tag_bytes<1>());
#if OPENTLV_FORMAT_BER || OPENTLV_FORMAT_DER || OPENTLV_FORMAT_CER
    const unsigned char asn1[] = {4, 1, 0x7A};
#endif
#if OPENTLV_FORMAT_BER
    builtin_round_trip<tlv::ber::format>(asn1, sizeof(asn1), tlv::tag_bytes<4>());
#endif
#if OPENTLV_FORMAT_DER
    builtin_round_trip<tlv::der::format>(asn1, sizeof(asn1), tlv::tag_bytes<4>());
#endif
#if OPENTLV_FORMAT_CER
    builtin_round_trip<tlv::cer::format>(asn1, sizeof(asn1), tlv::tag_bytes<4>());
#endif
#if OPENTLV_EMV
    const unsigned char emv[] = {0x5A, 1, 0x7A};
    builtin_round_trip<tlv::emv::format>(emv, sizeof(emv), tlv::tag_bytes<0x5A>());
#endif
#if OPENTLV_BLUETOOTH
    const unsigned char bluetooth[] = {2, 9, 0x7A};
    builtin_round_trip<tlv::bluetooth::format>(bluetooth, sizeof(bluetooth), tlv::tag_bytes<9>());
#endif
#if OPENTLV_LLDP
    const unsigned char lldp[] = {2, 1, 0x7A};
    builtin_round_trip<tlv::lldp::format>(lldp, sizeof(lldp), tlv::tag_bytes<1>());
#endif
#if OPENTLV_DHCP
    builtin_round_trip<tlv::dhcp::format>(simple, sizeof(simple), tlv::tag_bytes<1>());
#endif
#if OPENTLV_NFC
    builtin_round_trip<tlv::nfc::format>(simple, sizeof(simple), tlv::tag_bytes<1>());
#endif
}

TEST(Unit_Tlvpp_CustomFormat, NativeViewAdapterPreservesRuntimeCapabilitiesAndCustomization) {
    tlv::format_adapter<read_only>   original;
    tlv::format_adapter<tlv::format> native(original.view());
    EXPECT_TRUE(native.view().readable());
    EXPECT_FALSE(native.view().writable());
    EXPECT_FALSE(native.view().has_constructed_classifier());
    const unsigned char          wire[] = {1, 1, 0x7A, 0xA5};
    tlv::reader<customized_view> reader(bytes(wire, sizeof(wire)));
    ASSERT_TRUE(reader.next());
    EXPECT_EQ(sizeof(wire), reader.consumed());
}
