#ifndef OPENTLV_TLVPP_TYPED_HPP
#define OPENTLV_TLVPP_TYPED_HPP

#include <type_traits>
#include <vector>
#include "tlv++/types.hpp"
#include "tlv++/codec/typed_error.hpp"
#include "tlv++/writer/writer.hpp"
#include "tlv/codec/values.h"

/** @file
 * @brief C++11 typed fields and tag-independent Value codec customization.
 *
 * A codec exposes value_type, decode(bytes) returning expected<value_type,
 * tlv_codec_result_t>, and encode(const value_type&, byte*, size_t) returning
 * expected<size_t, tlv_codec_result_t>. Encode with nullptr and zero capacity
 * validates and measures the value. Implementations must respect capacity and
 * report the exact byte count. Input and output must not overlap. Schema owns
 * contextual length, occurrence and nesting constraints.
 */
namespace tlv {
/** @brief Program-lifetime byte identifier usable as a C++11 template argument.
 * @tparam TagBytes Canonical identifier bytes in order, without integer normalization.
 */
template <uint8_t... TagBytes> struct tag_constant {
    /** @brief Borrow the static identifier bytes. */
    static tlv::tag tag() noexcept {
        return tag_bytes<TagBytes...>();
    }
};
/** @brief Absent identifier provider for Formats supporting tagless elements. */
template <> struct tag_constant<> {
    /** @brief Return an absent identifier without allocating. */
    static tlv::tag tag() noexcept {
        return {};
    }
};

/** @brief Adapt a C Value descriptor with its exact C representation.
 * @tparam T Exact representation expected by Descriptor; default constructible.
 * @tparam Descriptor Program-lifetime C codec, never selected by enclosing tag.
 * @warning A descriptor returning borrowed data retains the input lifetime.
 */
template <typename T, const tlv_codec_t* Descriptor> struct codec_adapter {
    /** Value representation. */
    using value_type = T;
    /** @brief Decode Value bytes through the C codec.
     * @param input Borrowed input, retained if T is a borrowed representation.
     * @return Decoded value or original codec code.
     */
    static expected<T, tlv_codec_result_t> decode(bytes input) {
        T          value{};
        const auto rc = tlv_codec_decode(Descriptor, reinterpret_cast<const uint8_t*>(input.data()),
                                         input.size(), &value, sizeof(T));
        if (rc != TLV_CODEC_OK) return unexpected<tlv_codec_result_t>(rc);
        return value;
    }
    /** @brief Encode or measure through the C codec.
     * @param value Exact descriptor representation.
     * @param output Caller storage, or nullptr with zero capacity for measurement.
     * @param capacity Available bytes; output must be disjoint from value storage.
     * @return Written or required byte count, or original codec code.
     */
    static expected<size_t, tlv_codec_result_t> encode(const T& value, byte* output,
                                                       size_t capacity) {
        size_t     written = 0;
        const auto rc = tlv_codec_encode(Descriptor, &value, sizeof(T),
                                         reinterpret_cast<uint8_t*>(output), capacity, &written);
        if (rc != TLV_CODEC_OK) return unexpected<tlv_codec_result_t>(rc);
        return written;
    }
};
/** @brief One-byte unsigned integer codec. */
using uint8_codec = codec_adapter<uint8_t, &tlv_codec_uint8>;
/** @brief Two-byte big-endian unsigned integer codec. */
using uint16_be_codec = codec_adapter<uint16_t, &tlv_codec_uint16_be>;
/** @brief Two-byte little-endian unsigned integer codec. */
using uint16_le_codec = codec_adapter<uint16_t, &tlv_codec_uint16_le>;
/** @brief Four-byte big-endian unsigned integer codec. */
using uint32_be_codec = codec_adapter<uint32_t, &tlv_codec_uint32_be>;
/** @brief Four-byte little-endian unsigned integer codec. */
using uint32_le_codec = codec_adapter<uint32_t, &tlv_codec_uint32_le>;
/** @brief Minimal big-endian two's-complement signed integer codec. */
using int64_minimal_be_codec = codec_adapter<int64_t, &tlv_codec_int64_minimal_be>;

/** @brief Default Value codec customization point, independent of tags.
 * @tparam T Semantic C++ type; specialize for application types or select an explicit codec.
 *
 * No default integer endianness is inferred for multibyte integers. Specializations
 * must implement the contract documented in this header. Allocation exceptions
 * from owning codecs propagate, consistently with other owning C++ operations.
 */
template <typename T> struct codec {
    static_assert(!std::is_same<T, T>::value,
                  "No tlv::codec<T>: specialize it or supply an explicit field codec");
};
/** @brief Default codec for a single unsigned byte. */
template <> struct codec<uint8_t> : uint8_codec {};

/** @brief Default borrowed Value codec; decoded bytes retain input lifetime. */
template <> struct codec<value_view> {
    /** Borrowed semantic value type. */
    using value_type = value_view;
    /** @brief Decode arbitrary bytes without allocation or text validation.
     * @param input Borrowed input, live and immutable while the result is used.
     * @return Borrowed view or original C codec error.
     */
    static expected<value_view, tlv_codec_result_t> decode(bytes input) {
        auto raw = codec_adapter<tlv_value_t, &tlv_codec_bytes>::decode(input);
        if (!raw) return unexpected<tlv_codec_result_t>(raw.error());
        return detail::semantic_access::borrow(*raw);
    }
    /** @brief Copy or measure arbitrary Value bytes through the C codec.
     * @param value Borrowed readable Value.
     * @param output Disjoint output, or nullptr with zero capacity for measurement.
     * @param capacity Available bytes.
     * @return Written or required bytes, or original C codec error.
     */
    static expected<size_t, tlv_codec_result_t> encode(const value_view& value, byte* output,
                                                       size_t capacity) {
        return codec_adapter<tlv_value_t, &tlv_codec_bytes>::encode(
            detail::semantic_access::get(value), output, capacity);
    }
};

/** @brief Byte-preserving owning string codec, including embedded NUL; no UTF-8 policy. */
template <> struct codec<std::string> {
    /** Owning byte string representation. */
    using value_type = std::string;
    /** @brief Copy arbitrary Value bytes into an owning string; may allocate.
     * @param input Borrowed bytes, not retained.
     * @return Owned string or original codec error.
     */
    static expected<std::string, tlv_codec_result_t> decode(bytes input) {
        auto value = codec<value_view>::decode(input);
        if (!value) return unexpected<tlv_codec_result_t>(value.error());
        if (input.empty()) return std::string{};
        return std::string(reinterpret_cast<const char*>(input.data()), input.size());
    }
    /** @brief Copy or measure the string's exact bytes, without a trailing NUL.
     * @param value String to encode.
     * @param output Disjoint storage, or nullptr with zero capacity for measurement.
     * @param capacity Available bytes.
     * @return Written or required bytes, or original codec error.
     */
    static expected<size_t, tlv_codec_result_t> encode(const std::string& value, byte* output,
                                                       size_t capacity) {
        return codec<value_view>::encode(
            value_view(bytes(reinterpret_cast<const byte*>(value.data()), value.size())), output,
            capacity);
    }
};

/// @cond INTERNAL
namespace detail {
template <typename Tag, typename T, typename Codec> struct field_contract {
    template <typename G, typename C>
    static auto test(int) -> std::integral_constant<
        bool, std::is_same<decltype(G::tag()), tlv::tag>::value &&
                  std::is_same<T, typename C::value_type>::value &&
                  std::is_same<decltype(C::decode(std::declval<bytes>())),
                               expected<T, tlv_codec_result_t>>::value &&
                  std::is_same<decltype(C::encode(std::declval<const T&>(),
                                                  static_cast<byte*>(nullptr), size_t{})),
                               expected<size_t, tlv_codec_result_t>>::value>;
    template <typename, typename> static std::false_type test(...);
    static const bool value = decltype(test<Tag, Codec>(0))::value;
};
} // namespace detail
/// @endcond

/** @brief Associate a byte identifier, semantic type and Value codec at compile time.
 * @tparam Tag Identifier provider exposing static tag(), such as tag_constant.
 * @tparam T Semantic value type.
 * @tparam Codec Tag-independent codec implementing this header's contract.
 * @note This is a C++ composition, not a Definition registry or Schema replacement.
 */
template <typename Tag, typename T, typename Codec = codec<T>> struct field {
    static_assert(
        detail::field_contract<Tag, T, Codec>::value,
        "tlv::field requires Tag::tag() returning tlv::tag, Codec::value_type matching T, "
        "decode(bytes) returning expected<T, tlv_codec_result_t>, and "
        "encode(const T&, byte*, size_t) returning expected<size_t, tlv_codec_result_t>");
    /** Semantic decoded type. */
    using value_type = T;
    /** Selected Value codec. */
    using codec_type = Codec;
    /** @brief Borrow the field identifier; provider storage must have static lifetime. */
    static tlv::tag tag() {
        return Tag::tag();
    }
};

/// @cond INTERNAL
namespace detail {
template <typename Field>
expected<void, typed_error> writer_base::write(const typename Field::value_type& value) {
    auto size = Field::codec_type::encode(value, nullptr, 0);
    if (!size) return unexpected<typed_error>(typed_error(size.error()));
    std::vector<byte> scratch(*size);
    return write<Field>(value, span<byte>(scratch.data(), scratch.size()));
}
template <typename Field>
expected<void, typed_error> writer_base::write(const typename Field::value_type& value,
                                               span<byte>                        scratch) {
    auto size = Field::codec_type::encode(value, nullptr, 0);
    if (!size) return unexpected<typed_error>(typed_error(size.error()));
    if (*size > scratch.size())
        return unexpected<typed_error>(typed_error(TLV_CODEC_ERR_BUFFER_TOO_SHORT));
    auto written = Field::codec_type::encode(value, scratch.data(), scratch.size());
    if (!written) return unexpected<typed_error>(typed_error(written.error()));
    if (*written != *size || *written > scratch.size())
        return unexpected<typed_error>(typed_error(TLV_CODEC_ERR_INVALID_VALUE));
    auto result = write(Field::tag(), bytes(scratch.data(), *written));
    if (!result) return unexpected<typed_error>(typed_error(result.error().code));
    return {};
}
} // namespace detail
/// @endcond

/// @cond INTERNAL
namespace detail {
template <typename Field>
expected<typename Field::value_type, typed_error> decode_field(const element_view& value) {
    if (value.tag() != Field::tag())
        return unexpected<typed_error>(typed_error(typed_errc::tag_mismatch));
    auto result = Field::codec_type::decode(value.value().as_bytes());
    if (!result) return unexpected<typed_error>(typed_error(result.error()));
    return std::move(*result);
}
} // namespace detail
/// @endcond
} // namespace tlv
#endif
