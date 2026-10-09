// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_TLVPP_DETAIL_BUILTIN_CODEC_HPP
#define OPENTLV_TLVPP_DETAIL_BUILTIN_CODEC_HPP

/** @file
 * @brief Internal adapters for standard-specific C Value representations.
 *
 * Codecs interpret Value only, delegate validation to the canonical C engine,
 * and implement the generic typed-field contract. Successful operations allocate
 * nothing. Borrowed results require immutable input to outlive every retained copy.
 * Encode storage must be disjoint from all borrowed input; nullptr/0 validates
 * and measures. Codec errors are propagated unchanged.
 */
#include "tlv++/codec/dynamic.hpp"
#include "tlv++/codec/typed.hpp"

/// @cond INTERNAL
namespace tlv {
namespace detail {
template <typename T, typename Native, const tlv_codec_t* Descriptor, typename Conversion>
struct builtin_codec {
    using value_type = T;
    static expected<T, codec_failure> decode(bytes input) {
        auto result = codec_adapter<Native, Descriptor>::decode(input);
        if (!result) return unexpected<codec_failure>(result.error());
        return Conversion::from_native(*result);
    }
    static expected<size_t, codec_failure> encode(const T& value, byte* output, size_t capacity) {
        Native native = Conversion::to_native(value);
        return codec_adapter<Native, Descriptor>::encode(native, output, capacity);
    }
};
struct borrowed_value_conversion {
    static value_view from_native(tlv_value_t value) {
        return semantic_access::borrow(value);
    }
    static tlv_value_t to_native(value_view value) {
        return semantic_access::get(value);
    }
};
template <typename Native, const tlv_codec_t* Descriptor, size_t Width = 1>
struct builtin_string_codec {
    using value_type = value_view;
    static expected<value_view, codec_failure> decode(bytes input) {
        auto result = codec_adapter<Native, Descriptor>::decode(input);
        if (!result) return unexpected<codec_failure>(result.error());
        return value_view(
            bytes(reinterpret_cast<const byte*>(result->data), result->length * Width));
    }
    static expected<size_t, codec_failure> encode(value_view value, byte* output, size_t capacity) {
        if (value.size() % Width) return unexpected<codec_failure>(errc::invalid_value);
        Native native{reinterpret_cast<const uint8_t*>(value.data()), value.size() / Width};
        return codec_adapter<Native, Descriptor>::encode(native, output, capacity);
    }
};
} // namespace detail
} // namespace tlv
/// @endcond
#endif
