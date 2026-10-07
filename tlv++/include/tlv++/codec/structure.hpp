// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_TLVPP_STRUCTURE_HPP
#define OPENTLV_TLVPP_STRUCTURE_HPP
#include "tlv++/codec/dynamic.hpp"
#include "tlv++/types.hpp"
#include "tlv/codec/structure.h"

/**
 * @file structure.hpp
 * @brief C++ wrappers for structure codecs.
 */

namespace tlv {
/**
 * @brief Validates and decodes a complete sequence into an application object.
 *
 * Wraps tlv_structure_decode().
 *
 * @tparam T The exact representation documented by the descriptor; must be
 *           default constructible.
 *
 * @param codec Structure codec descriptor.
 * @param data  Encoded sequence; borrowed.
 *
 * @return The decoded object, or the #codec_errc reported by the
 *         codec.
 *
 * @warning The codec may borrow `data` in the returned object; the caller
 *          must keep `data` alive as long as the object is used.
 */
template <typename T>
TLV_NODISCARD expected<T, codec_errc> decode_structure(const tlv_structure_codec_t& codec,
                                                       bytes                        data) {
    T          value{};
    const auto rc = tlv_structure_decode(&codec, reinterpret_cast<const uint8_t*>(data.data()),
                                         data.size(), &value, sizeof(T));
    if (rc != TLV_CODEC_OK) return unexpected<codec_errc>(static_cast<codec_errc>(rc));
    return value;
}

/**
 * @brief Encodes an application object into a complete, validated sequence.
 *
 * Wraps tlv_structure_encode(). Output goes to caller-owned storage.
 *
 * @tparam T The exact representation documented by the descriptor.
 *
 * @param codec    Structure codec descriptor.
 * @param value    Object to encode.
 * @param data     Destination bytes; `nullptr` with zero `capacity`
 *                 performs the descriptor's size query.
 * @param capacity Destination capacity in bytes.
 *
 * @return The number of bytes written (or required, for a size query), or
 *         the #codec_errc reported by the codec.
 *
 * @warning On error the contents of `data` are unspecified.
 */
template <typename T>
TLV_NODISCARD expected<size_t, codec_errc>
encode_structure(const tlv_structure_codec_t& codec, const T& value, byte* data, size_t capacity) {
    size_t     written = 0;
    const auto rc = tlv_structure_encode(&codec, &value, sizeof(T),
                                         reinterpret_cast<uint8_t*>(data), capacity, &written);
    if (rc != TLV_CODEC_OK) return unexpected<codec_errc>(static_cast<codec_errc>(rc));
    return written;
}
} // namespace tlv
#endif
