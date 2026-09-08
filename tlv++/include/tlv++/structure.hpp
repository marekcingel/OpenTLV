#ifndef OPENTLV_TLVPP_STRUCTURE_HPP
#define OPENTLV_TLVPP_STRUCTURE_HPP
#include "tlv++/types.hpp"
#include "tlv/codec/structure.h"

namespace tlv {
// T must be the exact representation documented by the descriptor, with a
// default constructor. The codec may borrow input; the caller owns its lifetime.
template <typename T>
TLV_NODISCARD expected<T, tlv_codec_result_t>
decode_structure(const tlv_structure_codec_t& codec, bytes data) {
    T value{};
    tlv_codec_result_t rc = tlv_structure_decode(&codec,
        reinterpret_cast<const uint8_t*>(data.data()), data.size(), &value, sizeof(T));
    if (rc != TLV_CODEC_OK) return unexpected<tlv_codec_result_t>(rc);
    return value;
}

// Caller-owned output. nullptr/0 performs the descriptor's size query.
template <typename T>
TLV_NODISCARD expected<size_t, tlv_codec_result_t>
encode_structure(const tlv_structure_codec_t& codec, const T& value,
                 byte* data, size_t capacity) {
    size_t written = 0;
    tlv_codec_result_t rc = tlv_structure_encode(&codec, &value, sizeof(T),
        reinterpret_cast<uint8_t*>(data), capacity, &written);
    if (rc != TLV_CODEC_OK) return unexpected<tlv_codec_result_t>(rc);
    return written;
}
}
#endif
