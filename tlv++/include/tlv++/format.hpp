#ifndef OPENTLV_TLVPP_FORMAT_HPP
#define OPENTLV_TLVPP_FORMAT_HPP

#include "tlv/attributes.h"
#include "tlv/format.h"
#include "tlv++/types.hpp"

namespace tlv {

/**
 * @file
 * @brief Canonical format operations and immutable borrowed source information.
 */

/**
 * @brief Semantic element together with its borrowed original framing.
 */
using decoded = tlv_decoded_t;

/**
 * @brief Immutable borrowed original wire representation.
 */
using source = tlv_source_t;

/**
 * @brief Exact logical framing sizes independent of the native address space.
 */
using encoding = tlv_encoding_t;

/**
 * @brief Decode one element and retain its original wire ranges without allocation.
 *
 * @param[in] format Readable descriptor, borrowed.
 * @param[in] data   Immutable borrowed input.
 *
 * @return Decoded content and source, or the C format error.
 *
 * @warning Input, descriptor and context must outlive the result and remain unchanged.
 */
TLV_NODISCARD inline expected<decoded, error> decode(const tlv_format_t& format, bytes data) {
    decoded result{};
    auto rc = tlv_format_decode(&format, reinterpret_cast<const uint8_t*>(data.data()), data.size(),
                                &result, nullptr);
    if (rc != TLV_OK) return unexpected<error>(error::from_c(rc));
    return result;
}

/**
 * @brief Measure logical framing without a destination buffer.
 *
 * @param[in] format Writable descriptor.
 * @param[in] value  Semantic input; content-dependent formats require readable Value.
 *
 * @return Exact logical sizes, or a C format error.
 */
TLV_NODISCARD inline expected<encoding, error> measure(const tlv_format_t& format,
                                                       const element&      value) {
    encoding result{};
    auto     rc = tlv_format_measure(&format, &value, &result, nullptr);
    if (rc != TLV_OK) return unexpected<error>(error::from_c(rc));
    return result;
}

/**
 * @brief Encode current semantic content, regenerating framing.
 *
 * @param[in]  format   Writable descriptor.
 * @param[in]  value    Readable input, not overlapping destination.
 * @param[out] data     Destination pointer, NULL only for zero capacity.
 * @param[in]  capacity Native capacity in bytes.
 *
 * @return Written bytes, or a C format error. Callback failure may modify output.
 */
TLV_NODISCARD inline expected<size_t, error>
encode(const tlv_format_t& format, const element& value, byte* data, size_t capacity) {
    size_t written = 0;
    auto   rc = tlv_format_encode(&format, &value, reinterpret_cast<uint8_t*>(data), capacity,
                                  &written, nullptr);
    if (rc != TLV_OK) return unexpected<error>(error::from_c(rc));
    return written;
}

/**
 * @brief Reproduce original bytes after checking semantic equality.
 *
 * @param[in]  original Immutable borrowed source from decode().
 * @param[in]  value    Current semantic content.
 * @param[out] data     Destination, or NULL with zero capacity for a size query.
 * @param[in]  capacity Native writable bytes.
 *
 * @return Written/required bytes on success, or a C error; mutation is rejected.
 *
 * @warning Original bytes, descriptor and context must remain valid and unchanged.
 */
TLV_NODISCARD inline expected<size_t, error> preserve(const source& original, const element& value,
                                                      byte* data, size_t capacity) {
    size_t written = 0;
    auto   rc = tlv_source_preserve(&original, &value, reinterpret_cast<uint8_t*>(data), capacity,
                                    &written);
    if (rc != TLV_OK) return unexpected<error>(error::from_c(rc));
    return written;
}

} // namespace tlv
#endif
