#ifndef OPENTLV_TLVPP_TYPES_HPP
#define OPENTLV_TLVPP_TYPES_HPP

#include <string>
#include "tlv++/compat.hpp"
#include "tlv/element.h"

/**
 * @file types.hpp
 * @brief Core C++ types shared by the tlv++ wrappers.
 */

namespace tlv {

/**
 * @brief Idiomatic C++ error that wraps a C result code and its description.
 *
 * Returned in the error state of an `expected` by the tlv++ wrappers.
 *
 * @see tlv_result_t
 */
struct error {
    /** The C result code. */
    tlv_result_t code;
    /** Human-readable description of `code`, owned by this object. */
    std::string message;

    /**
     * @brief Builds an error from a C result code.
     *
     * @param c_code C result code.
     *
     * @return An error whose message is tlv_strerror(`c_code`).
     */
    static error from_c(tlv_result_t c_code) {
        return error{c_code, tlv_strerror(c_code)};
    }
};

/**
 * @brief C++ alias for the C tag type, #tlv_tag_t.
 */
using tag_t = tlv_tag_t;

/**
 * @brief Non-owning, read-only view of bytes.
 *
 * The caller owns the storage and must keep it alive while the view is used.
 */
using bytes = span<const byte>;

/**
 * @brief Alias for the canonical C element, with borrowed tag, length and value fields.
 * @warning Keep the source buffer alive while the element is used.
 */
using element = tlv_element_t;

/**
 * @brief Converts a logical TLV value to a native byte span without copying.
 *
 * @param value Borrowed value; its storage must outlive the returned span.
 * @return A byte span, or #TLV_ERR_NULL_ARG for a null pointer with nonzero size,
 *         or #TLV_ERR_NATIVE_SIZE if the size exceeds `SIZE_MAX`.
 * @note Checks the representation and native size, not the actual storage extent.
 */
TLV_NODISCARD inline expected<bytes, error> as_bytes(tlv_value_t value) {
    const tlv_result_t rc = tlv_value_validate(&value);
    if (rc != TLV_OK) return unexpected<error>(error::from_c(rc));
    return bytes(reinterpret_cast<const byte*>(value.data), static_cast<size_t>(value.size));
}

} // namespace tlv
#endif
