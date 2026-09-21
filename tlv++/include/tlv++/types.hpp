#ifndef OPENTLV_TLVPP_TYPES_HPP
#define OPENTLV_TLVPP_TYPES_HPP
#include <string>
#include "tlv++/compat.hpp"
#include "tlv/view.h"
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

/** @brief C++ alias for the C tag type, #tlv_tag_t. */
using tag_t = tlv_tag_t;

/**
 * @brief Non-owning, read-only view of bytes.
 *
 * The caller owns the storage and must keep it alive while the view is used.
 */
using bytes = span<const byte>;

/**
 * @brief A decoded TLV item on the C++ side.
 *
 * The tag and the value point into the original buffer (zero-copy) and are not owned.
 *
 * @warning The caller must keep the original buffer alive while the entry is used.
 */
struct entry {
    /** Item tag; borrows the original buffer. */
    tag_t tag;
    /** Item value; borrows the original buffer. */
    bytes value;
};

} // namespace tlv
#endif
