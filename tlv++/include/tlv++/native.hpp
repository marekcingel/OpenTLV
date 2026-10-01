#ifndef OPENTLV_TLVPP_NATIVE_HPP
#define OPENTLV_TLVPP_NATIVE_HPP

#include "tlv++/format.hpp"

/** @file
 * @brief Explicit interoperability with the canonical C engine.
 * @note Include this header explicitly when mixing the C and C++ APIs.
 */
namespace tlv {
/** @brief Explicit C interoperability; ordinary C++ code uses public C++ types. */
namespace native {

/**
 * @brief Borrow an existing immutable C Format without copying or allocation.
 * @param descriptor Caller-owned descriptor; invalid callbacks are reported by operations.
 * @return A C++ view of exactly this descriptor, including its original context.
 * @warning Descriptor and context must remain alive and unchanged for every
 * dependent Reader, Writer and retained source view. Temporary descriptors are rejected.
 */
inline tlv::format borrow_format(const tlv_format_t& descriptor) noexcept {
    return detail::format_access::borrow(descriptor);
}

/** @brief Reject borrowing a temporary descriptor whose lifetime would end immediately. */
tlv::format borrow_format(tlv_format_t&&) = delete;
/** @brief Reject borrowing a const temporary descriptor. */
tlv::format borrow_format(const tlv_format_t&&) = delete;

/**
 * @brief Access the borrowed native descriptor for an explicit C API operation.
 * @param view C++ Format view; copying or destroying it does not change the descriptor.
 * @return Immutable descriptor reference; no copy or allocation occurs.
 * @warning The descriptor and context retain their original borrowed lifetime.
 */
inline const tlv_format_t& descriptor(tlv::format view) noexcept {
    return detail::format_access::get(view);
}

} // namespace native
} // namespace tlv
#endif
