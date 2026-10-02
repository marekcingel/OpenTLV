// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

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

/**
 * @brief Validate and borrow native identifier bytes without copying.
 * @param raw Native descriptor; underlying immutable bytes must outlive all views.
 * @return Tag, or TLV_ERR_NULL_ARG for null storage with nonzero size.
 * @note The caller remains responsible for the actual storage extent.
 */
TLV_NODISCARD inline expected<tlv::tag, error> borrow_tag(tlv_tag_t raw) {
    if (!raw.data && raw.size) return unexpected<error>(error::from_c(TLV_ERR_NULL_ARG));
    return detail::semantic_access::borrow(raw);
}

/**
 * @brief Validate and borrow a native Value without copying.
 * @param raw Native descriptor; immutable storage must outlive every view.
 * @return Value view, TLV_ERR_NULL_ARG for invalid storage, or TLV_ERR_NATIVE_SIZE
 * if the logical length cannot be addressed by size_t.
 * @note Validation cannot prove the storage extent.
 */
TLV_NODISCARD inline expected<value_view, error> borrow_value(tlv_value_t raw) {
    const auto rc = tlv_value_validate(&raw);
    if (rc != TLV_OK) return unexpected<error>(error::from_c(rc));
    return detail::semantic_access::borrow(raw);
}

/**
 * @brief Validate and borrow a native semantic Element without copying bytes.
 * @param raw Descriptor whose immutable Tag and Value storage outlives every view.
 * @return Element view or the original Tag/Value representation error.
 */
TLV_NODISCARD inline expected<element_view, error> borrow_element(tlv_element_t raw) {
    auto identifier = borrow_tag(raw.tag);
    if (!identifier) return unexpected<error>(identifier.error());
    auto value = borrow_value(raw.value);
    if (!value) return unexpected<error>(value.error());
    return element_view(*identifier, *value);
}

/** @brief Export a shallow C Tag descriptor; storage retains its borrowed lifetime. */
inline tlv_tag_t descriptor(tlv::tag view) noexcept {
    return detail::semantic_access::get(view);
}
/** @brief Export a shallow C Value descriptor; storage retains its borrowed lifetime. */
inline tlv_value_t descriptor(value_view view) noexcept {
    return detail::semantic_access::get(view);
}
/** @brief Export a shallow C Element descriptor; neither descriptor nor bytes are retained. */
inline tlv_element_t descriptor(element_view view) noexcept {
    return detail::semantic_access::get(view);
}

} // namespace native
} // namespace tlv
#endif
