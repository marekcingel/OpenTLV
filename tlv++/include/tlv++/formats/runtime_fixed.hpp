// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_TLVPP_FORMATS_RUNTIME_FIXED_HPP
#define OPENTLV_TLVPP_FORMATS_RUNTIME_FIXED_HPP

#include "tlv++/format.hpp"
#include "tlv++/formats/options.hpp"
#include "tlv/formats/fixed.h"

/** @file
 * @brief Allocation-free owned runtime configuration for fixed-width Formats.
 */
namespace tlv {
/**
 * @brief Immutable runtime Format owner with explicit borrowed views.
 *
 * Construction and copying allocate nothing. A copy owns independent configuration.
 * Readers, Writers and retained source information borrow the particular owner from
 * which view() was obtained. Keep that owner alive and unmoved until all borrows end.
 * Assignment is disabled so existing views cannot silently change configuration.
 */
class runtime_fixed_format {
public:
    /**
     * @brief Configure fixed identifier/length fields using the canonical engine.
     * @param tag_width Identifier width in bytes, at least one.
     * @param length_width Length width in bytes, between one and eight.
     * @param order Numeric length byte order; does not transform identifier bytes.
     * @param fields Wire field order.
     * @param scope Quantity counted by the length.
     * @note Invalid configurations are reported by view(); construction never throws.
     */
    runtime_fixed_format(size_t tag_width, size_t length_width,
                         byte_order    order = byte_order::big_endian,
                         element_order fields = element_order::tlv,
                         length_scope  scope = length_scope::value) noexcept
        : config_{{tag_width},
                  {length_width, static_cast<tlv_byte_order_t>(order)},
                  static_cast<tlv_element_order_t>(fields),
                  static_cast<tlv_length_scope_t>(scope)},
          status_(tlv_fixed_format_init(&descriptor_, &config_)) {}

    /** @brief Copy configuration and rebind its descriptor to this independent owner. */
    runtime_fixed_format(const runtime_fixed_format& other) noexcept
        : config_(other.config_), status_(tlv_fixed_format_init(&descriptor_, &config_)) {}
    /** @brief Configuration cannot change while views may be borrowed. */
    runtime_fixed_format& operator=(const runtime_fixed_format&) = delete;

    /**
     * @brief Borrow this owner's readable/writable Format without allocation.
     * @return Format view, or invalid-argument/byte-order error for invalid configuration.
     * @warning This owner must outlive every use of the view and retained source.
     */
    expected<tlv::format, error> view() const& {
        if (status_ != TLV_OK) return unexpected<error>(error::from_c(status_));
        return detail::format_access::borrow(descriptor_);
    }
    /** @brief Prevent borrowing a temporary owner. */
    expected<tlv::format, error> view() const&& = delete;

private:
    tlv_fixed_format_t config_;
    tlv_format_t       descriptor_{};
    tlv_result_t       status_;
};
} // namespace tlv
#endif
