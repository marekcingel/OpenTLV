// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_TLVPP_DETAIL_FORMAT_ACCESS_HPP
#define OPENTLV_TLVPP_DETAIL_FORMAT_ACCESS_HPP

#include "tlv/format.h"

/** @file
 * @brief Internal access to the canonical Format descriptor.
 */
namespace tlv {
class format;

/// @cond INTERNAL
namespace detail {
struct format_access {
    static tlv::format         borrow(const tlv_format_t& descriptor) noexcept;
    static tlv::format         borrow(tlv_format_t&&) = delete;
    static tlv::format         borrow(const tlv_format_t&&) = delete;
    static const tlv_format_t& get(tlv::format view) noexcept;
};
} // namespace detail
/// @endcond
} // namespace tlv
#endif
