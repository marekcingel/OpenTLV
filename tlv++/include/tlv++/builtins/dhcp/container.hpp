// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_TLVPP_BUILTINS_DHCP_CONTAINER_HPP
#define OPENTLV_TLVPP_BUILTINS_DHCP_CONTAINER_HPP

#include "tlv/builtins/dhcp/container.h"
#include "tlv++/types.hpp"

/** @file
 * @brief C++ access to shared DHCPv4 options container validation.
 */
namespace tlv {
namespace native {
/**
 * @brief Validates a borrowed DHCPv4 options region using the C contract.
 * @param[in] data Input bytes; nullptr only for size zero.
 * @param[in] size Input size in bytes, without header or magic cookie.
 * @param[in] rules Rules; nullptr requires End and a zero-only tail.
 * @param[in] max_elements Element limit, including Pad and End; zero permits none.
 * @param[out] significant_size Prefix size through End, unchanged on failure.
 * @param[out] diagnostic Optional diagnostic, reset on every call.
 * @return The result of tlv_dhcpv4_options_validate(), propagated unchanged.
 * @note Never allocates or retains input. Output storage must not overlap input,
 *       rules or other outputs. Requires `OPENTLV_DHCP=ON`.
 * @see tlv_dhcpv4_options_validate
 */
inline tlv_result_t dhcpv4_options_validate(const uint8_t* data, size_t size,
                                            const tlv_dhcpv4_options_rules_t* rules,
                                            size_t max_elements, size_t& significant_size,
                                            tlv_diagnostic_t* diagnostic = nullptr) noexcept {
    return tlv_dhcpv4_options_validate(data, size, rules, max_elements, &significant_size,
                                       diagnostic);
}

} // namespace native

/** @brief DHCP container policy, separate from element framing. */
namespace dhcp {
/** @brief Policy for bytes after the first End option. */
enum class tail_policy {
    padding = TLV_DHCPV4_OPTIONS_TAIL_PAD,  /**< Require zero padding. */
    empty = TLV_DHCPV4_OPTIONS_TAIL_EMPTY,  /**< Require End to be the last byte. */
    ignore = TLV_DHCPV4_OPTIONS_TAIL_IGNORE /**< Ignore the remaining bytes. */
};
/** @brief Value configuration for DHCP options container validation. */
struct options_rules {
    bool        require_end; /**< Require an End option. */
    tail_policy tail;        /**< Tail policy after End. */
    /** @brief Default to mandatory End and zero-only padding. */
    options_rules(bool require_end = true, tail_policy tail = tail_policy::padding) noexcept
        : require_end(require_end), tail(tail) {}
};
/**
 * @brief Validate a DHCPv4 options region through the canonical container validator.
 * @param data Borrowed options bytes, without packet header or magic cookie.
 * @param rules Container policy; defaults to required End and zero-only padding.
 * @param max_elements Element limit including Pad and End; zero permits none.
 * @param diagnostic Optional diagnostic, reset on every call.
 * @return Significant prefix size through End, or the original C error.
 * @note Validation and error reporting allocate nothing and retain no input.
 * Output storage must not overlap input.
 * @see tlv_dhcpv4_options_validate
 */
TLV_NODISCARD inline expected<size_t, error>
options_validate(bytes data, options_rules rules = {}, size_t max_elements = SIZE_MAX,
                 tlv_diagnostic_t* diagnostic = nullptr) {
    const tlv_dhcpv4_options_rules_t raw{rules.require_end ? 1 : 0,
                                         static_cast<tlv_dhcpv4_options_tail_t>(rules.tail)};
    tlv_diagnostic_t                 local{};
    if (!diagnostic) diagnostic = &local;
    size_t     significant_size = 0;
    const auto rc =
        tlv_dhcpv4_options_validate(reinterpret_cast<const uint8_t*>(data.data()), data.size(),
                                    &raw, max_elements, &significant_size, diagnostic);
    if (rc != TLV_OK)
        return unexpected<error>(detail::error_access::diagnostic(*diagnostic, operation::reader));
    return significant_size;
}
} // namespace dhcp
} // namespace tlv
#endif
