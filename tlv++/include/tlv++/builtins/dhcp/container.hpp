#ifndef OPENTLV_TLVPP_BUILTINS_DHCP_CONTAINER_HPP
#define OPENTLV_TLVPP_BUILTINS_DHCP_CONTAINER_HPP

#include "tlv/builtins/dhcp/container.h"
#include "tlv++/types.hpp"

/** @file
 * @brief C++ access to shared DHCPv4 options container validation.
 */
namespace tlv {
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

/** @brief DHCP container policy, separate from element framing. */
namespace dhcp {
/**
 * @brief Validate a DHCPv4 options region through the canonical container validator.
 * @param data Borrowed options bytes, without packet header or magic cookie.
 * @param rules Optional rules; nullptr requires End and a zero-only tail.
 * @param max_elements Element limit including Pad and End; zero permits none.
 * @param diagnostic Optional diagnostic, reset on every call.
 * @return Significant prefix size through End, or the original C error.
 * @note Successful validation allocates nothing and retains no input. Building
 * an error description may allocate. Output storage must not overlap input.
 * @see tlv_dhcpv4_options_validate
 */
TLV_NODISCARD inline expected<size_t, error>
options_validate(bytes data, const tlv_dhcpv4_options_rules_t* rules = nullptr,
                 size_t max_elements = SIZE_MAX, tlv_diagnostic_t* diagnostic = nullptr) {
    size_t     significant_size = 0;
    const auto rc =
        tlv_dhcpv4_options_validate(reinterpret_cast<const uint8_t*>(data.data()), data.size(),
                                    rules, max_elements, &significant_size, diagnostic);
    if (rc != TLV_OK) return unexpected<error>(error::from_c(rc));
    return significant_size;
}
} // namespace dhcp
} // namespace tlv
#endif
