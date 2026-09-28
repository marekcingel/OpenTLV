#ifndef OPENTLV_TLVPP_BUILTINS_DHCP_CONTAINER_HPP
#define OPENTLV_TLVPP_BUILTINS_DHCP_CONTAINER_HPP

#include "tlv/builtins/dhcp/container.h"

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
} // namespace tlv
#endif
