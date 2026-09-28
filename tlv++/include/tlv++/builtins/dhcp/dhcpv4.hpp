#ifndef OPENTLV_TLVPP_BUILTINS_DHCP_DHCPV4_HPP
#define OPENTLV_TLVPP_BUILTINS_DHCP_DHCPV4_HPP

#include "tlv/builtins/dhcp/dhcpv4.h"

/** @file
 * @brief C++ preset for DHCPv4 option framing using the shared C descriptor.
 */
namespace tlv {
/**
 * @brief Returns the immutable DHCPv4 option framing preset.
 * @return The shared C descriptor with static lifetime.
 * @note Requires `OPENTLV_DHCP=ON`. The caller handles End and packet semantics.
 * @see tlv_format_dhcpv4
 */
inline const tlv_format_t& dhcpv4_format() noexcept {
    return tlv_format_dhcpv4;
}
} // namespace tlv
#endif
