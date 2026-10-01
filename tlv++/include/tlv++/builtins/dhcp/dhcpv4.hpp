#ifndef OPENTLV_TLVPP_BUILTINS_DHCP_DHCPV4_HPP
#define OPENTLV_TLVPP_BUILTINS_DHCP_DHCPV4_HPP

#include "tlv/builtins/dhcp/dhcpv4.h"

#include "tlv++/format.hpp"
#include "tlv++/reader/reader.hpp"

/** @file
 * @brief C++ preset for DHCPv4 option framing using the shared C descriptor.
 */
namespace tlv {
/** @brief DHCP wire framing presets. */
namespace dhcp {
/** @brief Built-in Format satisfying the generic C++ customization contract. */
class format : public tlv::format {
public:
    /** @brief Borrow the canonical program-lifetime descriptor without allocation. */
    format() noexcept : tlv::format(detail::format_access::borrow(tlv_format_dhcpv4)) {}
};
/**
 * @brief Parse final input as borrowed Elements using the built-in Format.
 * @param data Immutable borrowed final input.
 * @return Allocation-free single-pass range; no Schema or Value validation is performed.
 * @throws parse_error During iteration on any failure other than final EOF.
 * @warning Input must outlive the range and every retained Element or diagnostic.
 * @see tlv::parse
 */
TLV_NODISCARD inline detail::parsing_range<format> parse(bytes data) {
    return tlv::parse<format>(data);
}
} // namespace dhcp

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
