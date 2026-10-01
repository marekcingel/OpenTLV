#ifndef OPENTLV_TLVPP_BUILTINS_LLDP_LLDP_HPP
#define OPENTLV_TLVPP_BUILTINS_LLDP_LLDP_HPP

#include "tlv/builtins/lldp/lldp.h"

#include "tlv++/format.hpp"

/** @file
 * @brief C++ preset for LLDP framing, delegating to the shared C descriptor.
 */
namespace tlv {
/** @brief LLDP wire framing presets. */
namespace lldp {
/** @brief Built-in Format satisfying the generic C++ customization contract. */
class format : public tlv::format {
public:
    /** @brief Borrow the canonical program-lifetime descriptor without allocation. */
    format() noexcept : tlv::format(detail::format_access::borrow(tlv_format_lldp)) {}
};
} // namespace lldp

/**
 * @brief Returns the immutable LLDP framing preset.
 * @return The shared C descriptor with static lifetime.
 * @note Requires `OPENTLV_LLDP=ON`. Does not validate LLDPDU semantics.
 * @see tlv_format_lldp
 */
inline const tlv_format_t& lldp_format() noexcept {
    return tlv_format_lldp;
}
} // namespace tlv
#endif
