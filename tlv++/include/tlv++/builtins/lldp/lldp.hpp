#ifndef OPENTLV_TLVPP_BUILTINS_LLDP_LLDP_HPP
#define OPENTLV_TLVPP_BUILTINS_LLDP_LLDP_HPP

#include "tlv/builtins/lldp/lldp.h"

/** @file
 * @brief C++ preset for LLDP framing, delegating to the shared C descriptor.
 */
namespace tlv {
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
