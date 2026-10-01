#ifndef OPENTLV_TLVPP_BUILTINS_LLDP_LLDP_HPP
#define OPENTLV_TLVPP_BUILTINS_LLDP_LLDP_HPP

#include "tlv/builtins/lldp/lldp.h"

#include "tlv++/format.hpp"
#include "tlv++/reader/reader.hpp"

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
