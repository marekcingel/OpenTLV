#ifndef OPENTLV_TLVPP_BUILTINS_BLUETOOTH_LTV_HPP
#define OPENTLV_TLVPP_BUILTINS_BLUETOOTH_LTV_HPP
#include "tlv/builtins/bluetooth/bluetooth_ltv.h"
#include "tlv++/format.hpp"
#include "tlv++/reader/reader.hpp"
/** @file
 * @brief Generic C++ Bluetooth LTV framing preset.
 */
namespace tlv {
/** @brief Bluetooth wire framing; AD container validation remains separate. */
namespace bluetooth {
/** @brief Built-in Format satisfying the generic C++ customization contract. */
class format : public tlv::format {
public:
    /** @brief Borrow the immutable canonical descriptor without allocation. */
    format() noexcept : tlv::format(detail::format_access::borrow(tlv_format_bluetooth_ltv)) {}
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
} // namespace bluetooth
} // namespace tlv
#endif
