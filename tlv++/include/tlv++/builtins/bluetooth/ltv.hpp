#ifndef OPENTLV_TLVPP_BUILTINS_BLUETOOTH_LTV_HPP
#define OPENTLV_TLVPP_BUILTINS_BLUETOOTH_LTV_HPP
#include "tlv/builtins/bluetooth/bluetooth_ltv.h"
#include "tlv++/format.hpp"
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
} // namespace bluetooth
} // namespace tlv
#endif
