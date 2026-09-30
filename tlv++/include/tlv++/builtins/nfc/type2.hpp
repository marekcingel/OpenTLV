#ifndef OPENTLV_TLVPP_BUILTINS_NFC_TYPE2_HPP
#define OPENTLV_TLVPP_BUILTINS_NFC_TYPE2_HPP

#include "tlv/builtins/nfc/type2.h"

/** @file
 * @brief C++ preset for contiguous NFC Type 2 Tag TLV streams.
 */
namespace tlv {
/** @brief Returns the immutable NFC Type 2 framing preset.
 * @return Shared C descriptor with static lifetime.
 * @note Requires `OPENTLV_NFC=ON`. The caller handles padding, termination
 * and physical memory mapping; NDEF contents remain opaque.
 * @see tlv_format_nfc_type2
 */
inline const tlv_format_t& nfc_type2_format() noexcept {
    return tlv_format_nfc_type2;
}
} // namespace tlv
#endif
