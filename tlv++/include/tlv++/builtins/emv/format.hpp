#ifndef OPENTLV_CXX_BUILTINS_EMV_FORMAT_HPP
#define OPENTLV_CXX_BUILTINS_EMV_FORMAT_HPP

#include "tlv/builtins/emv/format.h"

/** @file
 * @brief C++ access to EMV Contact Book 3 element framing.
 */
namespace tlv {
/**
 * @brief Return the immutable definite EMV BER-TLV format.
 * @return The shared C descriptor; no allocation occurs.
 * @see tlv_format_emv
 */
inline const tlv_format_t& emv_format() noexcept {
    return tlv_format_emv;
}
} // namespace tlv
#endif
