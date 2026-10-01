#ifndef OPENTLV_TLVPP_BUILTINS_ASN1_CER_HPP
#define OPENTLV_TLVPP_BUILTINS_ASN1_CER_HPP
#include "tlv/builtins/asn1/cer.h"
#include "tlv++/format.hpp"
/** @file
 * @brief Generic C++ CER framing preset.
 */
namespace tlv {
/** @brief CER wire framing; semantic validation remains separate. */
namespace cer {
/** @brief Built-in Format satisfying the generic C++ customization contract. */
class format : public tlv::format {
public:
    /** @brief Borrow the immutable canonical descriptor without allocation. */
    format() noexcept : tlv::format(detail::format_access::borrow(tlv_format_cer)) {}
};
} // namespace cer
} // namespace tlv
#endif
