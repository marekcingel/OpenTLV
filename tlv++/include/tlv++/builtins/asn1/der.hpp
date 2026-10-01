#ifndef OPENTLV_TLVPP_BUILTINS_ASN1_DER_HPP
#define OPENTLV_TLVPP_BUILTINS_ASN1_DER_HPP
#include "tlv/builtins/asn1/der.h"
#include "tlv++/format.hpp"
/** @file
 * @brief Generic C++ DER framing preset.
 */
namespace tlv {
/** @brief DER wire framing; semantic validation remains separate. */
namespace der {
/** @brief Built-in Format satisfying the generic C++ customization contract. */
class format : public tlv::format {
public:
    /** @brief Borrow the immutable canonical descriptor without allocation. */
    format() noexcept : tlv::format(detail::format_access::borrow(tlv_format_der)) {}
};
} // namespace der
} // namespace tlv
#endif
