#ifndef OPENTLV_TLVPP_BUILTINS_ASN1_CER_HPP
#define OPENTLV_TLVPP_BUILTINS_ASN1_CER_HPP
#include "tlv/builtins/asn1/cer.h"
#include "tlv++/format.hpp"
#include "tlv++/reader/reader.hpp"
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
} // namespace cer
} // namespace tlv
#endif
