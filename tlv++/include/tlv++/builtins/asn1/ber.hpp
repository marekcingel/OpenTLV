#ifndef OPENTLV_TLVPP_BUILTINS_ASN1_BER_HPP
#define OPENTLV_TLVPP_BUILTINS_ASN1_BER_HPP

#include "tlv/builtins/asn1/ber.h"
#include "tlv++/types.hpp"
#include "tlv++/format.hpp"

/**
 * @file ber.hpp
 * @brief C++ wrapper for explicit BER indefinite-length framing.
 */

namespace tlv {

/** @brief BER-specific types backed by generic OpenTLV operations. */
namespace ber {
/**
 * @brief Program-lifetime BER Format usable by generic C++ consumers.
 * @note Constructing or copying this view allocates nothing. BER parsing and
 * encoding use the canonical engine; no independent parser is introduced.
 */
class format : public tlv::format {
public:
    /** @brief Select the immutable built-in BER descriptor and context. */
    format() noexcept : tlv::format(detail::format_access::borrow(tlv_format_ber)) {}
};
} // namespace ber

/**
 * @brief Writes explicit BER indefinite framing around an already encoded child sequence.
 *
 * Wraps tlv_ber_write_indefinite().
 *
 * @param data     Destination buffer. `nullptr` with zero `capacity` queries
 *                 the size.
 * @param capacity Destination capacity in bytes.
 * @param tag      Constructed element tag.
 * @param children Already encoded children, without the enclosing EOC. Must
 *                 not overlap the destination.
 *
 * @return The complete encoded size, or the error of
 *         tlv_ber_write_indefinite().
 *
 * @note On error the destination is unchanged.
 */
TLV_NODISCARD inline expected<size_t, error> ber_write_indefinite(byte* data, size_t capacity,
                                                                  tlv::tag tag, bytes children) {
    size_t       written = 0;
    tlv_result_t rc = tlv_ber_write_indefinite(
        reinterpret_cast<uint8_t*>(data), capacity, detail::semantic_access::get(tag),
        reinterpret_cast<const uint8_t*>(children.data()), children.size(), &written);
    if (rc != TLV_OK) return unexpected<error>(error::from_c(rc));
    return written;
}

} // namespace tlv

#endif
