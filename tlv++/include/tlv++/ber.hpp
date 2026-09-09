#ifndef OPENTLV_TLVPP_BER_HPP
#define OPENTLV_TLVPP_BER_HPP

#include "tlv/formats/asn1/ber.h"
#include "tlv++/types.hpp"

namespace tlv {

// Explicit BER indefinite framing of an already encoded child sequence.
// Returns the complete encoded size; destination and children must not overlap.
TLV_NODISCARD inline expected<size_t, error> ber_write_indefinite(
    byte* data, size_t capacity, tag_t tag, bytes children) {
    size_t written = 0;
    tlv_result_t rc = tlv_ber_write_indefinite(reinterpret_cast<uint8_t*>(data),
        capacity, tag, reinterpret_cast<const uint8_t*>(children.data()),
        children.size(), &written);
    if (rc != TLV_OK) return unexpected<error>(error::from_c(rc));
    return written;
}

} // namespace tlv

#endif
