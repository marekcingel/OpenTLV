#ifndef OPENTLV_TLVPP_WRITER_HPP
#define OPENTLV_TLVPP_WRITER_HPP

#include "tlv/writer/writer.h"
#include "tlv++/types.hpp"

namespace tlv {

// Thin C++ wrapper; the caller keeps the buffer, format, and context alive.
class writer {
public:
    writer(byte* buf, size_t capacity, const tlv_format_t& format) {
        tlv_writer_init(
            &impl_,
            reinterpret_cast<uint8_t*>(buf),
            capacity, &format);
    }

    // Writes raw bytes with the specified tag.
    TLV_NODISCARD expected<void, error> write(tag_t tag, bytes value) {
        tlv_result_t rc = tlv_writer_write(
            &impl_,
            tag,
            reinterpret_cast<const uint8_t*>(value.data()),
            value.size());
        if (rc != TLV_OK) {
            return unexpected<error>(error::from_c(rc));
        }
        return {};
    }

    TLV_NODISCARD size_t size() const {
        return tlv_writer_size(&impl_);
    }

private:
    tlv_writer_t impl_{};
};

} // namespace tlv

#endif // OPENTLV_TLVPP_WRITER_HPP
