#ifndef OPENTLV_TLVPP_READER_HPP
#define OPENTLV_TLVPP_READER_HPP

#include "tlv/reader/reader.h"
#include "tlv++/types.hpp"

namespace tlv {

// Thin, safe C++ wrapper around tlv_reader_t.
// The caller keeps the buffer, format, and format context alive.
class reader {
public:
    reader(bytes data, const tlv_reader_format_t& format) {
        tlv_result_t rc = tlv_reader_init(
            &impl_,
            reinterpret_cast<const uint8_t*>(data.data()),
            data.size(), &format);
        // Invalid buffers or missing format callbacks prevent reading.
        init_ok_ = (rc == TLV_OK);
    }

    TLV_NODISCARD bool at_end() const {
        return !init_ok_ || tlv_reader_at_end(&impl_) != 0;
    }

    // Reads the next item. Returns an error if the buffer is invalid or empty.
    TLV_NODISCARD expected<entry, error> next() {
        if (!init_ok_) {
            return unexpected<error>(error::from_c(TLV_ERR_NULL_ARG));
        }

        tlv_view_t raw{};
        tlv_result_t rc = tlv_reader_next(&impl_, &raw);
        if (rc != TLV_OK) {
            return unexpected<error>(error::from_c(rc));
        }

        return entry{
            raw.tag,
            bytes(reinterpret_cast<const byte*>(raw.value.data), raw.value.length)
        };
    }

private:
    tlv_reader_t impl_{};
    bool init_ok_ = false;
};

} // namespace tlv

#endif // OPENTLV_TLVPP_READER_HPP
