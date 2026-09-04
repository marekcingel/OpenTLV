#ifndef OPENTLV_TLVPP_READER_HPP
#define OPENTLV_TLVPP_READER_HPP

#include "tlv/reader.h"
#include "tlv++/codec.hpp"

namespace tlv {

// Thin, safe C++ wrapper around tlv_reader_t.
// It does not own the buffer (like the C core); it only iterates over it.
class reader {
public:
    explicit reader(bytes data) {
        tlv_result_t rc = tlv_reader_init(
            &impl_,
            reinterpret_cast<const uint8_t*>(data.data()),
            data.size());
        // init fails only for a null buffer with a non-zero size. That should
        // not occur with a valid span, but verify it through at_end().
        init_ok_ = (rc == TLV_OK);
    }

    [[nodiscard]] bool at_end() const {
        return !init_ok_ || tlv_reader_at_end(&impl_) != 0;
    }

    // Reads the next item. Returns an error if the buffer is invalid or empty.
    [[nodiscard]] expected<entry, error> next() {
        if (!init_ok_) {
            return unexpected<error>(error::from_c(TLV_ERR_NULL_ARG));
        }

        tlv_entry_t raw{};
        tlv_result_t rc = tlv_reader_next(&impl_, &raw);
        if (rc != TLV_OK) {
            return unexpected<error>(error::from_c(rc));
        }

        return entry{
            raw.tag.data[0],
            bytes(reinterpret_cast<const byte*>(raw.value.data), raw.value.length)
        };
    }

private:
    tlv_reader_t impl_{};
    bool init_ok_ = false;
};

} // namespace tlv

#endif // OPENTLV_TLVPP_READER_HPP
