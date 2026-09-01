#ifndef OPENTLV_TLVPP_WRITER_HPP
#define OPENTLV_TLVPP_WRITER_HPP

#include <expected>
#include <span>
#include <vector>

#include "tlv/writer.h"
#include "tlv++/codec.hpp"

namespace tlv {

// Thin C++ wrapper around tlv_writer_t. The caller owns the buffer (as in C).
class writer {
public:
    writer(std::byte* buf, size_t capacity) {
        tlv_writer_init(
            &impl_,
            reinterpret_cast<uint8_t*>(buf),
            capacity);
    }

    // Writes raw bytes with the specified tag.
    [[nodiscard]] std::expected<void, error> write(tag_t tag, bytes value) {
        tlv_result_t rc = tlv_writer_write(
            &impl_,
            tag,
            reinterpret_cast<const uint8_t*>(value.data()),
            value.size());
        if (rc != TLV_OK) {
            return std::unexpected(error::from_c(rc));
        }
        return {};
    }

    // Convenience overload for TlvCodec types: encodes the value into a
    // temporary buffer and writes it under T::tag.
    template<TlvCodec T>
    [[nodiscard]] std::expected<void, error> write(const T& value) {
        std::vector<std::byte> payload;
        value.encode(payload);
        return write(T::tag, payload);
    }

    [[nodiscard]] size_t size() const {
        return tlv_writer_size(&impl_);
    }

private:
    tlv_writer_t impl_{};
};

} // namespace tlv

#endif // OPENTLV_TLVPP_WRITER_HPP
