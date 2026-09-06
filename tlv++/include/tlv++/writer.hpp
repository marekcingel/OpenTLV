#ifndef OPENTLV_TLVPP_WRITER_HPP
#define OPENTLV_TLVPP_WRITER_HPP

#include <vector>
#include <type_traits>

#include "tlv/writer.h"
#include "tlv++/codec.hpp"

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
    [[nodiscard]] expected<void, error> write(tag_t tag, bytes value) {
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

    // Convenience overload for TlvCodec types: encodes the value into a
    // temporary buffer and writes it under T::tag.
#if __cplusplus >= 202002L
    template <TlvCodec T>
    [[nodiscard]] expected<void, error> write(const T& value) {
#else
    template <typename T>
    [[nodiscard]] typename std::enable_if<is_tlv_codec<T>::value,
                                          expected<void, error>>::type
    write(const T& value) {
#endif
        std::vector<byte> payload;
        value.encode(payload);
        return write(T::tag, bytes(payload.data(), payload.size()));
    }

    [[nodiscard]] size_t size() const {
        return tlv_writer_size(&impl_);
    }

private:
    tlv_writer_t impl_{};
};

} // namespace tlv

#endif // OPENTLV_TLVPP_WRITER_HPP
