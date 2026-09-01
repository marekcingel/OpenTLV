#ifndef OPENTLV_TLVPP_CODEC_HPP
#define OPENTLV_TLVPP_CODEC_HPP

#include <concepts>
#include <cstdint>
#include <span>
#include <vector>
#include <string>
#include <expected>

#include "tlv/error.h"
#include "tlv/tlv.h"

namespace tlv {

// Idiomatic C++ error that wraps a C error code and context.
struct error {
    tlv_result_t code;
    std::string  message;

    static error from_c(tlv_result_t c_code) {
        return error{c_code, tlv_strerror(c_code)};
    }
};

using tag_t = tlv_tag_t;
using bytes = std::span<const std::byte>;

// A TLV item on the C++ side (value points into the original buffer; zero-copy).
struct entry {
    tag_t tag;
    bytes value;
};

// Concept that every payload (data type) must satisfy to be encoded/decoded
// through TLV. Implementations live outside the library core.
template<typename T>
concept TlvCodec = requires(const T& val, bytes data, std::vector<std::byte>& out) {
    { T::tag } -> std::convertible_to<tag_t>;
    { val.encode(out) } -> std::same_as<void>;
    { T::decode(data) } -> std::same_as<std::expected<T, error>>;
};

} // namespace tlv

#endif // OPENTLV_TLVPP_CODEC_HPP
