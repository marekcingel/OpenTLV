#ifndef OPENTLV_TLVPP_CODEC_HPP
#define OPENTLV_TLVPP_CODEC_HPP

#include <cstdint>
#include <vector>
#include <string>

#include "tlv++/compat.hpp"

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
using bytes = span<const byte>;

// A TLV item on the C++ side (value points into the original buffer; zero-copy).
struct entry {
    tag_t tag;
    bytes value;
};

// Concept that every payload (data type) must satisfy to be encoded/decoded
// through TLV. Implementations live outside the library core.
// C++20 and later exposes this check as a concept. In C++11 through C++17 it
// remains an ordinary trait so the API can use SFINAE.
template <typename T> struct is_tlv_codec {
private:
    template <typename U>
    static auto test(int) -> decltype(
        static_cast<tag_t>(U::tag),
        std::declval<const U&>().encode(std::declval<std::vector<byte>&>()),
        U::decode(std::declval<bytes>()),
        std::true_type());
    template <typename> static std::false_type test(...);
public:
    static const bool value = decltype(test<T>(0))::value;
};

#if __cplusplus >= 202002L
template <typename T> concept TlvCodec = is_tlv_codec<T>::value;
#endif

} // namespace tlv

#endif // OPENTLV_TLVPP_CODEC_HPP
