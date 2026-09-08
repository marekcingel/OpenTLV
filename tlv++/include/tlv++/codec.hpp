#ifndef OPENTLV_TLVPP_CODEC_HPP
#define OPENTLV_TLVPP_CODEC_HPP

#include <type_traits>
#include <utility>
#include <vector>
#include "tlv++/types.hpp"
#include "tlv++/writer.hpp"

namespace tlv {

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

// Explicit higher-level convenience API. The temporary vector may allocate.
template <typename T>
TLV_NODISCARD typename std::enable_if<is_tlv_codec<T>::value, expected<void, error>>::type
write_value(writer& output, const T& value) {
    std::vector<byte> payload;
    value.encode(payload);
    return output.write(T::tag, bytes(payload.data(), payload.size()));
}

} // namespace tlv

#endif // OPENTLV_TLVPP_CODEC_HPP
