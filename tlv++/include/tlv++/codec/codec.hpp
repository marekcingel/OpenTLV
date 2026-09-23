#ifndef OPENTLV_TLVPP_CODEC_HPP
#define OPENTLV_TLVPP_CODEC_HPP

#include <type_traits>
#include <utility>
#include <vector>
#include "tlv++/types.hpp"
#include "tlv++/writer/writer.hpp"

/**
 * @file codec.hpp
 * @brief Compile-time codec trait and a convenience value writer.
 */

namespace tlv {

/**
 * @brief Trait for the interface every payload type must satisfy to be encoded and decoded through
 * TLV.
 *
 * `T` satisfies the trait when it provides:
 * - a static member `tag` convertible to #tag_t. The tag only borrows its bytes, so they must
 *   have static storage (for example `static const tlv::tag_t tag;` defined with `TLV_TAG(...)`),
 * - `void encode(std::vector<byte>&) const` appending its encoded value, and
 * - a static `decode(bytes)` returning the decoded value.
 *
 * Implementations live outside the library core. C++20 and later expose the
 * same check as the TlvCodec concept. In C++11 through C++17 it remains an
 * ordinary trait so the API can use SFINAE.
 *
 * @tparam T Payload type to check.
 */
template <typename T> struct is_tlv_codec {
private:
    template <typename U>
    static auto test(int)
        -> decltype(static_cast<tag_t>(U::tag),
                    std::declval<const U&>().encode(std::declval<std::vector<byte>&>()),
                    U::decode(std::declval<bytes>()), std::true_type());
    template <typename> static std::false_type test(...);

public:
    /** @brief Whether T provides the codec expressions described by this trait. */
    static const bool value = decltype(test<T>(0))::value;
};

#if __cplusplus >= 202002L || defined(OPENTLV_DOXYGEN)
/** @brief Concept form of #tlv::is_tlv_codec; available from C++20. */
template <typename T> concept TlvCodec = is_tlv_codec<T>::value;
#endif

/**
 * @brief Encodes a codec value and writes it as one element.
 *
 * Calls `value.encode()` into a temporary vector, then writes it under
 * `T::tag`. This is an explicit higher-level convenience API.
 *
 * @tparam T A type satisfying #tlv::is_tlv_codec.
 *
 * @param output Writer to append to.
 * @param value  Value to encode.
 *
 * @return Success, or the error of writer::write().
 *
 * @note The temporary vector may allocate.
 */
template <typename T>
TLV_NODISCARD typename std::enable_if<is_tlv_codec<T>::value, expected<void, error>>::type
write_value(writer& output, const T& value) {
    std::vector<byte> payload;
    value.encode(payload);
    return output.write(T::tag, bytes(payload.data(), payload.size()));
}

} // namespace tlv

#endif // OPENTLV_TLVPP_CODEC_HPP
