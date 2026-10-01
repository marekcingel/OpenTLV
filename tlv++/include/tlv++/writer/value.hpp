#ifndef OPENTLV_TLVPP_WRITER_VALUE_HPP
#define OPENTLV_TLVPP_WRITER_VALUE_HPP

#include "tlv++/types.hpp"
#include <type_traits>
#if __cplusplus >= 201703L
#include <string_view>
#endif

/** @file
 * @brief Borrowed byte and text inputs for typed Writer operations.
 */
namespace tlv {
/// @cond INTERNAL
namespace detail {
template <typename T>
struct writer_byte
    : std::integral_constant<
          bool, std::is_same<typename std::remove_cv<T>::type, byte>::value ||
                    std::is_same<typename std::remove_cv<T>::type, unsigned char>::value> {};

inline bytes writer_bytes(value_view value) noexcept {
    return value.as_bytes();
}

template <typename T, size_t N>
typename std::enable_if<writer_byte<T>::value, bytes>::type
writer_bytes(const T (&value)[N]) noexcept {
    return bytes(reinterpret_cast<const byte*>(value), N);
}

template <size_t N> bytes writer_bytes(const char (&value)[N]) noexcept {
    return bytes(reinterpret_cast<const byte*>(value), value[N - 1] == '\0' ? N - 1 : N);
}

template <typename Traits, typename Allocator>
bytes writer_bytes(const std::basic_string<char, Traits, Allocator>& value) noexcept {
    return bytes(reinterpret_cast<const byte*>(value.data()), value.size());
}
#if __cplusplus >= 201703L
template <typename Traits> bytes writer_bytes(std::basic_string_view<char, Traits> value) noexcept {
    return bytes(reinterpret_cast<const byte*>(value.data()), value.size());
}
#endif

template <typename T>
auto writer_bytes(const T& value) noexcept(noexcept(value.data()) && noexcept(value.size())) ->
    typename std::enable_if<std::is_same<typename std::remove_cv<typename std::remove_pointer<
                                             decltype(value.data())>::type>::type,
                                         byte>::value,
                            bytes>::type {
    return bytes(value.data(), value.size());
}

// uint8_t containers need a byte view even where byte is std::byte.
template <typename T>
auto writer_bytes(const T& value) noexcept(noexcept(value.data()) && noexcept(value.size())) ->
    typename std::enable_if<std::is_same<typename std::remove_cv<typename std::remove_pointer<
                                             decltype(value.data())>::type>::type,
                                         unsigned char>::value,
                            bytes>::type {
    return bytes(reinterpret_cast<const byte*>(value.data()), value.size());
}

template <size_t N> span<byte> writer_output(byte (&value)[N]) noexcept {
    return span<byte>(value, N);
}
template <typename T>
auto writer_output(T& value) noexcept(noexcept(value.data()) && noexcept(value.size()))
    -> decltype(span<byte>(value.data(), value.size())) {
    return span<byte>(value.data(), value.size());
}
} // namespace detail
/// @endcond
} // namespace tlv
#endif
