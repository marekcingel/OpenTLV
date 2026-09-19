#ifndef OPENTLV_TLVPP_REGISTRY_HPP
#define OPENTLV_TLVPP_REGISTRY_HPP

#include <functional>
#include <map>

#include "tlv++/codec.hpp"

namespace tlv {

/**
 * @file registry.hpp
 * @brief Runtime registry mapping tags to decoders.
 */

/**
 * @brief Registry for types that must be decoded at runtime.
 *
 * Complements the compile-time TlvCodec concept. Useful, for example, for
 * pluggable formats whose types are not all known at compile time.
 *
 * @note Registering and decoding may allocate.
 */
class codec_registry {
public:
    /** @brief Callable that decodes a value into a type-erased result. */
    using decoder_fn = std::function<expected<any, error>(bytes)>;

    /**
     * @brief Registers a decoder for a tag.
     *
     * Replaces any previous registration for the same tag.
     *
     * @param tag     Tag to register.
     * @param decoder Decoder called with the element's value bytes.
     */
    void register_decoder(tag_t tag, decoder_fn decoder) {
        decoders_[tag] = std::move(decoder);
    }

    /**
     * @brief Registers a codec type directly, using its static `tag` and `decode()`.
     *
     * Replaces any previous registration for `T::tag`.
     *
     * @tparam T A type satisfying #tlv::is_tlv_codec.
     */
#if __cplusplus >= 202002L
    template <TlvCodec T> void register_type() {
#else
    template <typename T> void register_type() {
#endif
        static_assert(is_tlv_codec<T>::value, "T must satisfy the TLV codec interface");
        register_decoder(T::tag, [](bytes data) -> expected<any, error> {
            expected<T, error> result = T::decode(data);
            if (!result) {
                return unexpected<error>(result.error());
            }
            return any(std::move(*result));
        });
    }

    /**
     * @brief Decodes a value with the decoder registered for a tag.
     *
     * @param tag  Tag identifying the decoder.
     * @param data Value bytes.
     *
     * @return The decoded value, the decoder's error, or an error with code
     *         #TLV_ERR_INVALID_LENGTH and message `"unregistered tag"` if no
     *         decoder is registered for `tag`.
     */
    TLV_NODISCARD expected<any, error> decode(tag_t tag, bytes data) const {
        if (decoders_.count(tag) == 0) {
            return unexpected<error>(error{TLV_ERR_INVALID_LENGTH, "unregistered tag"});
        }
        return decoders_.at(tag)(data);
    }

    /**
     * @brief Reports whether a decoder is registered for a tag.
     *
     * @param tag Tag to check.
     *
     * @return `true` if a decoder is registered.
     */
    TLV_NODISCARD bool has_decoder(tag_t tag) const {
        return decoders_.find(tag) != decoders_.end();
    }

private:
    struct tag_less {
        bool operator()(const tag_t& left, const tag_t& right) const {
            const size_t common = left.size < right.size ? left.size : right.size;
            for (size_t i = 0; i < common && i < TLV_TAG_CAPACITY; ++i) {
                if (left.data[i] != right.data[i]) {
                    return left.data[i] < right.data[i];
                }
            }
            return left.size < right.size;
        }
    };

    std::map<tag_t, decoder_fn, tag_less> decoders_;
};

} // namespace tlv

#endif // OPENTLV_TLVPP_REGISTRY_HPP
