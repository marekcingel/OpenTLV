#ifndef OPENTLV_TLVPP_REGISTRY_HPP
#define OPENTLV_TLVPP_REGISTRY_HPP

#include <any>
#include <expected>
#include <functional>
#include <unordered_map>

#include "tlv++/codec.hpp"

namespace tlv {

// Registry for types that must be decoded at runtime, rather than only through
// the compile-time TlvCodec concept. Useful, for example, for pluggable
// formats whose types are not all known at compile time.
class codec_registry {
public:
    using decoder_fn = std::function<std::expected<std::any, error>(bytes)>;

    // Registers a decoder for the specified tag. Replaces any previous registration.
    void register_decoder(tag_t tag, decoder_fn decoder) {
        decoders_[tag] = std::move(decoder);
    }

    // Registers a TlvCodec type directly, using its static tag and decode().
    template<TlvCodec T>
    void register_type() {
        register_decoder(T::tag, [](bytes data) -> std::expected<std::any, error> {
            auto result = T::decode(data);
            if (!result) {
                return std::unexpected(result.error());
            }
            return std::any(std::move(*result));
        });
    }

    [[nodiscard]] std::expected<std::any, error> decode(tag_t tag, bytes data) const {
        if (decoders_.count(tag) == 0) {
            return std::unexpected(error{TLV_ERR_INVALID_LENGTH, "unregistered tag"});
        }
        return decoders_.at(tag)(data);
    }

    [[nodiscard]] bool has_decoder(tag_t tag) const {
        return decoders_.contains(tag);
    }

private:
    std::unordered_map<tag_t, decoder_fn> decoders_;
};

} // namespace tlv

#endif // OPENTLV_TLVPP_REGISTRY_HPP
