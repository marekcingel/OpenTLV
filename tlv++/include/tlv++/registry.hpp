#ifndef OPENTLV_TLVPP_REGISTRY_HPP
#define OPENTLV_TLVPP_REGISTRY_HPP

#include <functional>
#include <map>

#include "tlv++/codec.hpp"

namespace tlv {

// Registry for types that must be decoded at runtime, rather than only through
// the compile-time TlvCodec concept. Useful, for example, for pluggable
// formats whose types are not all known at compile time.
class codec_registry {
public:
  using decoder_fn = std::function<expected<any, error>(bytes)>;

  // Registers a decoder for the specified tag. Replaces any previous
  // registration.
  void register_decoder(tag_t tag, decoder_fn decoder) {
    decoders_[tag] = std::move(decoder);
  }

  // Registers a TlvCodec type directly, using its static tag and decode().
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

  [[nodiscard]] expected<any, error> decode(tag_t tag,
                                                      bytes data) const {
    if (decoders_.count(tag) == 0) {
      return unexpected<error>(error{TLV_ERR_INVALID_LENGTH, "unregistered tag"});
    }
    return decoders_.at(tag)(data);
  }

  [[nodiscard]] bool has_decoder(tag_t tag) const {
    return decoders_.find(tag) != decoders_.end();
  }

private:
  std::map<tag_t, decoder_fn> decoders_;
};

} // namespace tlv

#endif // OPENTLV_TLVPP_REGISTRY_HPP
