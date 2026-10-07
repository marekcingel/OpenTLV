// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_TLVPP_CODEC_DYNAMIC_HPP
#define OPENTLV_TLVPP_CODEC_DYNAMIC_HPP
#include "tlv++/types.hpp"
#include "tlv/codec/codec.h"
#include <type_traits>
#include <utility>

/** @file
 * @brief Runtime-selected Value codecs over caller-owned typed storage.
 */
namespace tlv {
/** @brief Value conversion outcomes, independent of wire framing errors. */
enum class codec_errc {
    ok = TLV_CODEC_OK,                                  /**< Conversion succeeded. */
    null_argument = TLV_CODEC_ERR_NULL_ARG,             /**< Required storage absent. */
    buffer_too_short = TLV_CODEC_ERR_BUFFER_TOO_SHORT,  /**< Insufficient capacity. */
    invalid_value = TLV_CODEC_ERR_INVALID_VALUE,        /**< Invalid Value representation. */
    unsupported = TLV_CODEC_ERR_UNSUPPORTED,            /**< Direction not supported. */
    invalid_structure = TLV_CODEC_ERR_INVALID_STRUCTURE /**< Structural conversion failed. */
};
/** @brief Return immutable program-lifetime codec status text without allocation. */
inline const char* message(codec_errc code) noexcept {
    return tlv_codec_strerror(static_cast<tlv_codec_result_t>(code));
}
/** @brief Project a codec outcome into the common diagnostic contract without allocation.
 * @param code Original codec status, retained by the calling result for exact domain inspection.
 * @return Corresponding operation status with the codec's precise static description.
 */
inline error to_error(codec_errc code) noexcept {
    errc status = errc::invalid_value;
    switch (code) {
        case codec_errc::ok: status = errc::ok; break;
        case codec_errc::null_argument: status = errc::null_argument; break;
        case codec_errc::buffer_too_short: status = errc::buffer_too_short; break;
        case codec_errc::unsupported: status = errc::unsupported_type; break;
        case codec_errc::invalid_structure: status = errc::schema; break;
        case codec_errc::invalid_value: break;
    }
    return error(static_cast<tlv_result_t>(status), message(code)).during(operation::codec);
}
/// @cond INTERNAL
namespace detail {
struct codec_access;
}
/// @endcond
/**
 * @brief Borrowed runtime Value codec, selected by a domain dictionary or explicit
 * interoperability.
 *
 * The descriptor and its context must remain immutable and alive through every use.
 * Operations allocate nothing; borrowed decoded representations retain input lifetime.
 * A default view has no capabilities and reports unsupported operations.
 * The domain selecting the descriptor must document its exact representation type.
 */
class dynamic_codec {
public:
    /** @brief Create an absent codec. */
    dynamic_codec() noexcept = default;
    /** @brief Whether a decoder is available. */
    bool readable() const noexcept {
        return descriptor_ && descriptor_->decode;
    }
    /** @brief Whether an encoder is available. */
    bool writable() const noexcept {
        return descriptor_ && descriptor_->encode;
    }
    /**
     * @brief Decode into the descriptor's exact representation type.
     * @tparam T Exact representation documented by the selected dictionary or codec.
     * @param input Borrowed immutable Value bytes.
     * @return Representation or original codec status; conversion never selects by enclosing tag.
     * @warning T must match the selected descriptor; borrowed members require input to outlive T.
     */
    template <typename T> expected<T, codec_errc> decode(bytes input) const {
        T    result{};
        auto status = decode_into(input, span<T>(&result, 1));
        if (!status) return unexpected<codec_errc>(status.error());
        return result;
    }
    /**
     * @brief Decode into caller-owned, correctly typed representation storage.
     * @tparam T Exact representation type (or character type for string codecs).
     * @param input Borrowed immutable Value, disjoint from destination.
     * @param output Writable destination; capacity is checked in bytes.
     * @return Success or original codec status. On failure destination is unspecified.
     */
    template <typename T>
    expected<void, codec_errc> decode_into(bytes input, span<T> output) const {
        if (!readable()) return unexpected<codec_errc>(codec_errc::unsupported);
        if (output.size() > SIZE_MAX / sizeof(T))
            return unexpected<codec_errc>(codec_errc::buffer_too_short);
        auto rc = tlv_codec_decode(descriptor_, reinterpret_cast<const uint8_t*>(input.data()),
                                   input.size(), output.data(), output.size() * sizeof(T));
        if (rc != TLV_CODEC_OK) return unexpected<codec_errc>(static_cast<codec_errc>(rc));
        return {};
    }
    /**
     * @brief Encode or measure the descriptor's exact representation into caller storage.
     * @tparam T Exact representation type documented by the selected descriptor.
     * @param value Representation, disjoint from output.
     * @param output Writable bytes; a default empty span validates and measures only.
     * @return Written or required byte count, or original codec status.
     * @warning Failing encoding may modify destination bytes.
     */
    template <typename T>
    expected<size_t, codec_errc> encode(const T& value, span<byte> output = {}) const {
        if (!writable()) return unexpected<codec_errc>(codec_errc::unsupported);
        size_t written = 0;
        auto   rc =
            tlv_codec_encode(descriptor_, &value, sizeof(T),
                             reinterpret_cast<uint8_t*>(output.data()), output.size(), &written);
        if (rc != TLV_CODEC_OK) return unexpected<codec_errc>(static_cast<codec_errc>(rc));
        return written;
    }

private:
    const tlv_codec_t* descriptor_ = nullptr;
    explicit dynamic_codec(const tlv_codec_t* value) noexcept : descriptor_(value) {}
    friend struct detail::codec_access;
};
/// @cond INTERNAL
namespace detail {
struct codec_access {
    static dynamic_codec borrow(const tlv_codec_t* value) noexcept {
        return dynamic_codec(value);
    }
    static const tlv_codec_t* get(dynamic_codec value) noexcept {
        return value.descriptor_;
    }
};
} // namespace detail
/// @endcond

/** @brief Stationary owner adapting a stateful C++ Value codec to runtime selection.
 * @tparam Codec Immutable codec exposing value_type, const noexcept decode(bytes)
 * returning expected<value_type, codec_errc>, and const noexcept
 * encode(const value_type&, byte*, size_t) returning expected<size_t, codec_errc>.
 * @note Nonthrowing static typed codecs also satisfy this contract. The adapter allocates nothing;
 * state construction follows Codec's own policy. No native callback tables are required.
 * @warning Views borrow this owner. Decode results may borrow the input Value bytes.
 */
template <typename Codec> class codec_owner {
public:
    /** @brief Exact representation required by this runtime codec. */
    using value_type = typename Codec::value_type;
    static_assert(std::is_same<decltype(std::declval<const Codec&>().decode(std::declval<bytes>())),
                               expected<value_type, codec_errc>>::value,
                  "Runtime codec decode must return expected<value_type, codec_errc>");
    static_assert(
        std::is_same<decltype(std::declval<const Codec&>().encode(
                         std::declval<const value_type&>(), static_cast<byte*>(nullptr), size_t{})),
                     expected<size_t, codec_errc>>::value,
        "Runtime codec encode must return expected<size_t, codec_errc>");
    static_assert(std::is_nothrow_move_assignable<value_type>::value,
                  "Runtime codec representations must support noexcept move assignment");
    static_assert(noexcept(std::declval<const Codec&>().decode(std::declval<bytes>())),
                  "Runtime codec decode(bytes) must be const and noexcept");
    static_assert(noexcept(std::declval<const Codec&>().encode(std::declval<const value_type&>(),
                                                               static_cast<byte*>(nullptr),
                                                               size_t{})),
                  "Runtime codec encode(value, output, capacity) must be const and noexcept");
    /** @brief Construct codec state in place, including non-default-constructible state.
     * @param args Arguments forwarded exactly once to Codec's constructor.
     */
    template <typename... Args>
    explicit codec_owner(Args&&... args)
        : codec_(std::forward<Args>(args)...), descriptor_{this, decode, encode} {}
    /** @brief Keep borrowed descriptor/context addresses stationary. */
    codec_owner(const codec_owner&) = delete;
    /** @brief Do not replace state borrowed by runtime views. */
    codec_owner& operator=(const codec_owner&) = delete;
    /** @brief Borrow runtime capabilities; the owner must outlive every use. */
    dynamic_codec view() const& noexcept {
        return detail::codec_access::borrow(&descriptor_);
    }
    /** @brief Reject a runtime view into a temporary owner. */
    dynamic_codec view() const&& = delete;

private:
    Codec                     codec_;
    tlv_codec_t               descriptor_;
    static tlv_codec_result_t decode(const void* context, const uint8_t* data, size_t size,
                                     void* output, size_t capacity) noexcept {
        if (!output) return TLV_CODEC_ERR_NULL_ARG;
        if (capacity < sizeof(value_type)) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
        const auto& self = *static_cast<const codec_owner*>(context);
        auto        value = self.codec_.decode({reinterpret_cast<const byte*>(data), size});
        if (!value) return static_cast<tlv_codec_result_t>(value.error());
        *static_cast<value_type*>(output) = std::move(*value);
        return TLV_CODEC_OK;
    }
    static tlv_codec_result_t encode(const void* context, const void* input, size_t size,
                                     uint8_t* output, size_t capacity, size_t* written) noexcept {
        if (!input || !written) return TLV_CODEC_ERR_NULL_ARG;
        if (size != sizeof(value_type)) return TLV_CODEC_ERR_INVALID_VALUE;
        const auto& self = *static_cast<const codec_owner*>(context);
        auto        value = self.codec_.encode(*static_cast<const value_type*>(input),
                                               reinterpret_cast<byte*>(output), capacity);
        if (!value) return static_cast<tlv_codec_result_t>(value.error());
        *written = *value;
        return TLV_CODEC_OK;
    }
};
} // namespace tlv
#endif
