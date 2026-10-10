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
/** @brief Typed codec violation diagnostic category. */
enum class codec_violation {
    none = TLV_CODEC_VIOLATION_NONE /**< Canonical none category. */,
    result = TLV_CODEC_VIOLATION_RESULT /**< Canonical result category. */,
    size = TLV_CODEC_VIOLATION_SIZE /**< Canonical size category. */,
    type = TLV_CODEC_VIOLATION_TYPE /**< Canonical type category. */,
    utf8 = TLV_CODEC_VIOLATION_UTF8 /**< Canonical utf8 category. */
};
/** @brief Canonical static name, or unknown for unrecognized categories. */
inline const char* message(codec_violation value) noexcept {
    return tlv_codec_violation_string(static_cast<tlv_codec_violation_t>(value));
}

/** @brief Typed codec cause diagnostic category. */
enum class codec_cause {
    none = TLV_CODEC_CAUSE_NONE /**< Canonical none category. */,
    reader = TLV_CODEC_CAUSE_READER /**< Canonical reader category. */,
    schema = TLV_CODEC_CAUSE_SCHEMA /**< Canonical schema category. */
};
/** @brief Canonical static name, or unknown for unrecognized categories. */
inline const char* message(codec_cause value) noexcept {
    return tlv_codec_cause_string(static_cast<tlv_codec_cause_t>(value));
}

/** @brief Typed codec phase diagnostic category. */
enum class codec_phase {
    decode = TLV_CODEC_OP_DECODE /**< Canonical decode category. */,
    encode = TLV_CODEC_OP_ENCODE /**< Canonical encode category. */,
    measure = TLV_CODEC_OP_MEASURE /**< Canonical measure category. */
};
/** @brief Canonical static name, or unknown for unrecognized categories. */
inline const char* message(codec_phase value) noexcept {
    return tlv_codec_operation_string(static_cast<tlv_codec_operation_t>(value));
}

/** @brief Shared result and complete conversion evidence, without a separate error enum. */
struct codec_failure {
    tlv_result_t           code;         /**< Original common result. */
    tlv_codec_diagnostic_t diagnostic{}; /**< Conversion operation, location and delegated cause. */
    /** @brief Construct a result-only conversion failure. */
    codec_failure(errc value) noexcept : codec_failure(static_cast<tlv_result_t>(value)) {}
    /** @brief Preserve a native result with unknown cause/location. */
    explicit codec_failure(tlv_result_t value) noexcept : code(value) {
        tlv_codec_diagnostic_init(&diagnostic, TLV_CODEC_OP_DECODE);
        diagnostic.codec.reported = value;
        tlv_codec_diagnostic_result(&diagnostic, value);
    }
    /** @brief Preserve the full optional diagnostic by value; external borrows remain borrowed. */
    codec_failure(tlv_result_t value, const tlv_codec_diagnostic_t& detail) noexcept
        : code(value), diagnostic(detail) {
        diagnostic.diagnostic.code = value;
    }
    /** @brief Operation attempted by this conversion. */
    codec_phase phase() const noexcept {
        return static_cast<codec_phase>(diagnostic.codec.operation);
    }
    /** @brief Delegated diagnostic category. */
    codec_cause cause() const noexcept {
        return static_cast<codec_cause>(diagnostic.codec.cause);
    }
    /** @brief Callback contract violation, if detected. */
    codec_violation violation() const noexcept {
        return static_cast<codec_violation>(diagnostic.codec.violation);
    }
    /** @brief Common C++ result classification. */
    errc status() const noexcept {
        return static_cast<errc>(code);
    }
    /** @brief Canonical static description. */
    const char* message() const noexcept {
        return tlv_result_string(code);
    }
    /** @brief Project common metadata while this object retains complete typed evidence. */
    error failure() const noexcept {
        return detail::error_access::diagnostic(diagnostic.diagnostic, operation::codec);
    }
    /** @brief Return the shared native result for callback interoperability. */
    explicit operator tlv_result_t() const noexcept {
        return code;
    }
    /** @brief Compare classification with the shared result domain. */
    friend bool operator==(const codec_failure& a, errc b) noexcept {
        return a.status() == b;
    }
    /** @brief Compare classification with the shared result domain. */
    friend bool operator==(errc a, const codec_failure& b) noexcept {
        return a == b.status();
    }
};
/// @cond INTERNAL
namespace detail {
struct codec_access;
template <typename Owner, typename... Args> struct is_codec_owner_argument : std::false_type {};
template <typename Owner, typename Arg>
struct is_codec_owner_argument<Owner, Arg> : std::is_same<Owner, typename std::decay<Arg>::type> {};
} // namespace detail
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
    template <typename T> expected<T, codec_failure> decode(bytes input) const {
        T    result{};
        auto status = decode_into(input, span<T>(&result, 1));
        if (!status) return unexpected<codec_failure>(status.error());
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
    expected<void, codec_failure> decode_into(bytes input, span<T> output) const {
        if (!readable()) return unexpected<codec_failure>(errc::unsupported);
        if (output.size() > SIZE_MAX / sizeof(T))
            return unexpected<codec_failure>(errc::buffer_too_short);
        tlv_codec_diagnostic_t diagnostic;
        auto                   rc =
            tlv_codec_decode(descriptor_, reinterpret_cast<const uint8_t*>(input.data()),
                             input.size(), output.data(), output.size() * sizeof(T), &diagnostic);
        if (rc != TLV_OK) return unexpected<codec_failure>(codec_failure(rc, diagnostic));
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
    expected<size_t, codec_failure> encode(const T& value, span<byte> output = {}) const {
        if (!writable()) return unexpected<codec_failure>(errc::unsupported);
        tlv_codec_diagnostic_t diagnostic;
        size_t                 written = 0;
        auto rc = tlv_codec_encode(descriptor_, &value, sizeof(T),
                                   reinterpret_cast<uint8_t*>(output.data()), output.size(),
                                   &written, &diagnostic);
        if (rc != TLV_OK) return unexpected<codec_failure>(codec_failure(rc, diagnostic));
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
 * returning expected<value_type, codec_failure>, and const noexcept
 * encode(const value_type&, byte*, size_t) returning expected<size_t, codec_failure>.
 * @note Nonthrowing static typed codecs also satisfy this contract. The adapter allocates nothing;
 * state construction follows Codec's own policy. No native callback tables are required.
 * @warning Views borrow this owner. Decode results may borrow the input Value bytes.
 */
template <typename Codec> class codec_owner {
public:
    /** @brief Exact representation required by this runtime codec. */
    using value_type = typename Codec::value_type;
    static_assert(std::is_same<decltype(std::declval<const Codec&>().decode(std::declval<bytes>())),
                               expected<value_type, codec_failure>>::value,
                  "Runtime codec decode must return expected<value_type, codec_failure>");
    static_assert(
        std::is_same<decltype(std::declval<const Codec&>().encode(
                         std::declval<const value_type&>(), static_cast<byte*>(nullptr), size_t{})),
                     expected<size_t, codec_failure>>::value,
        "Runtime codec encode must return expected<size_t, codec_failure>");
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
     * @note A sole argument of this owner type is excluded, regardless of cv/ref qualification.
     * Owners cannot be copied or moved, even when Codec accepts arbitrary constructor arguments.
     */
    template <typename... Args,
              typename std::enable_if<!detail::is_codec_owner_argument<codec_owner, Args...>::value,
                                      int>::type = 0>
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
    Codec               codec_;
    tlv_codec_t         descriptor_;
    static tlv_result_t decode(const void* context, const uint8_t* data, size_t size, void* output,
                               size_t capacity, tlv_codec_diagnostic_t* diagnostic) noexcept {
        tlv_codec_diagnostic_init(diagnostic, TLV_CODEC_OP_DECODE);
        if (!output) return tlv_codec_diagnostic_result(diagnostic, TLV_ERR_NULL_ARG);
        if (capacity < sizeof(value_type))
            return tlv_codec_diagnostic_result(diagnostic, TLV_ERR_BUFFER_TOO_SHORT);
        const auto& self = *static_cast<const codec_owner*>(context);
        auto        value = self.codec_.decode({reinterpret_cast<const byte*>(data), size});
        if (!value) {
            if (diagnostic) *diagnostic = value.error().diagnostic;
            return tlv_codec_diagnostic_result(diagnostic, value.error().code);
        }
        *static_cast<value_type*>(output) = std::move(*value);
        return tlv_codec_diagnostic_result(diagnostic, TLV_OK);
    }
    static tlv_result_t encode(const void* context, const void* input, size_t size, uint8_t* output,
                               size_t capacity, size_t* written,
                               tlv_codec_diagnostic_t* diagnostic) noexcept {
        tlv_codec_diagnostic_init(diagnostic, TLV_CODEC_OP_ENCODE);
        if (!input || !written) return tlv_codec_diagnostic_result(diagnostic, TLV_ERR_NULL_ARG);
        if (size != sizeof(value_type))
            return tlv_codec_diagnostic_result(diagnostic, TLV_ERR_INVALID_VALUE);
        const auto& self = *static_cast<const codec_owner*>(context);
        auto        value = self.codec_.encode(*static_cast<const value_type*>(input),
                                               reinterpret_cast<byte*>(output), capacity);
        if (!value) {
            if (diagnostic) *diagnostic = value.error().diagnostic;
            return tlv_codec_diagnostic_result(diagnostic, value.error().code);
        }
        *written = *value;
        return tlv_codec_diagnostic_result(diagnostic, TLV_OK);
    }
};
} // namespace tlv
#endif
