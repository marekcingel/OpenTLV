#ifndef OPENTLV_TLVPP_FORMAT_TRAITS_HPP
#define OPENTLV_TLVPP_FORMAT_TRAITS_HPP

#include "tlv++/format.hpp"
#include "tlv/size.h"
#include <type_traits>
#include <utility>

/** @file
 * @brief C++11 Format customization and adaptation to the canonical C engine.
 */
namespace tlv {

/** @brief Allocation-free Format failure with optional relative wire diagnostics. */
struct format_failure {
    /** @brief Original canonical result code. */
    tlv_result_t code;
    /** @brief Partial wire information; offsets are relative to the element. */
    tlv_format_error_t detail;
    /** @brief Construct a failure without allocating a message.
     * @param code Canonical error code.
     * @param detail Optional wire information.
     */
    explicit format_failure(tlv_result_t code, tlv_format_error_t detail = {}) noexcept
        : code(code), detail(detail) {}
};

/** @brief Borrowed arguments for exact logical Format measurement.
 * @details Unlike a readable Element, measurement can describe a Value without
 * storage and can exceed the native address space. content contains the complete
 * Value when available, or an empty null span for a size-only request. Formats
 * inspecting Value must reject unavailable nonempty content. Arithmetic uses
 * value_size, never content.size(), and must check logical overflow.
 */
struct measure_request {
    /** @brief Canonical byte identifier, possibly absent. */
    tlv::tag identifier;
    /** @brief Logical Value byte count, independent of native size_t. */
    tlv_size_t value_size;
    /** @brief Complete borrowed readable content, or null/empty for size-only queries. */
    bytes content;
};

/// @cond INTERNAL
namespace detail {
template <typename...> struct format_void {
    using type = void;
};
template <typename F, typename = void> struct names_decode : std::false_type {};
template <typename F>
struct names_decode<F, typename format_void<decltype(&F::decode)>::type> : std::true_type {};
template <typename F, typename = void> struct names_measure : std::false_type {};
template <typename F>
struct names_measure<F, typename format_void<decltype(&F::measure)>::type> : std::true_type {};
template <typename F, typename = void> struct names_encode : std::false_type {};
template <typename F>
struct names_encode<F, typename format_void<decltype(&F::encode)>::type> : std::true_type {};
template <typename F, typename = void> struct names_is_constructed : std::false_type {};
template <typename F>
struct names_is_constructed<F, typename format_void<decltype(&F::is_constructed)>::type>
    : std::true_type {};
} // namespace detail
/// @endcond

/** @brief Customize a Format without inheritance or virtual dispatch.
 * @tparam F Immutable Format implementation.
 * @details The default trait forwards const, noexcept member operations:
 * decode(bytes) -> expected<decoded, format_failure>,
 * measure(const measure_request&) -> expected<encoding, format_failure>,
 * encode(const element_view&, span<byte>) -> expected<size_t, format_failure>,
 * and optional is_constructed(tag) -> bool.
 * Specializations expose equivalent static operations taking const F& first.
 * Decode is optional; measure and encode must occur together. At least one
 * capability group is required. All operations preserve the C Format invariants,
 * borrow storage, and must not allocate or throw. Classification is framing only.
 */
template <typename F, typename Enable = void> struct format_traits {
    /// @cond INTERNAL
    static const bool declares_decode = detail::names_decode<F>::value;
    static const bool declares_measure = detail::names_measure<F>::value;
    static const bool declares_encode = detail::names_encode<F>::value;
    static const bool declares_is_constructed = detail::names_is_constructed<F>::value;
    /// @endcond
    /** @brief Forward one complete element decode. */
    template <typename U = F>
    static auto decode(const U& f, bytes data) noexcept(noexcept(f.decode(data)))
        -> decltype(f.decode(data)) {
        return f.decode(data);
    }
    /** @brief Forward exact logical framing measurement. */
    template <typename U = F>
    static auto measure(const U&               f,
                        const measure_request& value) noexcept(noexcept(f.measure(value)))
        -> decltype(f.measure(value)) {
        return f.measure(value);
    }
    /** @brief Forward complete element encoding into bounded output. */
    template <typename U = F>
    static auto encode(const U& f, const element_view& value,
                       span<byte> data) noexcept(noexcept(f.encode(value, data)))
        -> decltype(f.encode(value, data)) {
        return f.encode(value, data);
    }
    /** @brief Forward optional constructed identifier classification. */
    template <typename U = F>
    static auto is_constructed(const U& f, tag id) noexcept(noexcept(f.is_constructed(id)))
        -> decltype(f.is_constructed(id)) {
        return f.is_constructed(id);
    }
};

/// @cond INTERNAL
namespace detail {

template <typename F, typename = void> struct declares_decode : names_decode<format_traits<F>> {};
template <typename F>
struct declares_decode<F, typename format_void<decltype(format_traits<F>::declares_decode)>::type>
    : std::integral_constant<bool, format_traits<F>::declares_decode> {};
template <typename F, typename = void> struct declares_measure : names_measure<format_traits<F>> {};
template <typename F>
struct declares_measure<F, typename format_void<decltype(format_traits<F>::declares_measure)>::type>
    : std::integral_constant<bool, format_traits<F>::declares_measure> {};
template <typename F, typename = void> struct declares_encode : names_encode<format_traits<F>> {};
template <typename F>
struct declares_encode<F, typename format_void<decltype(format_traits<F>::declares_encode)>::type>
    : std::integral_constant<bool, format_traits<F>::declares_encode> {};
template <typename F, typename = void>
struct declares_is_constructed : names_is_constructed<format_traits<F>> {};
template <typename F>
struct declares_is_constructed<
    F, typename format_void<decltype(format_traits<F>::declares_is_constructed)>::type>
    : std::integral_constant<bool, format_traits<F>::declares_is_constructed> {};
template <typename F, typename = void> struct decode_contract {
    static const bool present = declares_decode<F>::value;
    static const bool valid = false;
};
template <typename F>
struct decode_contract<F, typename format_void<decltype(format_traits<F>::decode(
                              std::declval<const F&>(), std::declval<bytes>()))>::type> {
    static const bool present = true;
    static const bool valid =
        std::is_same<decltype(format_traits<F>::decode(std::declval<const F&>(),
                                                       std::declval<bytes>())),
                     expected<decoded, format_failure>>::value &&
        noexcept(format_traits<F>::decode(std::declval<const F&>(), std::declval<bytes>()));
};
template <typename F, typename = void> struct measure_contract {
    static const bool present = declares_measure<F>::value;
    static const bool valid = false;
};
template <typename F>
struct measure_contract<
    F, typename format_void<decltype(format_traits<F>::measure(
           std::declval<const F&>(), std::declval<const measure_request&>()))>::type> {
    static const bool present = true;
    static const bool valid =
        std::is_same<decltype(format_traits<F>::measure(std::declval<const F&>(),
                                                        std::declval<const measure_request&>())),
                     expected<encoding, format_failure>>::value &&
        noexcept(format_traits<F>::measure(std::declval<const F&>(),
                                           std::declval<const measure_request&>()));
};
template <typename F, typename = void> struct encode_contract {
    static const bool present = declares_encode<F>::value;
    static const bool valid = false;
};
template <typename F>
struct encode_contract<F, typename format_void<decltype(format_traits<F>::encode(
                              std::declval<const F&>(), std::declval<const element_view&>(),
                              std::declval<span<byte>>()))>::type> {
    static const bool present = true;
    static const bool valid =
        std::is_same<decltype(format_traits<F>::encode(std::declval<const F&>(),
                                                       std::declval<const element_view&>(),
                                                       std::declval<span<byte>>())),
                     expected<size_t, format_failure>>::value &&
        noexcept(format_traits<F>::encode(std::declval<const F&>(),
                                          std::declval<const element_view&>(),
                                          std::declval<span<byte>>()));
};
template <typename F, typename = void> struct classifier_contract {
    static const bool present = declares_is_constructed<F>::value;
    static const bool valid = false;
};
template <typename F>
struct classifier_contract<F, typename format_void<decltype(format_traits<F>::is_constructed(
                                  std::declval<const F&>(), std::declval<tag>()))>::type> {
    static const bool present = true;
    static const bool valid =
        std::is_same<decltype(format_traits<F>::is_constructed(std::declval<const F&>(),
                                                               std::declval<tag>())),
                     bool>::value &&
        noexcept(format_traits<F>::is_constructed(std::declval<const F&>(), std::declval<tag>()));
};

template <typename F, bool Enabled> struct decode_bridge {
    static tlv_decode_fn get() {
        return nullptr;
    }
};
template <typename F> struct decode_bridge<F, true> {
    static tlv_result_t call(const void* context, const uint8_t* data, size_t size,
                             tlv_decoded_t* out, tlv_format_error_t* error) noexcept {
        auto result = format_traits<F>::decode(*static_cast<const F*>(context),
                                               bytes(reinterpret_cast<const byte*>(data), size));
        if (!result) {
            *error = result.error().detail;
            return result.error().code;
        }
        out->element = semantic_access::get(result->element);
        out->source = result->source;
        return TLV_OK;
    }
    static tlv_decode_fn get() {
        return &call;
    }
};
template <typename F, bool Enabled> struct write_bridge {
    static tlv_measure_fn measure() {
        return nullptr;
    }
    static tlv_encode_fn encode() {
        return nullptr;
    }
};
template <typename F> struct write_bridge<F, true> {
    static tlv_result_t measure_call(const void* context, const tlv_element_t* value,
                                     tlv_encoding_t* out, tlv_format_error_t* error) noexcept {
        size_t size = 0;
        if (value->value.data) {
            auto rc = tlv_size_to_native(value->value.size, &size);
            if (rc != TLV_OK) return rc;
        }
        const measure_request request{
            semantic_access::borrow(value->tag), value->value.size,
            bytes(reinterpret_cast<const byte*>(value->value.data), size)};
        auto result = format_traits<F>::measure(*static_cast<const F*>(context), request);
        if (!result) {
            *error = result.error().detail;
            return result.error().code;
        }
        *out = *result;
        return TLV_OK;
    }
    static tlv_result_t encode_call(const void* context, const tlv_element_t* value, uint8_t* data,
                                    size_t capacity, size_t* written,
                                    tlv_format_error_t* error) noexcept {
        auto result = format_traits<F>::encode(*static_cast<const F*>(context),
                                               semantic_access::borrow(*value),
                                               span<byte>(reinterpret_cast<byte*>(data), capacity));
        if (!result) {
            *error = result.error().detail;
            return result.error().code;
        }
        *written = *result;
        return TLV_OK;
    }
    static tlv_measure_fn measure() {
        return &measure_call;
    }
    static tlv_encode_fn encode() {
        return &encode_call;
    }
};
template <typename F, bool Enabled> struct classifier_bridge {
    static tlv_is_constructed_fn get() {
        return nullptr;
    }
};
template <typename F> struct classifier_bridge<F, true> {
    static int call(const void* context, const tlv_tag_t* id) noexcept {
        return format_traits<F>::is_constructed(*static_cast<const F*>(context),
                                                semantic_access::borrow(*id))
                   ? 1
                   : 0;
    }
    static tlv_is_constructed_fn get() {
        return &call;
    }
};
} // namespace detail
/// @endcond

/// @cond INTERNAL
namespace detail {
struct native_format_operations {
    /** @brief Decode through the canonical C Format and preserve failure detail. */
    template <typename F>
    static expected<decoded, format_failure> decode(const F& f, bytes data) noexcept {
        tlv_decoded_t      out{};
        tlv_format_error_t error{};
        auto rc = tlv_format_decode(&detail::format_access::get(f),
                                    reinterpret_cast<const uint8_t*>(data.data()), data.size(),
                                    &out, &error);
        if (rc != TLV_OK) return unexpected<format_failure>(format_failure(rc, error));
        return decoded{detail::semantic_access::borrow(out.element), out.source};
    }
    /** @brief Measure through the canonical C Format. */
    template <typename F>
    static expected<encoding, format_failure> measure(const F&               f,
                                                      const measure_request& value) noexcept {
        if ((value.content.data() && value.content.size() != value.value_size) ||
            (!value.content.data() && value.content.size()))
            return unexpected<format_failure>(format_failure(TLV_ERR_INVALID_ARG));
        encoding            out{};
        tlv_format_error_t  error{};
        const tlv_element_t raw{
            detail::semantic_access::get(value.identifier),
            {reinterpret_cast<const uint8_t*>(value.content.data()), value.value_size}};
        auto rc = tlv_format_measure(&detail::format_access::get(f), &raw, &out, &error);
        if (rc != TLV_OK) return unexpected<format_failure>(format_failure(rc, error));
        return out;
    }
    /** @brief Encode through the canonical C Format. */
    template <typename F>
    static expected<size_t, format_failure> encode(const F& f, const element_view& value,
                                                   span<byte> data) noexcept {
        size_t             out = 0;
        tlv_format_error_t error{};
        auto               raw = detail::semantic_access::get(value);
        auto               rc =
            tlv_format_encode(&detail::format_access::get(f), &raw,
                              reinterpret_cast<uint8_t*>(data.data()), data.size(), &out, &error);
        if (rc != TLV_OK) return unexpected<format_failure>(format_failure(rc, error));
        return out;
    }
    /** @brief Classify using the borrowed descriptor; absent classifiers return false. */
    template <typename F> static bool is_constructed(const F& f, tag id) noexcept {
        const auto& descriptor = detail::format_access::get(f);
        auto        raw = detail::semantic_access::get(id);
        return descriptor.is_constructed &&
               descriptor.is_constructed(descriptor.context, &raw) != 0;
    }
};
} // namespace detail
/// @endcond

/** @brief Built-in borrowed Format views implement the same customization contract.
 * @tparam F A C++ Format view or built-in preset derived from it.
 */
template <typename F>
struct format_traits<F, typename std::enable_if<std::is_base_of<tlv::format, F>::value>::type>
    : detail::native_format_operations {};

/** @brief Measure a logical Value, optionally without readable storage.
 * @param format Borrowed writable execution view.
 * @param request Canonical identifier, logical size and optional complete content.
 * @return Exact framing sizes or the original Format error.
 * @note Nonempty content must have the exact logical Value size. A size-only
 * request may exceed SIZE_MAX; narrowing is deferred until actual buffer use.
 */
TLV_NODISCARD inline expected<encoding, error> measure(tlv::format            format,
                                                       const measure_request& request) {
    auto result = format_traits<tlv::format>::measure(format, request);
    if (!result) return unexpected<error>(error::from_c(result.error().code));
    return *result;
}

/** @brief Compile-time capability and signature validation for a C++ Format.
 * @tparam F Format type or a type with specialized format_traits.
 */
template <typename F> struct format_capabilities {
    /** @brief Valid const noexcept decode operation. */
    static const bool readable = detail::decode_contract<F>::valid;
    /** @brief Valid const noexcept measurement and encoding operations. */
    static const bool writable =
        detail::measure_contract<F>::valid && detail::encode_contract<F>::valid;
    /** @brief Valid optional const noexcept classifier. */
    static const bool classified = detail::classifier_contract<F>::valid;
    /** @brief Complete contract including capability pairing and optional operation validation. */
    static const bool valid =
        (readable || writable) && (!detail::decode_contract<F>::present || readable) &&
        (detail::measure_contract<F>::present == detail::encode_contract<F>::present) &&
        (!detail::measure_contract<F>::present || writable) &&
        (!detail::classifier_contract<F>::present || classified);
};

/// @cond INTERNAL
namespace detail {
template <typename F,
          bool Native = std::is_base_of<native_format_operations, format_traits<F>>::value>
struct descriptor_bridge {
    static tlv_format_t make(const F& value) noexcept {
        return tlv_format_t{&value, decode_bridge<F, format_capabilities<F>::readable>::get(),
                            write_bridge<F, format_capabilities<F>::writable>::measure(),
                            write_bridge<F, format_capabilities<F>::writable>::encode(),
                            classifier_bridge<F, format_capabilities<F>::classified>::get()};
    }
};
template <typename F> struct descriptor_bridge<F, true> {
    static tlv_format_t make(const F& value) noexcept {
        // Native views already implement the execution contract. Preserve their
        // actual runtime capabilities and callbacks without adding another hop.
        return format_access::get(value);
    }
};
} // namespace detail
/// @endcond

/** @brief Stable allocation-free adapter owning an immutable C++ Format value.
 * @tparam F Format implementing format_traits.
 * @details Use view() with Tree Reader/Writer, Document, Query and free algorithms.
 * The adapter and any storage borrowed by F must outlive consumers and retained
 * Elements/sources. Copying and moving are prohibited to preserve descriptor and
 * context addresses. F construction may allocate; the adapter itself allocates
 * no heap storage and processing never copies F.
 */
template <typename F> class format_adapter {
    static_assert(
        !detail::decode_contract<F>::present || detail::decode_contract<F>::valid,
        "Format decode must return expected<decoded, format_failure> and be const noexcept");
    static_assert(detail::measure_contract<F>::present == detail::encode_contract<F>::present,
                  "Format writing requires both measure and encode");
    static_assert(
        !detail::measure_contract<F>::present || detail::measure_contract<F>::valid,
        "Format measure must return expected<encoding, format_failure> and be const noexcept");
    static_assert(
        !detail::encode_contract<F>::present || detail::encode_contract<F>::valid,
        "Format encode must return expected<size_t, format_failure> and be const noexcept");
    static_assert(!detail::classifier_contract<F>::present || detail::classifier_contract<F>::valid,
                  "Format is_constructed must return bool and be const noexcept");
    static_assert(format_capabilities<F>::readable || format_capabilities<F>::writable,
                  "Format requires decode or the measure/encode pair");

public:
    /** @brief Default-construct immutable Format configuration in stable storage. */
    format_adapter() : value_(), descriptor_(make_descriptor()) {}
    /** @brief Own the supplied Format configuration in stable storage.
     * @param value Configuration copied or moved by value; referenced storage remains borrowed.
     */
    explicit format_adapter(F value) : value_(std::move(value)), descriptor_(make_descriptor()) {}
    /** @brief Prohibit copying stable descriptor addresses. */
    format_adapter(const format_adapter&) = delete;
    /** @brief Prohibit assignment of immutable configuration. */
    format_adapter& operator=(const format_adapter&) = delete;
    /** @brief Return a borrowed generic view; the adapter must outlive all uses. */
    tlv::format view() const noexcept {
        return detail::format_access::borrow(descriptor_);
    }

private:
    tlv_format_t make_descriptor() const noexcept {
        return detail::descriptor_bridge<F>::make(value_);
    }
    const F            value_;
    const tlv_format_t descriptor_;
};
} // namespace tlv
#endif
