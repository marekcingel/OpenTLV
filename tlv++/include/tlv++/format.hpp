#ifndef OPENTLV_TLVPP_FORMAT_HPP
#define OPENTLV_TLVPP_FORMAT_HPP

#include "tlv/attributes.h"
#include "tlv/format.h"
#include "tlv++/types.hpp"
#include "tlv++/detail/format_access.hpp"

/**
 * @file
 * @brief Borrowed C++ Formats, canonical operations and original source information.
 */

namespace tlv {

/**
 * @brief Copyable, allocation-free view of an immutable wire Format.
 *
 * Copies borrow the same descriptor and context; they do not own either.
 * The view itself need not outlive a Reader or Writer initialized from it.
 * Use a C++ preset or explicitly import a C descriptor with
 * `tlv::native::borrow_format()` from `<tlv++/native.hpp>`.
 *
 * @warning The descriptor and its context must remain alive and unchanged for
 * all operations and all retained source views. Borrowing does not validate
 * callbacks; operations report the canonical engine's initialization errors.
 */
class format {
public:
    /** @brief Whether the Format provides element decoding. */
    bool readable() const noexcept {
        return descriptor_->decode != nullptr;
    }

    /** @brief Whether the Format provides both measurement and encoding. */
    bool writable() const noexcept {
        return descriptor_->measure != nullptr && descriptor_->encode != nullptr;
    }

    /** @brief Whether the Format can classify constructed identifiers. */
    bool has_constructed_classifier() const noexcept {
        return descriptor_->is_constructed != nullptr;
    }

private:
    explicit format(const tlv_format_t& descriptor) noexcept : descriptor_(&descriptor) {}
    const tlv_format_t* descriptor_;
    friend struct detail::format_access;
};

/// @cond INTERNAL
inline tlv::format detail::format_access::borrow(const tlv_format_t& descriptor) noexcept {
    return tlv::format(descriptor);
}
inline const tlv_format_t& detail::format_access::get(tlv::format view) noexcept {
    return *view.descriptor_;
}
/// @endcond

/**
 * @brief Semantic element together with its borrowed original framing.
 * @warning Input, Format identifier storage and source Format/context must
 * remain alive and unchanged while any retained copy is used. Copies allocate nothing.
 */
struct decoded {
    /** @brief Complete semantic content borrowing input or immutable Format storage. */
    element_view element;
    /** @brief Original immutable framing; source storage and Format must outlive uses. */
    tlv_source_t source;
};

/**
 * @brief Immutable borrowed original wire representation.
 */
using source = tlv_source_t;

/**
 * @brief Exact logical framing sizes independent of the native address space.
 */
using encoding = tlv_encoding_t;

/**
 * @brief Decode one element and retain its original wire ranges without allocation.
 *
 * @param[in] format Readable descriptor, borrowed.
 * @param[in] data   Immutable borrowed input.
 *
 * @return Decoded content and source, or the C format error.
 *
 * @warning Input, descriptor and context must outlive the result and remain unchanged.
 */
TLV_NODISCARD inline expected<decoded, error> decode(const tlv_format_t& format, bytes data) {
    tlv_decoded_t result{};
    auto rc = tlv_format_decode(&format, reinterpret_cast<const uint8_t*>(data.data()), data.size(),
                                &result, nullptr);
    if (rc != TLV_OK) return unexpected<error>(error::from_c(rc));
    return decoded{detail::semantic_access::borrow(result.element), result.source};
}

/** @brief Decode using a borrowed C++ Format view.
 * @copydetails decode(const tlv_format_t&, bytes)
 */
TLV_NODISCARD inline expected<decoded, error> decode(tlv::format format, bytes data) {
    return decode(detail::format_access::get(format), data);
}

/**
 * @brief Measure logical framing without a destination buffer.
 *
 * @param[in] format Writable descriptor.
 * @param[in] value  Semantic input; content-dependent formats require readable Value.
 *
 * @return Exact logical sizes, or a C format error.
 */
TLV_NODISCARD inline expected<encoding, error> measure(const tlv_format_t& format,
                                                       const element_view& value) {
    encoding   result{};
    const auto raw = detail::semantic_access::get(value);
    auto       rc = tlv_format_measure(&format, &raw, &result, nullptr);
    if (rc != TLV_OK) return unexpected<error>(error::from_c(rc));
    return result;
}

/** @brief Measure using a borrowed C++ Format view.
 * @copydetails measure(const tlv_format_t&, const element_view&)
 */
TLV_NODISCARD inline expected<encoding, error> measure(tlv::format         format,
                                                       const element_view& value) {
    return measure(detail::format_access::get(format), value);
}

/**
 * @brief Encode current semantic content, regenerating framing.
 *
 * @param[in]  format   Writable descriptor.
 * @param[in]  value    Readable input, not overlapping destination.
 * @param[out] data     Destination pointer, NULL only for zero capacity.
 * @param[in]  capacity Native capacity in bytes.
 *
 * @return Written bytes, or a C format error. Callback failure may modify output.
 */
TLV_NODISCARD inline expected<size_t, error>
encode(const tlv_format_t& format, const element_view& value, byte* data, size_t capacity) {
    size_t     written = 0;
    const auto raw = detail::semantic_access::get(value);
    auto rc = tlv_format_encode(&format, &raw, reinterpret_cast<uint8_t*>(data), capacity, &written,
                                nullptr);
    if (rc != TLV_OK) return unexpected<error>(error::from_c(rc));
    return written;
}

/** @brief Encode using a borrowed C++ Format view.
 * @copydetails encode(const tlv_format_t&, const element_view&, byte*, size_t)
 */
TLV_NODISCARD inline expected<size_t, error> encode(tlv::format format, const element_view& value,
                                                    byte* data, size_t capacity) {
    return encode(detail::format_access::get(format), value, data, capacity);
}

/**
 * @brief Reproduce original bytes after checking semantic equality.
 *
 * @param[in]  original Immutable borrowed source from decode().
 * @param[in]  value    Current semantic content.
 * @param[out] data     Destination, or NULL with zero capacity for a size query.
 * @param[in]  capacity Native writable bytes.
 *
 * @return Written/required bytes on success, or a C error; mutation is rejected.
 *
 * @warning Original bytes, descriptor and context must remain valid and unchanged.
 */
TLV_NODISCARD inline expected<size_t, error>
preserve(const source& original, const element_view& value, byte* data, size_t capacity) {
    size_t     written = 0;
    const auto raw = detail::semantic_access::get(value);
    auto       rc =
        tlv_source_preserve(&original, &raw, reinterpret_cast<uint8_t*>(data), capacity, &written);
    if (rc != TLV_OK) return unexpected<error>(error::from_c(rc));
    return written;
}

} // namespace tlv
#endif
