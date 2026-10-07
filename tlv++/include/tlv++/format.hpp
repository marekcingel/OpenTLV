// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

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

    /** @brief Classify an identifier through this Format; absent classifiers return false.
     * @param identifier Borrowed identifier, used only during this call.
     * @note This is wire classification, not semantic Schema validation. */
    bool is_constructed(tlv::tag identifier) const noexcept {
        const auto raw = detail::semantic_access::get(identifier);
        return descriptor_->is_constructed &&
               descriptor_->is_constructed(descriptor_->context, &raw) != 0;
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
TLV_NODISCARD inline expected<decoded, error> decode(tlv::format format, bytes data) {
    tlv_decoded_t      result{};
    tlv_format_error_t diagnostic{};
    auto rc = tlv_format_decode(&detail::format_access::get(format),
                                reinterpret_cast<const uint8_t*>(data.data()), data.size(), &result,
                                &diagnostic);
    if (rc != TLV_OK) {
        auto failure = error::from_c(rc).during(operation::format);
        if (diagnostic.has_offset) failure = failure.at(diagnostic.offset, operation::format);
        return unexpected<error>(failure);
    }
    return decoded{detail::semantic_access::borrow(result.element), result.source};
}

/**
 * @brief Measure logical framing without a destination buffer.
 *
 * @param[in] format Writable descriptor.
 * @param[in] value  Semantic input; content-dependent formats require readable Value.
 *
 * @return Exact logical sizes, or a C format error.
 */
TLV_NODISCARD inline expected<encoding, error> measure(tlv::format         format,
                                                       const element_view& value) {
    encoding           result{};
    tlv_format_error_t diagnostic{};
    const auto         raw = detail::semantic_access::get(value);
    auto rc = tlv_format_measure(&detail::format_access::get(format), &raw, &result, &diagnostic);
    if (rc != TLV_OK) {
        auto failure = error::from_c(rc).during(operation::format);
        if (diagnostic.has_offset) failure = failure.at(diagnostic.offset, operation::format);
        return unexpected<error>(failure);
    }
    return result;
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
TLV_NODISCARD inline expected<size_t, error> encode(tlv::format format, const element_view& value,
                                                    byte* data, size_t capacity) {
    size_t             written = 0;
    tlv_format_error_t diagnostic{};
    const auto         raw = detail::semantic_access::get(value);
    auto rc = tlv_format_encode(&detail::format_access::get(format), &raw,
                                reinterpret_cast<uint8_t*>(data), capacity, &written, &diagnostic);
    if (rc != TLV_OK) {
        auto failure = error::from_c(rc).during(operation::format);
        if (diagnostic.has_offset) failure = failure.at(diagnostic.offset, operation::format);
        return unexpected<error>(failure);
    }
    return written;
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
    if (rc != TLV_OK) return unexpected<error>(error::from_c(rc).during(operation::format));
    return written;
}

} // namespace tlv
#include "tlv++/format_traits.hpp"
#endif
