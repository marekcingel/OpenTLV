// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_TLVPP_WRITER_HPP
#define OPENTLV_TLVPP_WRITER_HPP

#include "tlv/writer/writer.h"
#include "tlv++/types.hpp"
#include "tlv++/format.hpp"
#include "tlv++/format_traits.hpp"
#include "tlv++/writer/value.hpp"

namespace tlv {

/**
 * @file writer.hpp
 * @brief C++ wrapper for sequential writing into a caller-owned buffer.
 */

/** @brief C++ alias for the writer-specific diagnostic type, #tlv_writer_diagnostic_t. */
using writer_diagnostic = tlv_writer_diagnostic_t;
/// @cond INTERNAL
namespace detail {
inline error writer_failed(tlv_result_t code, const writer_diagnostic& diagnostic) noexcept {
    return diagnostic.diagnostic.code == code
               ? error_access::diagnostic(diagnostic.diagnostic, operation::writer,
                                          diagnostic.has_tag ? &diagnostic.tag : nullptr)
               : error::from_c(code).during(operation::writer);
}
} // namespace detail
/// @endcond

/**
 * @brief Measures exact caller-owned destination storage for an Element.
 * @param value Semantic input; content-dependent formats require readable Value.
 * @param format Borrowed writable format.
 * @param diagnostic Optional failure detail; unchanged on success.
 * @return Native byte count or C error. Success does not allocate; errors may allocate.
 */
TLV_NODISCARD inline expected<size_t, error> encoded_size(const element_view& value,
                                                          tlv::format         format,
                                                          writer_diagnostic* diagnostic = nullptr) {
    writer_diagnostic local{};
    if (!diagnostic) diagnostic = &local;
    size_t     size = 0;
    const auto raw = detail::semantic_access::get(value);
    const auto rc =
        tlv_element_encoded_size_diag(&raw, &detail::format_access::get(format), &size, diagnostic);
    if (rc != TLV_OK) return unexpected<error>(detail::writer_failed(rc, *diagnostic));
    return size;
}

/**
 * @brief Measures an encoding from tag and Value length through the C Format.
 * @param tag Semantic tag.
 * @param length Logical Value length in bytes.
 * @param format Borrowed format; content-dependent formats may reject length-only measurement.
 * @return Required byte count, or the C measurement error.
 */
TLV_NODISCARD inline expected<size_t, error> encoded_size(tlv::tag tag, size_t length,
                                                          tlv::format format) {
    size_t     size = 0;
    const auto rc = tlv_encoded_size(detail::semantic_access::get(tag), length,
                                     &detail::format_access::get(format), &size);
    if (rc != TLV_OK) return unexpected<error>(error::from_c(rc).during(operation::writer));
    return size;
}

/**
 * @brief Encodes one semantic Element into caller-owned storage.
 * @param data Writable output; must not overlap the input Element's storage.
 * @param capacity Available output bytes.
 * @param format Borrowed Format and context, live for this call.
 * @param value Semantic Element with readable Value bytes.
 * @param diagnostic Optional borrowed failure detail; unchanged on success.
 * @return Written byte count, or the canonical C error.
 * @warning A failing Format callback may modify output bytes; see tlv_write_element_diag().
 */
TLV_NODISCARD inline expected<size_t, error> write(byte* data, size_t capacity, tlv::format format,
                                                   const element_view& value,
                                                   writer_diagnostic*  diagnostic = nullptr) {
    writer_diagnostic local{};
    if (!diagnostic) diagnostic = &local;
    size_t     written = 0;
    const auto raw = detail::semantic_access::get(value);
    const auto rc =
        tlv_write_element_diag(reinterpret_cast<uint8_t*>(data), capacity,
                               &detail::format_access::get(format), &raw, &written, diagnostic);
    if (rc != TLV_OK) return unexpected<error>(detail::writer_failed(rc, *diagnostic));
    return written;
}

/**
 * @brief Encodes one Tag and Value pair into caller-owned storage.
 * @param data Writable output; must not overlap the input tag or Value storage.
 * @param capacity Available output bytes.
 * @param format Borrowed Format and context.
 * @param tag Semantic tag.
 * @param value Readable Value bytes, borrowed for this call.
 * @param diagnostic Optional borrowed failure detail; unchanged on success.
 * @return Written byte count, or the canonical C error.
 * @warning A failing Format callback may modify output bytes; see tlv_write_diag().
 */
TLV_NODISCARD inline expected<size_t, error> write(byte* data, size_t capacity, tlv::format format,
                                                   tlv::tag tag, bytes value,
                                                   writer_diagnostic* diagnostic = nullptr) {
    writer_diagnostic local{};
    if (!diagnostic) diagnostic = &local;
    size_t     written = 0;
    const auto rc = tlv_write_diag(
        reinterpret_cast<uint8_t*>(data), capacity, &detail::format_access::get(format),
        detail::semantic_access::get(tag), reinterpret_cast<const uint8_t*>(value.data()),
        value.size(), &written, diagnostic);
    if (rc != TLV_OK) return unexpected<error>(detail::writer_failed(rc, *diagnostic));
    return written;
}

/**
 * @brief Thin C++ wrapper around #tlv_writer_t.
 *
 * Writes elements sequentially into a caller-owned buffer. Successful writes
 * do not allocate; an error result carries a `std::string` message and
 * therefore may allocate.
 *
 * @warning The caller must keep the buffer, format, and format context
 *          alive for the lifetime of the writer.
 * @see @docs{guides/memory,format context ownership and lifetime}
 */
namespace detail {
class writer_base {
public:
    /** @brief Encode a typed field into temporary owned storage, then write through Format.
     * @tparam Field Typed field selecting identifier and codec; include codec/typed.hpp.
     * @param value Semantic value, borrowed for this call.
     * @return Success or original codec/Writer error in its own domain.
     * @note May allocate; allocation exceptions propagate. Failure preserves the cursor.
     */
    template <typename Field>
    TLV_NODISCARD expected<void, typed_error> write(const typename Field::value_type& value);

    /** @brief Encode a typed field using caller-owned scratch, then write through Format.
     * @tparam Field Typed field selecting identifier and codec; include codec/typed.hpp.
     * @param value Semantic input, disjoint from scratch and Writer output.
     * @param scratch Temporary writable Value storage, disjoint from Writer output.
     * @return Success, codec error (including insufficient scratch), or original Writer error.
     * @note No library Value allocation. Custom codecs may allocate. Failure preserves
     * the Writer cursor; scratch and bytes beyond the cursor may change.
     */
    template <typename Field>
    TLV_NODISCARD expected<void, typed_error> write(const typename Field::value_type& value,
                                                    span<byte>                        scratch);
    /** @brief Initialize from borrowed mutable byte storage and a C++ Format view.
     * @param output Caller-owned contiguous storage, never resized.
     * @param format Borrowed descriptor and context, live for the cursor lifetime.
     */
    writer_base(span<byte> output, tlv::format format)
        : writer_base(output.data(), output.size(), format) {}

    /** @brief Initialize from borrowed mutable byte storage and a native Format.
     * @param output Caller-owned contiguous storage, never resized.
     * @param format Borrowed descriptor and context, live for the cursor lifetime.
     */
    writer_base(span<byte> output, const tlv_format_t& format)
        : writer_base(output.data(), output.size(), format) {}

    /**
     * @brief Borrow a byte sequence or text and write it under a semantic Tag.
     * @param tag Identifier, borrowed for this call.
     * @param value Byte/uint8_t array or contiguous container, Value view, string,
     * or string_view (C++17). Character arrays omit one trailing NUL, retaining
     * embedded NULs; strings use their explicit size. Inputs must not overlap output.
     * @return Canonical Writer result; error message construction may allocate.
     * @note No Value conversion allocates. Numbers require an explicit value codec;
     * encode them into caller storage before writing the resulting bytes.
     */
    template <typename T>
    TLV_NODISCARD auto write(tlv::tag tag, const T& value)
        -> decltype(detail::writer_bytes(value), expected<void, error>{}) {
        return write(tag, detail::writer_bytes(value));
    }

    /**
     * @brief Write a supported Value using program-lifetime identifier bytes.
     * @tparam TagBytes Individual identifier bytes in order; no integer normalization.
     * @param value Borrowed input with the same conversion rules as write(tag, value).
     * @return Canonical Writer result; failed writes preserve the cursor.
     */
    template <uint8_t... TagBytes, typename T>
    TLV_NODISCARD auto write(const T& value)
        -> decltype(detail::writer_bytes(value), expected<void, error>{}) {
        return write(tlv::tag_bytes<TagBytes...>(), detail::writer_bytes(value));
    }

    /**
     * @brief Create a sequential writer from a C++ Format view without allocation.
     * @param buf Borrowed output buffer, null only for zero capacity.
     * @param capacity Writable byte count.
     * @param format Borrowed Format; descriptor and context must outlive this writer.
     * @note The view may be temporary. Subsequent writes report initialization failures.
     */
    writer_base(byte* buf, size_t capacity, tlv::format format)
        : writer_base(buf, capacity, detail::format_access::get(format)) {}

    /**
     * @brief Creates a writer over a buffer.
     *
     * Initialization failures (for example missing format callbacks) are not
     * reported here; a subsequent write() fails.
     *
     * @param buf      Output buffer; borrowed.
     * @param capacity Buffer capacity in bytes.
     * @param format   Writer format; borrowed.
     */
    writer_base(byte* buf, size_t capacity, const tlv_format_t& format) {
        tlv_writer_init(&impl_, reinterpret_cast<uint8_t*>(buf), capacity, &format);
    }

    /**
     * @brief Writes one element with the given tag and raw value bytes.
     *
     * @param tag   Element tag.
     * @param value Value bytes; not retained.
     *
     * @return Success, or the error of tlv_writer_write().
     *
     * @note On error the write position is unchanged.
     */
    TLV_NODISCARD expected<void, error> write(tlv::tag tag, bytes value) {
        writer_diagnostic diagnostic{};
        return write(tag, value, diagnostic);
    }

    /**
     * @brief Write a borrowed Tag and Value through the canonical Writer.
     * @param tag Identifier bytes, borrowed for this call.
     * @param value Value bytes, borrowed for this call and disjoint from output.
     * @return Success or the original Writer error; failure preserves the cursor.
     */
    TLV_NODISCARD expected<void, error> write(tlv::tag tag, value_view value) {
        return write(tag, value.as_bytes());
    }

    /**
     * @brief Writes one element with the given tag and raw value bytes, with diagnostic detail on
     * failure.
     *
     * Behaves like write(), and additionally fills `out_diagnostic` when the
     * write fails; wraps tlv_writer_write_diag().
     *
     * @param tag            Element tag.
     * @param value          Value bytes; not retained.
     * @param out_diagnostic Receives detail on failure; left unchanged on success.
     *
     * @return Same as write().
     */
    TLV_NODISCARD expected<void, error> write(tlv::tag tag, bytes value,
                                              writer_diagnostic& out_diagnostic) {
        tlv_result_t rc = tlv_writer_write_diag(&impl_, detail::semantic_access::get(tag),
                                                reinterpret_cast<const uint8_t*>(value.data()),
                                                value.size(), &out_diagnostic);
        if (rc != TLV_OK) {
            return unexpected<error>(detail::writer_failed(rc, out_diagnostic));
        }
        return {};
    }

    /**
     * @brief Returns the number of bytes written so far.
     *
     * @return The current write position in bytes.
     */
    TLV_NODISCARD size_t size() const {
        return tlv_writer_size(&impl_);
    }

    /**
     * @brief Returns remaining destination bytes without changing state.
     * @return Available capacity in bytes.
     */
    TLV_NODISCARD size_t remaining() const {
        return tlv_writer_remaining(&impl_);
    }

    /**
     * @brief Encodes an Element at the current position using the cursor's Format.
     * @param value Semantic input; borrowed for the call, must not overlap output.
     * @param diagnostic Optional failure detail with absolute buffer offset.
     * @return Success or C error; position advances only on success.
     * @warning Callback errors may modify bytes past the unchanged position.
     */
    TLV_NODISCARD expected<void, error> write(const element_view& value,
                                              writer_diagnostic*  diagnostic = nullptr) {
        writer_diagnostic local{};
        if (!diagnostic) diagnostic = &local;
        const auto raw = detail::semantic_access::get(value);
        const auto rc = tlv_writer_write_element_diag(&impl_, &raw, diagnostic);
        if (rc != TLV_OK) return unexpected<error>(detail::writer_failed(rc, *diagnostic));
        return {};
    }

    /**
     * @brief Copies a raw byte range without validation or format conversion.
     * @param encoded Borrowed byte range; overlap is supported.
     * @param diagnostic Optional failure detail with absolute buffer offset.
     * @return Success or C error; failure preserves position and output bytes.
     */
    TLV_NODISCARD expected<void, error> copy_encoded(bytes              encoded,
                                                     writer_diagnostic* diagnostic = nullptr) {
        writer_diagnostic local{};
        if (!diagnostic) diagnostic = &local;
        const auto rc = tlv_writer_copy_encoded_diag(
            &impl_, reinterpret_cast<const uint8_t*>(encoded.data()), encoded.size(), diagnostic);
        if (rc != TLV_OK) return unexpected<error>(detail::writer_failed(rc, *diagnostic));
        return {};
    }

    /**
     * @brief Appends original framing after checking unchanged semantic content.
     * @param original Borrowed immutable Source; bytes and Format must remain alive.
     * @param value Current semantic content, equal to original content.
     * @param diagnostic Optional failure detail with absolute buffer offset.
     * @return Success or C error; failure preserves position and output bytes.
     * @warning Follow the overlap and immutable-source rules of tlv_writer_preserve().
     */
    TLV_NODISCARD expected<void, error> preserve(const tlv_source_t& original,
                                                 const element_view& value,
                                                 writer_diagnostic*  diagnostic = nullptr) {
        writer_diagnostic local{};
        if (!diagnostic) diagnostic = &local;
        const auto raw = detail::semantic_access::get(value);
        const auto rc = tlv_writer_preserve_diag(&impl_, &original, &raw, diagnostic);
        if (rc != TLV_OK) return unexpected<error>(detail::writer_failed(rc, *diagnostic));
        return {};
    }

private:
    tlv_writer_t impl_{};
};
} // namespace detail

/** @brief Generic sequential writer using the canonical C engine.
 * @tparam F C++ Format implementing format_traits; format selects a borrowed runtime view.
 * @warning For typed Formats this cursor owns a stable adapter and cannot be copied
 * or moved. It and all Format-borrowed storage must outlive retained results.
 */
template <typename F = tlv::format>
class writer : private format_adapter<F>, public detail::writer_base {
    static_assert(format_capabilities<F>::writable, "writer requires a writable Format");

public:
    /** @brief Initialize a typed Writer over borrowed mutable byte storage.
     * @param output Caller-owned contiguous output, never resized.
     * @param value Immutable Format configuration owned by the cursor.
     */
    explicit writer(span<byte> output, F value = F{})
        : writer(output.data(), output.size(), std::move(value)) {}

    /** @brief Initialize with default-constructed Format configuration.
     * @param data Borrowed output.
     * @param capacity Native output capacity.
     */
    writer(byte* data, size_t capacity)
        : format_adapter<F>(), detail::writer_base(data, capacity, format_adapter<F>::view()) {}
    /** @brief Initialize the cursor, owning immutable Format configuration.
     * @param data Borrowed output.
     * @param capacity Native output capacity.
     * @param value Format configuration copied or moved into stable storage.
     */
    explicit writer(byte* data, size_t capacity, F value)
        : format_adapter<F>(std::move(value)),
          detail::writer_base(data, capacity, format_adapter<F>::view()) {}
};
/** @brief Runtime Format cursor; descriptor and context remain borrowed. */
template <> class writer<tlv::format> : public detail::writer_base {
public:
    /** @brief Borrow mutable output and a C++ Format with explicit lifetime. */
    writer(byte* data, size_t capacity, tlv::format format)
        : detail::writer_base(data, capacity, format) {}
    /** @brief Borrow contiguous output and a C++ Format with explicit lifetime. */
    writer(span<byte> output, tlv::format format) : detail::writer_base(output, format) {}
};

} // namespace tlv

#endif // OPENTLV_TLVPP_WRITER_HPP
