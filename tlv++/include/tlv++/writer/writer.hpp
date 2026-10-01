#ifndef OPENTLV_TLVPP_WRITER_HPP
#define OPENTLV_TLVPP_WRITER_HPP

#include "tlv/writer/writer.h"
#include "tlv++/types.hpp"
#include "tlv++/format.hpp"

namespace tlv {

/**
 * @file writer.hpp
 * @brief C++ wrapper for sequential writing into a caller-owned buffer.
 */

/** @brief C++ alias for the writer-specific diagnostic type, #tlv_writer_diagnostic_t. */
using writer_diagnostic = tlv_writer_diagnostic_t;

/**
 * @brief Measures exact caller-owned destination storage for an Element.
 * @param value Semantic input; content-dependent formats require readable Value.
 * @param format Borrowed writable format.
 * @param diagnostic Optional failure detail; unchanged on success.
 * @return Native byte count or C error. Success does not allocate; errors may allocate.
 */
TLV_NODISCARD inline expected<size_t, error> encoded_size(const element&      value,
                                                          const tlv_format_t& format,
                                                          writer_diagnostic* diagnostic = nullptr) {
    size_t     size = 0;
    const auto rc = tlv_element_encoded_size_diag(&value, &format, &size, diagnostic);
    if (rc != TLV_OK) return unexpected<error>(error::from_c(rc));
    return size;
}

/**
 * @brief Measures an encoding from tag and Value length through the C Format.
 * @param tag Semantic tag.
 * @param length Logical Value length in bytes.
 * @param format Borrowed format; content-dependent formats may reject length-only measurement.
 * @return Required byte count, or the C measurement error.
 */
TLV_NODISCARD inline expected<size_t, error> encoded_size(tag_t tag, size_t length,
                                                          const tlv_format_t& format) {
    size_t     size = 0;
    const auto rc = tlv_encoded_size(tag, length, &format, &size);
    if (rc != TLV_OK) return unexpected<error>(error::from_c(rc));
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
TLV_NODISCARD inline expected<size_t, error> write(byte* data, size_t capacity,
                                                   const tlv_format_t& format, const element& value,
                                                   writer_diagnostic* diagnostic = nullptr) {
    size_t     written = 0;
    const auto rc = tlv_write_element_diag(reinterpret_cast<uint8_t*>(data), capacity, &format,
                                           &value, &written, diagnostic);
    if (rc != TLV_OK) return unexpected<error>(error::from_c(rc));
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
TLV_NODISCARD inline expected<size_t, error> write(byte* data, size_t capacity,
                                                   const tlv_format_t& format, tag_t tag,
                                                   bytes              value,
                                                   writer_diagnostic* diagnostic = nullptr) {
    size_t     written = 0;
    const auto rc = tlv_write_diag(reinterpret_cast<uint8_t*>(data), capacity, &format, tag,
                                   reinterpret_cast<const uint8_t*>(value.data()), value.size(),
                                   &written, diagnostic);
    if (rc != TLV_OK) return unexpected<error>(error::from_c(rc));
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
class writer {
public:
    /**
     * @brief Create a sequential writer from a C++ Format view without allocation.
     * @param buf Borrowed output buffer, null only for zero capacity.
     * @param capacity Writable byte count.
     * @param format Borrowed Format; descriptor and context must outlive this writer.
     * @note The view may be temporary. Subsequent writes report initialization failures.
     */
    writer(byte* buf, size_t capacity, tlv::format format)
        : writer(buf, capacity, detail::format_access::get(format)) {}

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
    writer(byte* buf, size_t capacity, const tlv_format_t& format) {
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
    TLV_NODISCARD expected<void, error> write(tag_t tag, bytes value) {
        tlv_result_t rc = tlv_writer_write(
            &impl_, tag, reinterpret_cast<const uint8_t*>(value.data()), value.size());
        if (rc != TLV_OK) {
            return unexpected<error>(error::from_c(rc));
        }
        return {};
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
    TLV_NODISCARD expected<void, error> write(tag_t tag, bytes value,
                                              writer_diagnostic& out_diagnostic) {
        tlv_result_t rc =
            tlv_writer_write_diag(&impl_, tag, reinterpret_cast<const uint8_t*>(value.data()),
                                  value.size(), &out_diagnostic);
        if (rc != TLV_OK) {
            return unexpected<error>(error::from_c(rc));
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
    TLV_NODISCARD expected<void, error> write(const element&     value,
                                              writer_diagnostic* diagnostic = nullptr) {
        const auto rc = tlv_writer_write_element_diag(&impl_, &value, diagnostic);
        if (rc != TLV_OK) return unexpected<error>(error::from_c(rc));
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
        const auto rc = tlv_writer_copy_encoded_diag(
            &impl_, reinterpret_cast<const uint8_t*>(encoded.data()), encoded.size(), diagnostic);
        if (rc != TLV_OK) return unexpected<error>(error::from_c(rc));
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
    TLV_NODISCARD expected<void, error> preserve(const tlv_source_t& original, const element& value,
                                                 writer_diagnostic* diagnostic = nullptr) {
        const auto rc = tlv_writer_preserve_diag(&impl_, &original, &value, diagnostic);
        if (rc != TLV_OK) return unexpected<error>(error::from_c(rc));
        return {};
    }

private:
    tlv_writer_t impl_{};
};

/** @brief Measure an Element using a C++ Format view.
 * @copydetails encoded_size(const element&, const tlv_format_t&, writer_diagnostic*)
 */
TLV_NODISCARD inline expected<size_t, error> encoded_size(const element& value, tlv::format format,
                                                          writer_diagnostic* diagnostic = nullptr) {
    return encoded_size(value, detail::format_access::get(format), diagnostic);
}

/** @brief Measure a Tag and Value length using a C++ Format view.
 * @copydetails encoded_size(tag_t, size_t, const tlv_format_t&)
 */
TLV_NODISCARD inline expected<size_t, error> encoded_size(tag_t tag, size_t length,
                                                          tlv::format format) {
    return encoded_size(tag, length, detail::format_access::get(format));
}

/** @brief Write an Element using a C++ Format view.
 * @copydetails write(byte*, size_t, const tlv_format_t&, const element&, writer_diagnostic*)
 */
TLV_NODISCARD inline expected<size_t, error> write(byte* data, size_t capacity, tlv::format format,
                                                   const element&     value,
                                                   writer_diagnostic* diagnostic = nullptr) {
    return write(data, capacity, detail::format_access::get(format), value, diagnostic);
}

/** @brief Write a Tag and Value using a C++ Format view.
 * @copydetails write(byte*, size_t, const tlv_format_t&, tag_t, bytes, writer_diagnostic*)
 */
TLV_NODISCARD inline expected<size_t, error> write(byte* data, size_t capacity, tlv::format format,
                                                   tag_t tag, bytes value,
                                                   writer_diagnostic* diagnostic = nullptr) {
    return write(data, capacity, detail::format_access::get(format), tag, value, diagnostic);
}

} // namespace tlv

#endif // OPENTLV_TLVPP_WRITER_HPP
