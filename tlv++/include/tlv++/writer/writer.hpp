#ifndef OPENTLV_TLVPP_WRITER_HPP
#define OPENTLV_TLVPP_WRITER_HPP

#include "tlv/writer/writer.h"
#include "tlv++/types.hpp"

namespace tlv {

/**
 * @file writer.hpp
 * @brief C++ wrapper for sequential writing into a caller-owned buffer.
 */

/** @brief C++ alias for the writer-specific diagnostic type, #tlv_writer_diagnostic_t. */
using writer_diagnostic = tlv_writer_diagnostic_t;

/**
 * @brief Thin C++ wrapper around #tlv_writer_t.
 *
 * Writes elements sequentially into a caller-owned buffer. Successful writes
 * do not allocate; an error result carries a `std::string` message and
 * therefore may allocate.
 *
 * @warning The caller must keep the buffer, format, and format context
 *          alive for the lifetime of the writer.
 */
class writer {
public:
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
    writer(byte* buf, size_t capacity, const tlv_writer_format_t& format) {
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

private:
    tlv_writer_t impl_{};
};

} // namespace tlv

#endif // OPENTLV_TLVPP_WRITER_HPP
