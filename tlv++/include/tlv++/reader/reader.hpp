#ifndef OPENTLV_TLVPP_READER_HPP
#define OPENTLV_TLVPP_READER_HPP

#include "tlv/reader/reader.h"
#include "tlv/size.h"
#include "tlv++/types.hpp"

namespace tlv {

/**
 * @file reader.hpp
 * @brief C++ wrapper for sequential zero-copy reading.
 */

/** @brief C++ alias for the reader-specific diagnostic type, #tlv_reader_diagnostic_t. */
using reader_diagnostic = tlv_reader_diagnostic_t;

/**
 * @brief Thin, safe C++ wrapper around #tlv_reader_t.
 *
 * Reads elements sequentially without copying value bytes. Successful reads
 * do not allocate; an error result carries a `std::string` message and
 * therefore may allocate.
 *
 * @warning The caller must keep the buffer, format, and format context
 *          alive for the lifetime of the reader and of any element it returns.
 * @see @docs{guides/memory,format context ownership and lifetime}
 */
class reader {
public:
    /**
     * @brief Creates a reader over a buffer.
     *
     * Invalid buffers or missing format callbacks are not reported here;
     * they prevent reading, so at_end() returns `true` and next() returns an
     * error.
     *
     * @param data   Encoded input; borrowed.
     * @param format Reader format; borrowed.
     */
    reader(bytes data, const tlv_format_t& format) {
        tlv_result_t rc = tlv_reader_init(&impl_, reinterpret_cast<const uint8_t*>(data.data()),
                                          data.size(), &format);
        // Invalid buffers or missing format callbacks prevent reading.
        init_ok_ = (rc == TLV_OK);
    }

    /**
     * @brief Reports whether the reader has consumed all input.
     *
     * @return `true` if no further elements exist, or if the reader failed
     *         to initialize.
     */
    TLV_NODISCARD bool at_end() const {
        return !init_ok_ || tlv_reader_at_end(&impl_) != 0;
    }

    /**
     * @brief Reads the next element and advances the reader.
     *
     * The returned element's value borrows the original buffer.
     *
     * @return The next element, or an error: #TLV_ERR_NULL_ARG if the reader
     *         failed to initialize, #TLV_ERR_END_OF_BUFFER when no further
     *         element exists, or any error of tlv_reader_next().
     *
     * @note On error the reader position is unchanged.
     */
    TLV_NODISCARD expected<element, error> next() {
        if (!init_ok_) {
            return unexpected<error>(error::from_c(TLV_ERR_NULL_ARG));
        }

        tlv_element_t raw{};
        tlv_result_t  rc = tlv_reader_next(&impl_, &raw);
        if (rc != TLV_OK) {
            return unexpected<error>(error::from_c(rc));
        }

        return raw;
    }

    /**
     * @brief Reads the next element and advances the reader, with diagnostic detail on failure.
     *
     * Behaves like next(), and additionally fills `out_diagnostic` when the
     * read fails; wraps tlv_reader_next_diag().
     *
     * @param[out] out_diagnostic Receives detail on failure; left unchanged on success.
     *
     * @return Same as next().
     */
    TLV_NODISCARD expected<element, error> next(reader_diagnostic& out_diagnostic) {
        if (!init_ok_) {
            return unexpected<error>(error::from_c(TLV_ERR_NULL_ARG));
        }

        tlv_element_t raw{};
        tlv_result_t  rc = tlv_reader_next_diag(&impl_, &raw, &out_diagnostic);
        if (rc != TLV_OK) {
            return unexpected<error>(error::from_c(rc));
        }

        return raw;
    }

private:
    tlv_reader_t impl_{};
    bool         init_ok_ = false;
};

} // namespace tlv

#endif // OPENTLV_TLVPP_READER_HPP
