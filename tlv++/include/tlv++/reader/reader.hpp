#ifndef OPENTLV_TLVPP_READER_HPP
#define OPENTLV_TLVPP_READER_HPP

#include "tlv/reader/reader.h"
#include "tlv/size.h"
#include "tlv++/types.hpp"
#include "tlv++/format.hpp"
#include "tlv/reader/visitor.h"
#include <type_traits>

namespace tlv {

/**
 * @file reader.hpp
 * @brief C++ wrapper for sequential zero-copy reading.
 */

/** @brief C++ alias for the reader-specific diagnostic type, #tlv_reader_diagnostic_t. */
using reader_diagnostic = tlv_reader_diagnostic_t;

/** @brief Whether the supplied input window declares final EOF. */
enum class input_mode {
    final,      /**< No more input will follow this window. */
    incremental /**< More input may be supplied after NEED_MORE_DATA. */
};

/**
 * @brief Read one complete element with its source ranges and optional diagnostics.
 * @param data Immutable borrowed input.
 * @param format Borrowed readable format and context.
 * @param[out] consumed Encoded byte count; unchanged on failure.
 * @param[out] diagnostic Optional Reader detail; unchanged on success.
 * @return Decoded element and source, or the original C Reader error.
 * @warning Input and Format storage must outlive the returned borrowed views.
 */
TLV_NODISCARD inline expected<decoded, error> read(bytes data, const tlv_format_t& format,
                                                   size_t&            consumed,
                                                   reader_diagnostic* diagnostic = nullptr) {
    decoded result{};
    auto rc = tlv_read_source_diag(reinterpret_cast<const uint8_t*>(data.data()), data.size(),
                                   &format, &result.element, &consumed, &result.source, diagnostic);
    if (rc != TLV_OK) return unexpected<error>(error::from_c(rc));
    return result;
}

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
     * @param mode Whether this window is final or accepts incremental continuation.
     */
    reader(bytes data, const tlv_format_t& format, input_mode mode = input_mode::final) {
        auto init = mode == input_mode::final ? tlv_reader_init : tlv_reader_init_incremental;
        tlv_result_t rc =
            init(&impl_, reinterpret_cast<const uint8_t*>(data.data()), data.size(), &format);
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

    /**
     * @brief Read an element with source ranges in the same decode.
     * @param[out] diagnostic Optional failure detail; unchanged on success.
     * @return Borrowed element and source, or the same outcomes as next().
     * @note NEED_MORE_DATA preserves the cursor and permits set_input() then retry.
     */
    TLV_NODISCARD expected<decoded, error> next_source(reader_diagnostic* diagnostic = nullptr) {
        if (!init_ok_) return unexpected<error>(error::from_c(TLV_ERR_NULL_ARG));
        decoded result{};
        auto rc = tlv_reader_next_source_diag(&impl_, &result.element, &result.source, diagnostic);
        if (rc != TLV_OK) return unexpected<error>(error::from_c(rc));
        return result;
    }

    /**
     * @brief Replace the borrowed input window while preserving absolute offsets.
     * @param data Replacement window retaining undiscarded bytes unchanged.
     * @param discard Consumed prefix to discard, at most consumed().
     * @param mode Whether the replacement declares final EOF.
     * @return Success or the original C error; failure preserves state.
     * @warning Release borrowed views before moving or overwriting their storage.
     * @see tlv_reader_set_input
     */
    TLV_NODISCARD expected<void, error> set_input(bytes data, size_t discard, input_mode mode) {
        auto rc = init_ok_
                      ? tlv_reader_set_input(&impl_, reinterpret_cast<const uint8_t*>(data.data()),
                                             data.size(), discard, mode == input_mode::final)
                      : TLV_ERR_NULL_ARG;
        if (rc != TLV_OK) return unexpected<error>(error::from_c(rc));
        return {};
    }

    /** @brief Discardable prefix byte count; retained views may still borrow it. */
    TLV_NODISCARD size_t consumed() const {
        return tlv_reader_consumed(&impl_);
    }

    /** @brief Absolute offset of the next element. */
    TLV_NODISCARD size_t offset() const {
        return tlv_reader_offset(&impl_);
    }

    /**
     * @brief Visit remaining elements through the C Visitor engine.
     * @param visitor Callable taking an Element and returning tlv_visit_result_t.
     * @param[out] diagnostic Optional detail, cleared at entry for a valid cursor.
     * @return Success on EOF or STOP; NEED_MORE_DATA or an original C error otherwise.
     * @warning Do not mutate the cursor, input or Format in the callback. Effects
     * are not rolled back; the current element is consumed before the callback.
     * @see tlv_reader_visit_diag
     */
    template <typename Visitor>
    TLV_NODISCARD expected<void, error> visit(Visitor&&          visitor,
                                              reader_diagnostic* diagnostic = nullptr) {
        if (!init_ok_) return unexpected<error>(error::from_c(TLV_ERR_NULL_ARG));
        using callable = typename std::remove_reference<Visitor>::type;
        struct state {
            callable* function;
        } context{&visitor};
        auto callback = [](const tlv_element_t* value, void* context) -> tlv_visit_result_t {
            return (*static_cast<state*>(context)->function)(*value);
        };
        auto rc = tlv_reader_visit_diag(&impl_, callback, &context, diagnostic);
        if (rc != TLV_OK) return unexpected<error>(error::from_c(rc));
        return {};
    }

private:
    tlv_reader_t impl_{};
    bool         init_ok_ = false;
};

} // namespace tlv

#endif // OPENTLV_TLVPP_READER_HPP
