// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_TLVPP_READER_HPP
#define OPENTLV_TLVPP_READER_HPP

#include "tlv/reader/reader.h"
#include "tlv/size.h"
#include "tlv++/types.hpp"
#include "tlv++/format.hpp"
#include "tlv++/format_traits.hpp"
#include "tlv++/detail/visitor.hpp"
#include "tlv/reader/visitor.h"
#include <type_traits>
#include <iterator>

namespace tlv {

/**
 * @file reader.hpp
 * @brief C++ wrapper for sequential zero-copy reading.
 */

/** @brief C++ alias for the reader-specific diagnostic type, #tlv_reader_diagnostic_t. */
using reader_diagnostic = tlv_reader_diagnostic_t;
/** @brief Reader-specific evidence without common diagnostic metadata. */
using reader_detail = tlv_reader_detail_t;

/** @brief Wire field being read when a Reader failed. */
enum class reader_phase {
    tag = TLV_READER_OP_TAG,         /**< Identifier field. */
    length = TLV_READER_OP_LENGTH,   /**< Length field. */
    value = TLV_READER_OP_VALUE,     /**< Value bytes. */
    trailer = TLV_READER_OP_TRAILER, /**< Closing framing. */
    header = TLV_READER_OP_HEADER    /**< Complete header. */
};
/** @brief Reader phase in an existing diagnostic. */
inline reader_phase phase(const reader_detail& value) noexcept {
    return static_cast<reader_phase>(value.operation);
}
/** @brief Apply phase to the Reader-specific part of a complete diagnostic. */
inline reader_phase phase(const reader_diagnostic& value) noexcept {
    return phase(value.detail);
}
/** @brief Immutable program-lifetime Reader phase name. */
inline const char* message(reader_phase value) noexcept {
    return tlv_reader_operation_string(static_cast<tlv_reader_operation_t>(value));
}
/** @brief Borrow a Reader diagnostic's identifier, or an absent identifier. */
inline tlv::tag diagnostic_tag(const reader_detail& value) noexcept {
    return value.has_tag ? detail::semantic_access::borrow(value.tag) : tlv::tag{};
}
/** @brief Apply diagnostic_tag to the Reader-specific part of a complete diagnostic. */
inline tlv::tag diagnostic_tag(const reader_diagnostic& value) noexcept {
    return diagnostic_tag(value.detail);
}
/** @brief Attach a borrowed identifier to a Reader diagnostic. */
inline void set_tag(reader_detail& value, tlv::tag identifier) noexcept {
    value.tag = detail::semantic_access::get(identifier);
    value.has_tag = 1;
}
/** @brief Apply set_tag to the Reader-specific part of a complete diagnostic. */
inline void set_tag(reader_diagnostic& value, tlv::tag identifier) noexcept {
    set_tag(value.detail, identifier);
}
/** @brief Borrow original Length octets, or an empty view when unavailable. */
inline bytes raw_length(const reader_detail& value) noexcept {
    return value.has_raw_length
               ? bytes(reinterpret_cast<const byte*>(value.raw_length.data), value.raw_length.size)
               : bytes{};
}
/** @brief Apply raw_length to the Reader-specific part of a complete diagnostic. */
inline bytes raw_length(const reader_diagnostic& value) noexcept {
    return raw_length(value.detail);
}
/// @cond INTERNAL
namespace detail {
inline error reader_failed(tlv_result_t code, const reader_diagnostic& diagnostic,
                           size_t /*offset*/) noexcept {
    return diagnostic.diagnostic.code == code
               ? error_access::diagnostic(diagnostic.diagnostic, operation::reader,
                                          diagnostic.detail.has_tag ? &diagnostic.detail.tag
                                                                    : nullptr)
               : error::from_c(code).during(operation::reader);
}
} // namespace detail
/// @endcond

/**
 * @brief Exception raised by Reader iteration on any outcome other than final EOF.
 *
 * Successful iteration allocates nothing. Constructing this exception may allocate.
 * Diagnostic byte views borrow input and Format storage, which must outlive their use.
 */
class parse_error : public std::runtime_error {
public:
    /** @brief Retain the original Reader failure and the failing element's absolute offset.
     * @param code Original C result, including NEED_MORE_DATA.
     * @param offset Absolute offset of the unconsumed element.
     * @param diagnostic Original C Reader detail; any byte views remain borrowed.
     */
    parse_error(tlv_result_t code, size_t offset, reader_diagnostic diagnostic)
        : std::runtime_error(tlv_strerror(code)), code_(code), offset_(offset),
          diagnostic_(diagnostic) {}
    /** @brief Original C Reader result code. */
    tlv_result_t code() const noexcept {
        return code_;
    }
    /** @brief Canonical C++ status matching pull-based Reader errors. */
    errc status() const noexcept {
        return static_cast<errc>(code_);
    }
    /** @brief Copy the common structured failure without allocating. */
    tlv::error failure() const noexcept {
        return detail::reader_failed(code_, diagnostic_, offset_);
    }
    /** @brief Absolute offset of the element whose read failed. */
    size_t offset() const noexcept {
        return offset_;
    }
    /** @brief Original Reader diagnostic, including the failing field's offset when known. */
    const reader_diagnostic& diagnostic() const noexcept {
        return diagnostic_;
    }

private:
    tlv_result_t      code_;
    size_t            offset_;
    reader_diagnostic diagnostic_;
};

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
TLV_NODISCARD inline expected<decoded, error> read(bytes data, tlv::format format, size_t& consumed,
                                                   reader_diagnostic* diagnostic = nullptr) {
    tlv_decoded_t     result{};
    reader_diagnostic local{};
    auto*             report = diagnostic ? diagnostic : &local;
    auto rc = tlv_read_source_diag(reinterpret_cast<const uint8_t*>(data.data()), data.size(),
                                   &detail::format_access::get(format), &result.element, &consumed,
                                   &result.source, report);
    if (rc != TLV_OK) return unexpected<error>(detail::reader_failed(rc, *report, 0));
    return decoded{detail::semantic_access::borrow(result.element), result.source};
}

/**
 * @brief Thin, safe C++ wrapper around #tlv_reader_t.
 *
 * Reads elements sequentially without copying value bytes. Successful reads
 * and returned errors do not allocate. Error descriptions have static lifetime.
 *
 * @warning The caller must keep the buffer, format, and format context
 *          alive for the lifetime of the reader and of any element it returns.
 * @see @docs{guides/memory,format context ownership and lifetime}
 */
namespace detail {
class reader_iterator;
template <typename F> class parsing_range;
class reader_base {
public:
    /** @brief C++11 single-pass input iterator yielding borrowed Element views. */
    using iterator = reader_iterator;
    /**
     * @brief Consume and publish the next element at the current cursor position.
     * @return Input iterator, or end() only on genuine final EOF.
     * @throws parse_error On initialization, decoding or incremental-input failure.
     * @note Each begin() consumes another element; it never rewinds. break leaves
     * the published element consumed. Only one traversal may be active at a time.
     * @warning Advancing any iterator invalidates its other copies. Explicit next(),
     * next_source(), visit(), successful set_input(), and cursor destruction invalidate
     * active iterators. Input and Format storage must outlive retained Element views.
     */
    iterator begin();
    /** @brief Return the end iterator without parsing or changing the cursor. */
    iterator end() const noexcept;
    /**
     * @brief Create a sequential reader from a C++ Format view without allocation.
     * @param data Encoded input, borrowed.
     * @param format Borrowed Format; its descriptor and context must outlive this cursor and
     * results.
     * @param mode Whether this window is final or accepts incremental continuation.
     * @note The view object may be temporary. Initialization errors are reported by next().
     */
    reader_base(bytes data, tlv::format format, input_mode mode = input_mode::final)
        : reader_base(data, detail::format_access::get(format), mode) {}

    /**
     * @brief Creates a reader over a buffer.
     *
     * Invalid buffers or missing format callbacks are not reported here;
     * they prevent reading, so at_end() returns `false` and next() returns an
     * error.
     *
     * @param data   Encoded input; borrowed.
     * @param format Reader format; borrowed.
     * @param mode Whether this window is final or accepts incremental continuation.
     */
    reader_base(bytes data, const tlv_format_t& format, input_mode mode = input_mode::final) {
        auto init = mode == input_mode::final ? tlv_reader_init : tlv_reader_init_incremental;
        tlv_result_t rc =
            init(&impl_, reinterpret_cast<const uint8_t*>(data.data()), data.size(), &format);
        // Invalid buffers or missing format callbacks prevent reading.
        init_ok_ = (rc == TLV_OK);
    }

    /**
     * @brief Reports whether the reader has consumed all input.
     *
     * @return `true` only at a successfully initialized final input boundary.
     * Initialization failure and exhausted incremental input are not clean EOF;
     * next() reports their distinct outcomes.
     */
    TLV_NODISCARD bool at_end() const {
        return init_ok_ && tlv_reader_at_end(&impl_) != 0;
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
    TLV_NODISCARD expected<element_view, error> next() {
        // The C cursor initializes diagnostics on every failure; success never reads them.
        reader_diagnostic diagnostic;
        return next(diagnostic);
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
    TLV_NODISCARD expected<element_view, error> next(reader_diagnostic& out_diagnostic) {
        if (!init_ok_) {
            return unexpected<error>(error::from_c(TLV_ERR_NULL_ARG));
        }

        tlv_element_t raw{};
        tlv_result_t  rc = tlv_reader_next_diag(&impl_, &raw, &out_diagnostic);
        if (rc != TLV_OK) {
            return unexpected<error>(detail::reader_failed(rc, out_diagnostic, offset()));
        }

        return detail::semantic_access::borrow(raw);
    }

    /**
     * @brief Read an element with source ranges in the same decode.
     * @param[out] diagnostic Optional failure detail; unchanged on success.
     * @return Borrowed element and source, or the same outcomes as next().
     * @note NEED_MORE_DATA preserves the cursor and permits set_input() then retry.
     */
    TLV_NODISCARD expected<decoded, error> next_source(reader_diagnostic* diagnostic = nullptr) {
        if (!init_ok_) return unexpected<error>(error::from_c(TLV_ERR_NULL_ARG));
        tlv_decoded_t     result{};
        reader_diagnostic local{};
        auto*             report = diagnostic ? diagnostic : &local;
        auto rc = tlv_reader_next_source_diag(&impl_, &result.element, &result.source, report);
        if (rc != TLV_OK) return unexpected<error>(detail::reader_failed(rc, *report, offset()));
        return decoded{detail::semantic_access::borrow(result.element), result.source};
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
        detail::element_visitor<Visitor> context{&visitor};
        auto rc = tlv_reader_visit_diag(&impl_, &detail::element_visitor<Visitor>::call, &context,
                                        diagnostic);
        if (rc != TLV_OK) return unexpected<error>(error::from_c(rc));
        return {};
    }

private:
    bool read_for_iteration(element_view& element) {
        // Only the cursor's final boundary is EOF. A callback returning END_OF_BUFFER
        // inside nonempty input remains an error.
        if (init_ok_ && at_end()) return false;
        reader_diagnostic diagnostic;
        tlv_element_t     raw{};
        const auto        position = offset();
        const auto        rc =
            init_ok_ ? tlv_reader_next_diag(&impl_, &raw, &diagnostic) : TLV_ERR_NULL_ARG;
        if (rc != TLV_OK) {
            if (!init_ok_) {
                diagnostic = {};
                diagnostic.diagnostic.code = rc;
                diagnostic.diagnostic.severity = TLV_DIAGNOSTIC_SEVERITY_ERROR;
                diagnostic.detail.operation = TLV_READER_OP_HEADER;
            }
            throw parse_error(rc, position, diagnostic);
        }
        element = detail::semantic_access::borrow(raw);
        return true;
    }
    tlv_reader_t impl_{};
    bool         init_ok_ = false;
    friend class reader_iterator;
    template <typename F> friend class parsing_range;
};

/// @cond INTERNAL
class reader_iterator {
public:
    using iterator_category = std::input_iterator_tag;
    using value_type = element_view;
    using difference_type = std::ptrdiff_t;
    using pointer = const element_view*;
    using reference = const element_view&;

    reader_iterator() noexcept = default;
    explicit reader_iterator(reader_base& cursor) : cursor_(&cursor) {
        advance();
    }
    reference operator*() const noexcept {
        return element_;
    }
    pointer operator->() const noexcept {
        return &element_;
    }
    reader_iterator& operator++() {
        advance();
        return *this;
    }
    reader_iterator operator++(int) {
        auto previous = *this;
        advance();
        return previous;
    }
    friend bool operator==(const reader_iterator& lhs, const reader_iterator& rhs) noexcept {
        return lhs.cursor_ == rhs.cursor_ && (!lhs.cursor_ || lhs.position_ == rhs.position_);
    }
    friend bool operator!=(const reader_iterator& lhs, const reader_iterator& rhs) noexcept {
        return !(lhs == rhs);
    }

private:
    void advance() {
        auto* cursor = cursor_;
        cursor_ = nullptr;
        if (cursor->read_for_iteration(element_)) {
            position_ = cursor->offset();
            cursor_ = cursor;
        }
    }
    reader_base* cursor_ = nullptr;
    element_view element_{};
    size_t       position_ = 0;
};

inline reader_base::iterator reader_base::begin() {
    return iterator(*this);
}
inline reader_base::iterator reader_base::end() const noexcept {
    return iterator();
}

// Own configuration inline and rebuild all internal addresses when returned by value
// in C++11, including builds with copy elision disabled. Moving invalidates iterators
// and any views borrowing the old configuration; input-backed views remain borrowed.
template <typename F> class parsing_range {
    static_assert(format_capabilities<F>::valid && format_capabilities<F>::readable,
                  "parse requires a valid readable Format");

public:
    parsing_range(bytes data, F value)
        : value_(std::move(value)), descriptor_(descriptor_bridge<F>::make(value_)),
          cursor_(data, descriptor_) {}
    parsing_range(parsing_range&& other)
        : value_(std::move(other.value_)), descriptor_(descriptor_bridge<F>::make(value_)),
          cursor_(other.cursor_) {
        cursor_.impl_.format = &descriptor_;
        other.cursor_.init_ok_ = false;
    }
    parsing_range(const parsing_range&) = delete;
    parsing_range&  operator=(const parsing_range&) = delete;
    parsing_range&  operator=(parsing_range&&) = delete;
    reader_iterator begin() {
        return cursor_.begin();
    }
    reader_iterator end() const noexcept {
        return cursor_.end();
    }

private:
    F                  value_;
    const tlv_format_t descriptor_;
    reader_base        cursor_;
};
/// @endcond
} // namespace detail

/** @brief Generic sequential reader using the canonical C engine.
 * @tparam F C++ Format implementing format_traits; format selects a borrowed runtime view.
 * @details Supports consuming, single-pass C++11 iteration over element_view.
 * Only final EOF ends iteration; other outcomes throw parse_error. Explicit
 * cursor operations retain expected-based error handling.
 * @warning For typed Formats this cursor owns a stable adapter and cannot be copied
 * or moved. It and all Format-borrowed storage must outlive retained results.
 */
template <typename F = tlv::format>
class reader : private format_adapter<F>, public detail::reader_base {
    static_assert(format_capabilities<F>::readable, "reader requires a readable Format");

public:
    /** @brief Initialize with default-constructed Format configuration.
     * @param data Borrowed input.
     * @param mode Final or incremental input.
     */
    explicit reader(bytes data, input_mode mode = input_mode::final)
        : format_adapter<F>(), detail::reader_base(data, format_adapter<F>::view(), mode) {}
    /** @brief Initialize the cursor, owning immutable Format configuration.
     * @param data Borrowed input.
     * @param mode Final or incremental input.
     * @param value Format configuration copied or moved into stable storage.
     */
    explicit reader(bytes data, F value, input_mode mode = input_mode::final)
        : format_adapter<F>(std::move(value)),
          detail::reader_base(data, format_adapter<F>::view(), mode) {}
};
/** @brief Iterable runtime Format cursor; descriptor and context remain borrowed.
 * @details Iteration follows reader::begin(); explicit cursor operations retain
 * expected-based error handling.
 */
template <> class reader<tlv::format> : public detail::reader_base {
public:
    /** @brief Initialize from a borrowed C++ Format; explicit C interoperability uses
     * native::borrow_format(). */
    reader(bytes data, tlv::format format, input_mode mode = input_mode::final)
        : detail::reader_base(data, format, mode) {}
};

/**
 * @brief Create an allocation-free single-pass parsing range owning Format configuration.
 * @tparam F Readable C++ Format; deduced from the configuration argument.
 * @param data Immutable borrowed input, treated as final.
 * @param value Format configuration copied or moved into the range.
 * @return Move-constructible range yielding element_view through the canonical C Reader.
 * @throws parse_error During iteration on any failure; only final EOF ends the range.
 * @note Format construction or movement may allocate if F does. Range machinery and
 * successful iteration do not allocate or copy Value bytes. begin() consumes from
 * the current position, with the same single-pass rules as reader::begin().
 * @warning Input and storage borrowed by F must outlive retained results. The range
 * must also outlive views borrowing its owned Format. Moving it invalidates iterators
 * and views borrowing its previous Format storage. No copy or assignment is provided.
 */
template <typename F> TLV_NODISCARD detail::parsing_range<F> parse(bytes data, F value) {
    return detail::parsing_range<F>(data, std::move(value));
}

/** @brief Parse final input with default-constructed Format configuration.
 * @tparam F Readable, default-constructible C++ Format.
 * @param data Immutable borrowed final input.
 * @return Single-pass range with the ownership and error rules of parse(bytes, F).
 */
template <typename F> TLV_NODISCARD detail::parsing_range<F> parse(bytes data) {
    return tlv::parse(data, F{});
}

} // namespace tlv

#endif // OPENTLV_TLVPP_READER_HPP
