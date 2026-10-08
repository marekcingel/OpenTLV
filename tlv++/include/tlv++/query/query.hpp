// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_TLVPP_QUERY_HPP
#define OPENTLV_TLVPP_QUERY_HPP
#include <type_traits>
#include <iterator>
#include "tlv++/types.hpp"
#include "tlv/size.h"
#include "tlv/query/query.h"
#include "tlv++/reader/tree.hpp"

/**
 * @file query.hpp
 * @brief C++ wrapper for path queries over TLV data.
 */

namespace tlv {
class query_range;
/// @cond INTERNAL
namespace detail {
struct query_access;
}
/// @endcond

/** @brief Query compilation failure with the original C error and text offset. */
class query_error : public std::runtime_error {
public:
    /** @brief Retain compilation error code and offending text position. */
    query_error(tlv_result_t code, tlv_diagnostic_t diagnostic)
        : std::runtime_error(tlv_strerror(code)), code_(code), diagnostic_(diagnostic) {
        diagnostic_.code = code;
    }
    /** @brief Original C compilation result. */
    tlv_result_t code() const noexcept {
        return code_;
    }
    /** @brief Canonical C++ status matching nonthrowing Query parsing. */
    errc status() const noexcept {
        return static_cast<errc>(code_);
    }
    /** @brief Copy the common structured failure without allocating. */
    tlv::error failure() const noexcept {
        return detail::error_access::diagnostic(diagnostic_, operation::query);
    }
    /** @brief Zero-based offending character or tag position. */
    size_t offset() const noexcept {
        return diagnostic_.location.begin;
    }
    /** @brief Primary expression evidence, or unknown when no text position is available. */
    tlv_location_t location() const noexcept {
        return diagnostic_.location;
    }

private:
    tlv_result_t     code_;
    tlv_diagnostic_t diagnostic_;
};
/**
 * @brief A parsed path query such as `6F/A5/50`.
 *
 * Wraps #tlv_query_t; the query language is described in
 * tlv/query/query.h. The object is a small self-contained value; it never
 * allocates and does not refer to the text it was parsed from.
 */
class query {
public:
    /** @brief Compile a path, throwing query_error on failure.
     * @param text NUL-terminated path; not retained.
     * @return Self-contained compiled Query.
     */
    static query compile(const char* text) {
        tlv_diagnostic_t diagnostic{};
        auto             result = parse(text, &diagnostic);
        if (!result) throw query_error(result.error().code, diagnostic);
        return *result;
    }

    /** @brief Select matches from a Tree Reader starting at a tree boundary.
     * @param reader Borrowed cursor, which must outlive the range and iterators.
     * @return Allocation-free single-pass range owning a copy of this Query.
     * @warning Do not interleave other cursor operations except set_input() after
     * NEED_MORE_DATA. Input and Format storage must outlive retained results.
     */
    query_range select(tree_reader& reader) const;
    /**
     * @brief Parses the text of a query.
     *
     * Wraps tlv_query_parse().
     *
     * @param text         NUL-terminated query text.
     * @param diagnostic Optional. On failure receives the index in `text` of
     *                     the offending character; see tlv_query_parse().
     *
     * @return The query, or the error of tlv_query_parse().
     */
    TLV_NODISCARD static expected<query, error> parse(const char*       text,
                                                      tlv_diagnostic_t* diagnostic = nullptr) {
        tlv_diagnostic_t local{};
        if (!diagnostic) diagnostic = &local;
        query        result;
        tlv_result_t rc = tlv_query_parse(text, &result.query_, diagnostic);
        if (rc != TLV_OK) {
            diagnostic->code = rc;
            return unexpected<error>(
                detail::error_access::diagnostic(*diagnostic, operation::query));
        }
        return result;
    }

    /** @brief Number of tags in the query, which is the depth of the addressed elements plus one.
     */
    size_t size() const {
        return tlv_query_count(&query_);
    }

    /** @brief Return the canonical path spelling in an owning string.
     * @return Uppercase identifiers joined by slashes; allocates result storage.
     */
    std::string format() const {
        size_t required = 0;
        tlv_query_format(&query_, nullptr, 0, &required);
        std::string result(required, '\0');
        if (required) {
            tlv_query_format(&query_, &result[0], required, &required);
            result.resize(required - 1);
        }
        return result;
    }

    /**
     * @brief Return the tag at a zero-based query step, or an empty tag out of range.
     * @warning The returned bytes borrow this query and must not outlive it.
     */
    tlv::tag step(size_t index) const& {
        return detail::semantic_access::borrow(tlv_query_step(&query_, index));
    }
    /** @brief Reject identifier views into a temporary Query. */
    tlv::tag step(size_t) const&& = delete;

private:
    const tlv_query_t& c_query() const {
        return query_;
    }
    friend class query_range;
    friend class query_matcher;
    friend class document;
    friend struct detail::query_access;

public:
    /**
     * @brief Calls a visitor for every element the query addresses.
     *
     * Wraps tlv_query_visit_buffer(): elements are visited in document order and the
     * rules for limits, offsets and errors are the same. Nothing is allocated
     * and the entries passed to the visitor borrow `data`.
     *
     * @tparam Visitor Callable invoked as `visitor(element_view, depth, absolute_offset)`
     *                 returning #tlv_visit_result_t, as for tree_reader::visit().
     *
     * @param data          Encoded input; borrowed.
     * @param format        Reader format. A `nullptr` `format.is_constructed`
     *                      treats every value as opaque, in which case only
     *                      one-tag queries can match.
     * @param max_depth     Runtime depth limit; the convenience API owns TLV_QUERY_MAX_STEPS
     * frames.
     * @param max_elements  Bound on all traversed elements.
     * @param visitor       Visitor callable; returning #TLV_VISIT_STOP succeeds
     *                      immediately, #TLV_VISIT_ERROR fails.
     * @param diagnostic  Optional. On failure receives the failing element's
     *                      absolute offset; unchanged on success.
     *
     * @return Success, also when nothing matched, or the error of tlv_query_visit_buffer().
     *
     * @warning Visitor side effects are not rolled back on error.
     */
    template <typename Visitor>
    TLV_NODISCARD expected<void, error>
    visit_buffer(bytes data, tlv::format format, size_t max_depth, size_t max_elements,
                 Visitor&& visitor, tlv_reader_diagnostic_t* diagnostic = nullptr) const {
        tlv_reader_diagnostic_t local{};
        if (!diagnostic) diagnostic = &local;
        detail::tree_visitor<Visitor> state{&visitor};
        tlv_result_t                  rc = tlv_query_visit_buffer(
            reinterpret_cast<const uint8_t*>(data.data()), data.size(),
            &detail::format_access::get(format), &query_, max_depth, max_elements,
            &detail::tree_visitor<Visitor>::call, &state, diagnostic);
        if (rc != TLV_OK) {
            diagnostic->diagnostic.code = rc;
            return unexpected<error>(
                detail::error_access::diagnostic(diagnostic->diagnostic, operation::query));
        }
        return {};
    }

private:
    query() : query_() {}
    tlv_query_t query_;
};

/// @cond INTERNAL
namespace detail {
struct query_access {
    static const tlv_query_t& get(const query& value) {
        return value.c_query();
    }
};
} // namespace detail
/// @endcond

/** @brief Lazy single-pass Query results yielding normal tree_item records.
 * @note next() preserves matching state across NEED_MORE_DATA. Only final EOF
 * ends iteration; other outcomes throw parse_error from begin() or increment.
 * Moving the range invalidates its iterators. Range, Reader, frames, input and
 * Format must outlive their respective borrowed uses. Successful pulls allocate
 * nothing. Query matching is performed entirely by the C engine.
 */
class query_range {
public:
    /** @brief Create a selection owning its Query and borrowing its Tree Reader. */
    query_range(tree_reader& reader, const query& pattern)
        : reader_(&reader), query_(pattern.c_query()) {
        tlv_query_matcher_init(&matcher_, &query_);
    }
    /** @brief Transfer continuation state and invalidate source iterators. */
    query_range(query_range&& other) noexcept
        : reader_(other.reader_), query_(other.query_), matcher_(other.matcher_) {
        tlv_query_matcher_rebind(&matcher_, &query_);
        other.reader_ = nullptr;
        ++other.generation_;
    }
    /** @brief Copying would share a mutable Reader cursor and is prohibited. */
    query_range(const query_range&) = delete;
    /** @brief Assignment is prohibited while a selection borrows its cursor. */
    query_range& operator=(const query_range&) = delete;
    /** @brief Move assignment is prohibited; construct a new selection instead. */
    query_range& operator=(query_range&&) = delete;

    /** @brief Pull the next match, or original Reader error including NEED_MORE_DATA.
     * @param diagnostic Optional original Reader diagnostic.
     * @return Matching tree_item or END_OF_BUFFER at final exhaustion.
     * @note Feed replacement input to the Reader before retrying NEED_MORE_DATA.
     * Every pull invalidates earlier iterators. No unmatched ancestors are skipped.
     */
    expected<tree_item, error> next(reader_diagnostic* diagnostic = nullptr) {
        tree_item item{};
        auto      rc = pull(item, diagnostic);
        if (rc != TLV_OK) return unexpected<error>(error::from_c(rc));
        return item;
    }

    /** @brief C++11 input iterator; advancing invalidates other iterator copies. */
    class iterator {
    public:
        /** @cond INTERNAL */
        using iterator_category = std::input_iterator_tag;
        using value_type = tree_item;
        using difference_type = std::ptrdiff_t;
        using pointer = const tree_item*;
        using reference = const tree_item&;
        /** @endcond */
        /** @brief Construct the end iterator. */
        iterator() = default;
        /** @brief Read the current match; the iterator must be valid. */
        reference operator*() const {
            return current_;
        }
        /** @brief Access the current match; the iterator must be valid. */
        pointer operator->() const {
            return &current_;
        }
        /** @brief Pull the next match; throw parse_error except at final EOF. */
        iterator& operator++() {
            if (active())
                advance();
            else
                range_ = nullptr;
            return *this;
        }
        /** @brief Pull the next match and return its predecessor's borrowed record. */
        iterator operator++(int) {
            auto old = *this;
            ++*this;
            return old;
        }
        /** @brief Compare single-pass positions; invalidated copies equal end. */
        friend bool operator==(const iterator& a, const iterator& b) {
            return a.active() == b.active();
        }
        /** @brief Compare single-pass positions. */
        friend bool operator!=(const iterator& a, const iterator& b) {
            return !(a == b);
        }

    private:
        explicit iterator(query_range& range) : range_(&range) {
            advance();
        }
        query_range* active() const {
            return range_ && generation_ == range_->generation_ ? range_ : nullptr;
        }
        void advance() {
            if (!range_) return;
            reader_diagnostic diagnostic{};
            auto              code = range_->pull(current_, &diagnostic);
            generation_ = range_->generation_;
            if (code != TLV_OK) {
                auto offset = range_->reader_ ? range_->reader_->offset() : 0;
                range_ = nullptr;
                if (code != TLV_ERR_END_OF_BUFFER) throw parse_error(code, offset, diagnostic);
                return;
            }
        }
        query_range* range_ = nullptr;
        size_t       generation_ = 0;
        tree_item    current_{};
        friend class query_range;
    };
    /** @brief Consume through the next match; throw parse_error on non-EOF failure. */
    iterator begin() {
        return iterator(*this);
    }
    /** @brief Return end without consuming input. */
    iterator end() const noexcept {
        return iterator();
    }

private:
    tlv_result_t pull(tree_item& item, reader_diagnostic* diagnostic) {
        ++generation_;
        if (!reader_) return TLV_ERR_INVALID_ARG;
        for (;;) {
            auto rc = reader_->next_item(item, diagnostic);
            if (rc != TLV_OK) return rc;
            auto tag = detail::semantic_access::get(item.element.tag());
            if (tlv_query_matcher_visit(&matcher_, &tag, item.depth)) return TLV_OK;
        }
    }
    tree_reader*        reader_;
    tlv_query_t         query_;
    tlv_query_matcher_t matcher_{};
    size_t              generation_ = 0;
};

inline query_range query::select(tree_reader& reader) const {
    return query_range(reader, *this);
}

inline query_range tree_reader::select(const query& pattern) {
    return pattern.select(*this);
}

inline query_range tree_reader::select(const char* text) {
    return query::compile(text).select(*this);
}

/**
 * @brief Resumable C Query matcher owning a copy of its parsed query.
 * @note Match state survives Visitor STOP and incremental input replacement.
 * No processing semantics are implemented outside the C Query engine.
 */
class query_matcher {
public:
    /** @brief Start matching a new traversal using an owned copy of the query. */
    explicit query_matcher(const query& pattern) : query_(pattern.c_query()) {
        init_result_ = tlv_query_matcher_init(&impl_, &query_);
    }
    /** @brief Copying would invalidate the native matcher's owned-query reference. */
    query_matcher(const query_matcher&) = delete;
    /** @brief Assignment is prohibited to preserve native continuation state. */
    query_matcher& operator=(const query_matcher&) = delete;

    /**
     * @brief Feed one preorder tag to the canonical matcher.
     * @param tag Borrowed tag of the current item.
     * @param depth Item depth, starting at zero for roots.
     * @return True if this item matches the query.
     * @warning Feed every item in order; do not skip nonmatching ancestors.
     */
    bool matches(tlv::tag tag, size_t depth) {
        const auto raw = detail::semantic_access::get(tag);
        return init_result_ == TLV_OK && tlv_query_matcher_visit(&impl_, &raw, depth) != 0;
    }

    /**
     * @brief Visit matching items from a C++ Tree Reader, preserving match state.
     * @param reader Cursor at the start of a tree or a previous matching continuation.
     * @param visitor Callable taking Element, depth and offset, returning tlv_visit_result_t.
     * @param[out] diagnostic Optional failure offset; unchanged on success.
     * @return Success on EOF or STOP; NEED_MORE_DATA or original C error otherwise.
     * @warning Do not interleave unmatched pulls or mutate the cursor in callbacks.
     * Callback effects are not rolled back; retained Elements borrow input or Format.
     */
    template <typename Visitor>
    TLV_NODISCARD expected<void, error> visit(tree_reader& reader, Visitor&& visitor,
                                              tlv_reader_diagnostic_t* diagnostic = nullptr) {
        reader.has_current_ = false;
        if (init_result_ != TLV_OK) return unexpected<error>(error::from_c(init_result_));
        if (reader.init_result_ != TLV_OK)
            return unexpected<error>(error::from_c(reader.init_result_));
        tlv_reader_diagnostic_t local{};
        if (!diagnostic) diagnostic = &local;
        detail::tree_visitor<Visitor> context{&visitor};
        auto rc = tlv_query_visit(&reader.impl_, &impl_, &detail::tree_visitor<Visitor>::call,
                                  &context, diagnostic);
        if (rc != TLV_OK) {
            diagnostic->diagnostic.code = rc;
            return unexpected<error>(
                detail::error_access::diagnostic(diagnostic->diagnostic, operation::query));
        }
        return {};
    }

private:
    tlv_query_t         query_{};
    tlv_query_matcher_t impl_{};
    tlv_result_t        init_result_;
};
} // namespace tlv
#endif
