#ifndef OPENTLV_TLVPP_QUERY_HPP
#define OPENTLV_TLVPP_QUERY_HPP
#include <type_traits>
#include "tlv++/types.hpp"
#include "tlv/size.h"
#include "tlv/query/query.h"
#include "tlv++/reader/tree.hpp"

/**
 * @file query.hpp
 * @brief C++ wrapper for path queries over TLV data.
 */

namespace tlv {
/**
 * @brief A parsed path query such as `6F/A5/50`.
 *
 * Wraps #tlv_query_t; the query language is described in
 * tlv/query/query.h. The object is a small self-contained value; it never
 * allocates and does not refer to the text it was parsed from.
 */
class query {
public:
    /**
     * @brief Parses the text of a query.
     *
     * Wraps tlv_query_parse().
     *
     * @param text         NUL-terminated query text.
     * @param error_offset Optional. On failure receives the index in `text` of
     *                     the offending character; see tlv_query_parse().
     *
     * @return The query, or the error of tlv_query_parse().
     */
    TLV_NODISCARD static expected<query, error> parse(const char* text,
                                                      size_t*     error_offset = nullptr) {
        query        result;
        tlv_result_t rc = tlv_query_parse(text, &result.query_, error_offset);
        if (rc != TLV_OK) return unexpected<error>(error::from_c(rc));
        return result;
    }

    /** @brief Number of tags in the query, which is the depth of the addressed elements plus one.
     */
    size_t size() const {
        return query_.count;
    }

    /**
     * @brief Return the tag at a zero-based query step, or an empty tag out of range.
     * @warning The returned bytes borrow this query and must not outlive it.
     */
    tag_t step(size_t index) const {
        return tlv_query_step(&query_, index);
    }

    /** @brief The underlying C query, for use with the C API. */
    const tlv_query_t& c_query() const {
        return query_;
    }

    /**
     * @brief Calls a visitor for every element the query addresses.
     *
     * Wraps tlv_query_visit_buffer(): elements are visited in document order and the
     * rules for limits, offsets and errors are the same. Nothing is allocated
     * and the entries passed to the visitor borrow `data`.
     *
     * @tparam Visitor Callable invoked as `visitor(element, depth, absolute_offset)`
     *                 returning #tlv_visit_result_t, as for visit_tree().
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
     * @param error_offset  Optional. On failure receives the failing element's
     *                      absolute offset; unchanged on success.
     *
     * @return Success, also when nothing matched, or the error of tlv_query_visit_buffer().
     *
     * @warning Visitor side effects are not rolled back on error.
     */
    template <typename Visitor>
    TLV_NODISCARD expected<void, error>
    visit_buffer(bytes data, const tlv_format_t& format, size_t max_depth, size_t max_elements,
                 Visitor&& visitor, size_t* error_offset = nullptr) const {
        typedef typename std::remove_reference<Visitor>::type visitor_type;
        struct adapter {
            visitor_type*             visitor;
            static tlv_visit_result_t call(const tlv_element_t* element, size_t depth,
                                           size_t offset, void* context) {
                adapter* self = static_cast<adapter*>(context);
                return (*self->visitor)(*element, depth, offset);
            }
        };
        adapter      state{&visitor};
        tlv_result_t rc = tlv_query_visit_buffer(
            reinterpret_cast<const uint8_t*>(data.data()), data.size(), &format, &query_, max_depth,
            max_elements, &adapter::call, &state, error_offset);
        if (rc != TLV_OK) return unexpected<error>(error::from_c(rc));
        return {};
    }

private:
    query() : query_() {}
    tlv_query_t query_;
};

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
    bool matches(tag_t tag, size_t depth) {
        return init_result_ == TLV_OK && tlv_query_matcher_visit(&impl_, &tag, depth) != 0;
    }

    /**
     * @brief Visit matching items from a C++ Tree Reader, preserving match state.
     * @param reader Cursor at the start of a tree or a previous matching continuation.
     * @param visitor Callable taking Element, depth and offset, returning tlv_visit_result_t.
     * @param[out] error_offset Optional failure offset; unchanged on success.
     * @return Success on EOF or STOP; NEED_MORE_DATA or original C error otherwise.
     * @warning Do not interleave unmatched pulls or mutate the cursor in callbacks.
     * Callback effects are not rolled back; retained Elements borrow input or Format.
     */
    template <typename Visitor>
    TLV_NODISCARD expected<void, error> visit(tree_reader& reader, Visitor&& visitor,
                                              size_t* error_offset = nullptr) {
        if (init_result_ != TLV_OK) return unexpected<error>(error::from_c(init_result_));
        if (reader.init_result_ != TLV_OK)
            return unexpected<error>(error::from_c(reader.init_result_));
        using callable = typename std::remove_reference<Visitor>::type;
        struct state {
            callable* function;
        } context{&visitor};
        auto callback = [](const tlv_element_t* value, size_t depth, size_t offset,
                           void* context) -> tlv_visit_result_t {
            return (*static_cast<state*>(context)->function)(*value, depth, offset);
        };
        auto rc = tlv_query_visit(&reader.impl_, &impl_, callback, &context, error_offset);
        if (rc != TLV_OK) return unexpected<error>(error::from_c(rc));
        return {};
    }

private:
    tlv_query_t         query_{};
    tlv_query_matcher_t impl_{};
    tlv_result_t        init_result_;
};
} // namespace tlv
#endif
