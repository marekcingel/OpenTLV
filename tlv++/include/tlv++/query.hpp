#ifndef OPENTLV_TLVPP_QUERY_HPP
#define OPENTLV_TLVPP_QUERY_HPP
#include <type_traits>
#include "tlv++/types.hpp"
#include "tlv/length.h"
#include "tlv/query/query.h"

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

    /** @brief The underlying C query, for use with the C API. */
    const tlv_query_t& c_query() const {
        return query_;
    }

    /**
     * @brief Calls a visitor for every element the query addresses.
     *
     * Wraps tlv_query_walk(): elements are visited in document order and the
     * rules for limits, offsets and errors are the same. Nothing is allocated
     * and the entries passed to the visitor borrow `data`.
     *
     * @tparam Visitor Callable invoked as `visitor(entry, depth, absolute_offset)`
     *                 returning #tlv_visit_result_t, as for walk_tree().
     *
     * @param data          Encoded input; borrowed.
     * @param format        Reader format.
     * @param is_constructed Nesting predicate receiving `format.context`, or
     *                      `nullptr` to treat every value as opaque, in which
     *                      case only one-tag queries can match.
     * @param max_depth     Maximum nesting depth, `0..TLV_WALK_MAX_DEPTH`.
     * @param max_elements  Bound on all traversed elements.
     * @param visitor       Visitor callable; returning #TLV_VISIT_STOP succeeds
     *                      immediately, #TLV_VISIT_ERROR fails.
     * @param error_offset  Optional. On failure receives the failing element's
     *                      absolute offset; unchanged on success.
     *
     * @return Success, also when nothing matched, or the error of tlv_query_walk().
     *
     * @warning Visitor side effects are not rolled back on error.
     */
    template <typename Visitor>
    TLV_NODISCARD expected<void, error> walk(bytes data, const tlv_reader_format_t& format,
                                             tlv_is_constructed_fn is_constructed, size_t max_depth,
                                             size_t max_elements, Visitor&& visitor,
                                             size_t* error_offset = nullptr) const {
        typedef typename std::remove_reference<Visitor>::type visitor_type;
        struct adapter {
            visitor_type*             visitor;
            static tlv_visit_result_t call(const tlv_view_t* view, size_t depth, size_t offset,
                                           void* context) {
                adapter* self = static_cast<adapter*>(context);
                size_t   length;
                if (tlv_length_to_size(view->value.length, &length) != TLV_OK)
                    return TLV_VISIT_ERROR;
                return (*self->visitor)(
                    entry{view->tag,
                          bytes(reinterpret_cast<const byte*>(view->value.data), length)},
                    depth, offset);
            }
        };
        adapter      state{&visitor};
        tlv_result_t rc = tlv_query_walk(reinterpret_cast<const uint8_t*>(data.data()), data.size(),
                                         &format, is_constructed, &query_, max_depth, max_elements,
                                         &adapter::call, &state, error_offset);
        if (rc != TLV_OK) return unexpected<error>(error::from_c(rc));
        return {};
    }

private:
    query() : query_() {}
    tlv_query_t query_;
};
} // namespace tlv
#endif
