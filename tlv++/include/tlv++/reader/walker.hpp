#ifndef OPENTLV_TLVPP_WALKER_HPP
#define OPENTLV_TLVPP_WALKER_HPP
#include <type_traits>
#include "tlv++/types.hpp"
#include "tlv/reader/walker.h"
#include "tlv/length.h"

/**
 * @file walker.hpp
 * @brief C++ wrapper for nested traversal of TLV data.
 */

namespace tlv {
/**
 * @brief Traverses nested elements in preorder, calling a visitor for each.
 *
 * Wraps tlv_walk_tree(). The visitor is borrowed for this call; no
 * function wrapper or allocation is needed. Entries passed to the visitor
 * borrow `data`.
 *
 * @tparam Visitor Callable invoked as `visitor(entry, depth, absolute_offset)`
 *                 returning #tlv_visit_result_t. `entry` borrows `data`,
 *                 `depth` is zero for top-level elements, and
 *                 `absolute_offset` is the element's tag offset in `data`.
 *
 * @param data          Encoded input; borrowed.
 * @param format        Reader format.
 * @param is_constructed Nesting predicate receiving `format.context`, or
 *                      `nullptr` to treat every value as opaque.
 * @param max_depth     Maximum nesting depth, `0..TLV_WALK_MAX_DEPTH`.
 * @param max_elements  Bound on all visited elements.
 * @param visitor       Visitor callable; returning #TLV_VISIT_STOP succeeds
 *                      immediately, #TLV_VISIT_ERROR fails.
 * @param error_offset  Optional. On failure receives the failing element's
 *                      absolute offset; unchanged on success.
 *
 * @return Success, or the error of tlv_walk_tree(). A value whose length does
 *         not fit the native size makes the adapter return #TLV_VISIT_ERROR.
 *
 * @warning Visitor side effects are not rolled back on error.
 */
template <typename Visitor>
TLV_NODISCARD expected<void, error> walk_tree(bytes data, const tlv_reader_format_t& format,
                                              tlv_is_constructed_fn is_constructed,
                                              size_t max_depth, size_t max_elements,
                                              Visitor&& visitor, size_t* error_offset = nullptr) {
    typedef typename std::remove_reference<Visitor>::type visitor_type;
    struct adapter {
        visitor_type*             visitor;
        static tlv_visit_result_t call(const tlv_view_t* view, size_t depth, size_t offset,
                                       void* context) {
            adapter* self = static_cast<adapter*>(context);
            size_t   length;
            if (tlv_length_to_size(view->value.length, &length) != TLV_OK) return TLV_VISIT_ERROR;
            return (*self->visitor)(
                entry{view->tag, bytes(reinterpret_cast<const byte*>(view->value.data), length)},
                depth, offset);
        }
    };
    adapter      state{&visitor};
    tlv_result_t rc = tlv_walk_tree(reinterpret_cast<const uint8_t*>(data.data()), data.size(),
                                    &format, is_constructed, max_depth, max_elements,
                                    &adapter::call, &state, error_offset);
    if (rc != TLV_OK) return unexpected<error>(error::from_c(rc));
    return {};
}
} // namespace tlv
#endif
