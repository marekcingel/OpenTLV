#ifndef OPENTLV_TLVPP_WALKER_HPP
#define OPENTLV_TLVPP_WALKER_HPP
#include <type_traits>
#include "tlv++/types.hpp"
#include "tlv/reader/walker.h"
#include "tlv/size.h"

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
 * @tparam Visitor Callable invoked as `visitor(element, depth, absolute_offset)`
 *                 returning #tlv_visit_result_t. `element` borrows `data`,
 *                 `depth` is zero for top-level elements, and
 *                 `absolute_offset` is the element's tag offset in `data`.
 *
 * @param data          Encoded input; borrowed.
 * @param format        Reader format. A `nullptr` `format.is_constructed`
 *                      treats every value as opaque.
 * @param max_depth     Maximum nesting depth, `0..TLV_WALK_MAX_DEPTH`.
 * @param max_elements  Bound on all visited elements.
 * @param visitor       Visitor callable; returning #TLV_VISIT_STOP succeeds
 *                      immediately, #TLV_VISIT_ERROR fails.
 * @param error_offset  Optional. On failure receives the failing element's
 *                      absolute offset; unchanged on success.
 *
 * @return Success, or the error of tlv_walk_tree().
 *
 * @warning Visitor side effects are not rolled back on error.
 */
template <typename Visitor>
TLV_NODISCARD expected<void, error> walk_tree(bytes data, const tlv_format_t& format,
                                              size_t max_depth, size_t max_elements,
                                              Visitor&& visitor, size_t* error_offset = nullptr) {
    typedef typename std::remove_reference<Visitor>::type visitor_type;
    struct adapter {
        visitor_type*             visitor;
        static tlv_visit_result_t call(const tlv_element_t* element, size_t depth, size_t offset,
                                       void* context) {
            adapter* self = static_cast<adapter*>(context);
            return (*self->visitor)(*element, depth, offset);
        }
    };
    adapter      state{&visitor};
    tlv_result_t rc =
        tlv_walk_tree(reinterpret_cast<const uint8_t*>(data.data()), data.size(), &format,
                      max_depth, max_elements, &adapter::call, &state, error_offset);
    if (rc != TLV_OK) return unexpected<error>(error::from_c(rc));
    return {};
}
} // namespace tlv
#endif
