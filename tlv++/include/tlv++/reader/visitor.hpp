#ifndef OPENTLV_TLVPP_VISITOR_HPP
#define OPENTLV_TLVPP_VISITOR_HPP
#include <type_traits>
#include "tlv++/types.hpp"
#include "tlv/reader/visitor.h"
#include "tlv/size.h"

/**
 * @file visitor.hpp
 * @brief C++ wrapper for nested traversal of TLV data.
 */

namespace tlv {
/**
 * @brief Visit an initialized caller-owned Tree Reader without allocation.
 *
 * @tparam Visitor Callable taking Element, depth and absolute offset and returning
 * tlv_visit_result_t.
 * @param[in,out] reader Initialized cursor with caller-owned input and frames.
 * @param[in] visitor Borrowed callable; STOP succeeds, ERROR fails.
 * @param[out] error_offset Optional absolute failure offset; unchanged on success.
 * @return Success on exhaustion or STOP; otherwise the original cursor or visitor error.
 * @warning Borrowed lifetimes and callback restrictions follow tlv_tree_reader_visit().
 */
template <typename Visitor>
TLV_NODISCARD expected<void, error> visit_tree(tlv_tree_reader_t& reader, Visitor&& visitor,
                                               size_t* error_offset = nullptr) {
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
    tlv_result_t rc = tlv_tree_reader_visit(&reader, &adapter::call, &state, error_offset);
    if (rc != TLV_OK) return unexpected<error>(error::from_c(rc));
    return {};
}
} // namespace tlv
#endif
