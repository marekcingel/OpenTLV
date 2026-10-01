#ifndef OPENTLV_TLVPP_DETAIL_VISITOR_HPP
#define OPENTLV_TLVPP_DETAIL_VISITOR_HPP

#include "tlv/reader/visitor.h"
#include <type_traits>

/** @file
 * @brief Internal synchronous visitor trampolines for the canonical C engine.
 */
namespace tlv {
/// @cond INTERNAL
namespace detail {

template <typename Visitor> struct element_visitor {
    using callable = typename std::remove_reference<Visitor>::type;
    callable* function;

    static tlv_visit_result_t call(const tlv_element_t* value, void* context) {
        return (*static_cast<element_visitor*>(context)->function)(*value);
    }
};

template <typename Visitor> struct tree_visitor {
    using callable = typename std::remove_reference<Visitor>::type;
    callable* function;

    static tlv_visit_result_t call(const tlv_element_t* value, size_t depth, size_t offset,
                                   void* context) {
        return (*static_cast<tree_visitor*>(context)->function)(*value, depth, offset);
    }
};

} // namespace detail
/// @endcond
} // namespace tlv
#endif
