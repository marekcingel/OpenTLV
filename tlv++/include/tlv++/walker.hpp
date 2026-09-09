#ifndef OPENTLV_TLVPP_WALKER_HPP
#define OPENTLV_TLVPP_WALKER_HPP
#include <type_traits>
#include "tlv++/types.hpp"
#include "tlv/reader/walker.h"

namespace tlv {
// Visitor(entry, depth, absolute_offset) returns tlv_visit_result_t.
// It is borrowed for this call; no function wrapper or allocation is needed.
template <typename Visitor>
TLV_NODISCARD expected<void, error>
walk_tree(bytes data, const tlv_reader_format_t& format, tlv_is_constructed_fn is_constructed, size_t max_depth,
          size_t max_elements, Visitor&& visitor, size_t* error_offset = nullptr) {
    typedef typename std::remove_reference<Visitor>::type visitor_type;
    struct adapter {
        visitor_type* visitor;
        static tlv_visit_result_t call(const tlv_view_t* view, size_t depth,
                                       size_t offset, void* context) {
            adapter* self = static_cast<adapter*>(context);
            return (*self->visitor)(entry{view->tag,
                bytes(reinterpret_cast<const byte*>(view->value.data), view->value.length)},
                depth, offset);
        }
    };
    adapter state{&visitor};
    tlv_result_t rc = tlv_walk_tree(reinterpret_cast<const uint8_t*>(data.data()),
        data.size(), &format, is_constructed, max_depth, max_elements, &adapter::call, &state, error_offset);
    if (rc != TLV_OK) return unexpected<error>(error::from_c(rc));
    return {};
}
}
#endif
