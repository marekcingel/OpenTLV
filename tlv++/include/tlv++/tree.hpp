#ifndef OPENTLV_TLVPP_TREE_HPP
#define OPENTLV_TLVPP_TREE_HPP

#include "tlv++/types.hpp"
#include "tlv/tree.h"

/** @file
 * @brief Shared borrowed C++ structural records for Reader and Writer.
 */
namespace tlv {
/**
 * @brief Complete borrowed element with source, depth, offset and classification.
 * @warning Immutable input, Format-supplied identifier storage and source Format
 * context must outlive all retained copies. Copying never allocates or copies bytes.
 */
struct tree_item {
    /** @brief Complete borrowed semantic content. */
    element_view element;
    /** @brief Borrowed original framing. */
    tlv_source_t source;
    /** @brief Preorder depth, with roots at zero. */
    size_t depth;
    /** @brief Absolute logical source offset. */
    size_t offset;
    /** @brief Whether the Format classifies the node as constructed. */
    bool constructed;
};
/**
 * @brief Canonical borrowed BEGIN, ELEMENT or END event.
 *
 * Reader BEGIN carries a complete Value; Writer builds the parent Value from
 * subsequent events. END has no borrowed payload. Source is optional producer
 * metadata and does not affect encoding. Copying allocates nothing.
 * @warning BEGIN/ELEMENT input, Format-supplied identifier storage and source
 * Format/context must outlive every retained copy. END needs no parent storage.
 */
struct tree_event {
    /** @brief BEGIN, ELEMENT or END operation; END has no borrowed payload. */
    tlv_tree_event_kind_t kind;
    /** @brief Borrowed semantic payload, absent for END. */
    element_view element;
    /** @brief Original framing, absent for END and optional for custom producers. */
    tlv_source_t source;
    /** @brief Structural depth, including on END; roots are zero. */
    size_t depth;
    /** @brief Absolute node start, or Value end on END. */
    size_t offset;
    /** @brief END only: descendants were omitted rather than validated. */
    bool skipped;
};

/// @cond INTERNAL
namespace detail {
struct tree_access {
    static tree_event borrow(tlv_tree_event_t raw) noexcept {
        return {raw.kind,   semantic_access::borrow(raw.element),
                raw.source, raw.depth,
                raw.offset, raw.skipped != 0};
    }
    static tlv_tree_event_t get(const tree_event& view) noexcept {
        return {view.kind,   semantic_access::get(view.element),
                view.source, view.depth,
                view.offset, view.skipped ? 1 : 0};
    }
};
} // namespace detail
/// @endcond

} // namespace tlv
#endif
