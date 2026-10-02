// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_TREE_H
#define OPENTLV_TREE_H

#include "tlv/element.h"
#include "tlv/format.h"

/** @file
 * @brief Format-independent streaming structure shared by Tree Reader and Writer.
 */

/** @brief One operation in a balanced structural stream. */
typedef enum tlv_tree_event_kind {
    TLV_TREE_BEGIN,   /**< Open a constructed node; its children follow. */
    TLV_TREE_ELEMENT, /**< One primitive node. */
    TLV_TREE_END      /**< Close the innermost open node, without borrowed payload. */
} tlv_tree_event_kind_t;

/**
 * @brief Borrowed structural event, not a materialized tree node.
 *
 * BEGIN and ELEMENT carry the existing semantic Element. Reader-produced BEGIN
 * carries a complete source Value, but Writer ignores it and builds a new Value
 * from subsequent events. END has zeroed Element/Source and needs no retained
 * parent bytes. An empty container is BEGIN followed by END. Roots form a
 * sequence without a synthetic container. EOF is a Reader result, not an event.
 *
 * Borrowed payload remains valid only while its original input and Format
 * storage remain alive and unchanged. NEED_MORE_DATA neither publishes an
 * event nor extends the lifetime of previous payloads. Source is optional
 * metadata for producers other than Reader and is never used for encoding.
 */
typedef struct tlv_tree_event {
    tlv_tree_event_kind_t kind; /**< Structural operation. */
    tlv_element_t element;      /**< Complete borrowed node; absent on END. */
    tlv_source_t source;        /**< Original encoding metadata; absent on END. */
    size_t depth;               /**< Node depth, including on END; roots are zero. */
    size_t offset;              /**< Node start, or Value end on END, in source bytes. */
    int skipped;                /**< END only: descendants were omitted, not validated. */
} tlv_tree_event_t;

#endif
