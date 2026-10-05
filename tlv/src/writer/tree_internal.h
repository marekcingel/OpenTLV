// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#ifndef OPENTLV_TREE_WRITER_INTERNAL_H
#define OPENTLV_TREE_WRITER_INTERNAL_H
#include "tlv/writer/tree.h"
/* Optional budget observer: one unit per event and three per actual Value byte
 * processed by sizing/copying/encoding. Called before the associated operation.
 * Storage capacities never participate in this accounting. */
typedef tlv_result_t (*tree_writer_charge_fn)(void* context, size_t amount);
tlv_result_t tree_writer_measure_events_observed(
    const tlv_format_t* format, tlv_tree_event_next_fn next, void* context,
    tlv_tree_writer_workspace_t* workspace, size_t max_depth, size_t max_elements, size_t* size,
    tlv_writer_diagnostic_t* diagnostic, tree_writer_charge_fn charge, void* charge_context);
#endif
