#ifndef OPENTLV_WALKER_H
#define OPENTLV_WALKER_H

#include "tlv/formats/format.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum tlv_visit_result {
    TLV_VISIT_CONTINUE = 0,
    TLV_VISIT_STOP = 1,
    TLV_VISIT_ERROR = 2
} tlv_visit_result_t;

/* The view pointer is valid only during the callback. Its value borrows data. */
typedef tlv_visit_result_t (*tlv_visitor_t)(const tlv_view_t* view, void* context);

/*
 * Visits each sequential element using the generic reader, without allocation
 * or recursion into values. The input and format must remain valid and unchanged
 * during traversal. context is passed through unchanged and may be NULL.
 * Returns TLV_OK at the end (including empty input) or on TLV_VISIT_STOP.
 * Reader errors propagate unchanged; TLV_VISIT_ERROR or an unknown visitor
 * result returns TLV_ERR_VISITOR. No further elements are read after stop/error.
 * Requires a visitor and format->read_tag/read_length, even for empty input.
 * data may be NULL only when size is zero; invalid arguments return
 * TLV_ERR_NULL_ARG. Earlier callback effects are not rolled back on error.
 */
tlv_result_t tlv_walk(const uint8_t* data, size_t size,
                      const tlv_format_t* format, tlv_visitor_t visitor,
                      void* context);

#define TLV_WALK_MAX_DEPTH 64
typedef tlv_visit_result_t (*tlv_tree_visitor_t)(const tlv_view_t* view,
                                               size_t depth, size_t offset,
                                               void* context);
/* Preorder traversal of definite-length containers identified by the format.
 * Top-level depth is zero; max_depth is 0..TLV_WALK_MAX_DEPTH. No allocation
 * or C recursion. NULL visitor validates only. STOP succeeds immediately.
 * max_elements bounds all visited nodes (zero permits only empty input).
 * error_offset, if non-NULL, receives the failing element's absolute offset
 * on failure and remains unchanged on success. Callback effects are not
 * rolled back. The input, format and borrowed views follow tlv_walk lifetimes. */
tlv_result_t tlv_walk_tree(const uint8_t* data, size_t size,
                           const tlv_format_t* format, size_t max_depth,
                           size_t max_elements, tlv_tree_visitor_t visitor,
                           void* context, size_t* error_offset);

#ifdef __cplusplus
}
#endif

#endif /* OPENTLV_WALKER_H */
