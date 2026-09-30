#include "tlv/reader/walker.h"
#include "tlv/reader/reader.h"
#include "tlv/reader/tree.h"

static tlv_result_t tree_error(tlv_result_t rc, size_t offset, size_t* out) {
    if (out) *out = offset;
    return rc;
}

tlv_result_t tlv_tree_reader_visit_diag(tlv_tree_reader_t* reader, tlv_tree_visitor_t visitor,
                                        void* context, size_t* error_offset,
                                        tlv_reader_diagnostic_t* diagnostic) {
    tlv_result_t rc;
    if (diagnostic) tlv_reader_diagnostic_init(diagnostic);
    if (!reader) return tree_error(TLV_ERR_NULL_ARG, 0, error_offset);
    while (!tlv_tree_reader_at_end(reader)) {
        tlv_tree_item_t item;
        rc = tlv_tree_reader_next_diag(reader, &item, diagnostic);
        if (rc != TLV_OK) return tree_error(rc, tlv_tree_reader_offset(reader), error_offset);
        if (visitor) {
            tlv_visit_result_t result = visitor(&item.element, item.depth, item.offset, context);
            if (result == TLV_VISIT_STOP) return TLV_OK;
            if (result != TLV_VISIT_CONTINUE)
                return tree_error(TLV_ERR_VISITOR, item.offset, error_offset);
        }
    }
    return TLV_OK;
}

tlv_result_t tlv_tree_reader_visit(tlv_tree_reader_t* reader, tlv_tree_visitor_t visitor,
                                   void* context, size_t* error_offset) {
    return tlv_tree_reader_visit_diag(reader, visitor, context, error_offset, NULL);
}

tlv_result_t tlv_reader_visit_diag(tlv_reader_t* reader, tlv_visitor_t visitor, void* context,
                                   tlv_reader_diagnostic_t* diagnostic) {
    tlv_result_t rc;
    if (diagnostic) tlv_reader_diagnostic_init(diagnostic);
    if (!reader || !visitor) return TLV_ERR_NULL_ARG;
    while (!tlv_reader_at_end(reader)) {
        tlv_element_t element;
        rc = tlv_reader_next_diag(reader, &element, diagnostic);
        if (rc != TLV_OK) return rc;
        switch (visitor(&element, context)) {
            case TLV_VISIT_CONTINUE: break;
            case TLV_VISIT_STOP: return TLV_OK;
            default: return TLV_ERR_VISITOR;
        }
    }
    return TLV_OK;
}

tlv_result_t tlv_reader_visit(tlv_reader_t* reader, tlv_visitor_t visitor, void* context) {
    return tlv_reader_visit_diag(reader, visitor, context, NULL);
}

tlv_result_t tlv_walk(const uint8_t* data, size_t size, const tlv_format_t* format,
                      tlv_visitor_t visitor, void* context) {
    tlv_reader_t reader;
    tlv_result_t rc;
    if (!visitor) return TLV_ERR_NULL_ARG;
    rc = tlv_reader_init(&reader, data, size, format);
    if (rc != TLV_OK) return rc;
    return tlv_reader_visit(&reader, visitor, context);
}

static tlv_result_t walk_tree_impl(const uint8_t* data, size_t size, const tlv_format_t* format,
                                   size_t max_depth, size_t max_elements,
                                   tlv_tree_visitor_t visitor, void* context, size_t* error_offset,
                                   tlv_reader_diagnostic_t* diagnostic) {
    tlv_tree_frame_t frames[TLV_WALK_MAX_DEPTH];
    tlv_tree_reader_t reader;
    tlv_result_t rc;
    if (diagnostic) tlv_reader_diagnostic_init(diagnostic);
    rc = tlv_tree_reader_init(&reader, data, size, format, frames, TLV_WALK_MAX_DEPTH, max_depth,
                              max_elements);
    if (rc != TLV_OK) return tree_error(rc, 0, error_offset);
    if (max_depth > TLV_WALK_MAX_DEPTH) return tree_error(TLV_ERR_LIMIT, 0, error_offset);
    return tlv_tree_reader_visit_diag(&reader, visitor, context, error_offset, diagnostic);
}

tlv_result_t tlv_walk_tree(const uint8_t* data, size_t size, const tlv_format_t* format,
                           size_t max_depth, size_t max_elements, tlv_tree_visitor_t visitor,
                           void* context, size_t* error_offset) {
    return walk_tree_impl(data, size, format, max_depth, max_elements, visitor, context,
                          error_offset, NULL);
}

tlv_result_t tlv_walk_tree_diag(const uint8_t* data, size_t size, const tlv_format_t* format,
                                size_t max_depth, size_t max_elements, tlv_tree_visitor_t visitor,
                                void* context, size_t* error_offset,
                                tlv_reader_diagnostic_t* diagnostic) {
    return walk_tree_impl(data, size, format, max_depth, max_elements, visitor, context,
                          error_offset, diagnostic);
}
