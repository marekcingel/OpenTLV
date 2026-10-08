// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/reader/visitor.h"
#include "tlv/reader/reader.h"
#include "tlv/reader/tree.h"

static tlv_result_t tree_error(tlv_result_t rc, size_t offset, size_t* out) {
    if (out) *out = offset;
    return rc;
}

static tlv_result_t visitor_error(tlv_reader_diagnostic_t* diagnostic, tlv_result_t rc,
                                  int has_offset, size_t offset) {
    if (diagnostic) {
        tlv_reader_diagnostic_init(diagnostic);
        tlv_diagnostic_init(&diagnostic->diagnostic, rc, TLV_DIAGNOSTIC_SEVERITY_ERROR);
        if (has_offset) tlv_diagnostic_set_offset(&diagnostic->diagnostic, offset);
    }
    return rc;
}

tlv_result_t tlv_tree_reader_visit_diag(tlv_tree_reader_t* reader, tlv_tree_visitor_t visitor,
                                        void* context, size_t* error_offset,
                                        tlv_reader_diagnostic_t* diagnostic) {
    tlv_result_t rc;
    if (diagnostic) tlv_reader_diagnostic_init(diagnostic);
    if (!reader)
        return tree_error(visitor_error(diagnostic, TLV_ERR_NULL_ARG, 0, 0), 0, error_offset);
    /* Node projection drains structural ENDs before callbacks, preserving STOP
     * and Query frontier semantics even when the last match closes its parents. */
    while (!tlv_tree_reader_at_end(reader)) {
        tlv_tree_item_t item;
        rc = tlv_tree_reader_next_diag(reader, &item, diagnostic);
        if (rc != TLV_OK) {
            /* Tree preflight failures leave their diagnostic untouched. */
            if (diagnostic && diagnostic->diagnostic.code != rc)
                visitor_error(diagnostic, rc, 0, 0);
            return tree_error(rc, tlv_tree_reader_offset(reader), error_offset);
        }
        if (visitor) {
            tlv_visit_result_t result = visitor(&item.element, item.depth, item.offset, context);
            if (result == TLV_VISIT_STOP) return TLV_OK;
            if (result != TLV_VISIT_CONTINUE)
                return tree_error(visitor_error(diagnostic, TLV_ERR_VISITOR, 1, item.offset),
                                  item.offset, error_offset);
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
    if (!reader || !visitor) return visitor_error(diagnostic, TLV_ERR_NULL_ARG, 0, 0);
    while (!tlv_reader_at_end(reader)) {
        tlv_element_t element;
        size_t offset = diagnostic ? tlv_reader_offset(reader) : 0;
        rc = tlv_reader_next_diag(reader, &element, diagnostic);
        if (rc != TLV_OK) return rc;
        switch (visitor(&element, context)) {
            case TLV_VISIT_CONTINUE: break;
            case TLV_VISIT_STOP: return TLV_OK;
            default: return visitor_error(diagnostic, TLV_ERR_VISITOR, 1, offset);
        }
    }
    return TLV_OK;
}

tlv_result_t tlv_reader_visit(tlv_reader_t* reader, tlv_visitor_t visitor, void* context) {
    return tlv_reader_visit_diag(reader, visitor, context, NULL);
}
