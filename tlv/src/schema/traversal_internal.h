// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_SCHEMA_TRAVERSAL_INTERNAL_H
#define OPENTLV_SCHEMA_TRAVERSAL_INTERNAL_H
#include "tlv/reader/visitor.h"

/* Schema's bounded preflight shares the canonical structural cursor. */
static tlv_result_t schema_check_tree(const uint8_t* data, size_t size, const tlv_format_t* format,
                                      size_t max_depth, size_t max_elements,
                                      tlv_diagnostic_t* diagnostic) {
    tlv_tree_frame_t frames[TLV_SCHEMA_MAX_DEPTH];
    tlv_tree_reader_t reader;
    tlv_result_t rc = tlv_tree_reader_init(&reader, data, size, format, frames,
                                           TLV_SCHEMA_MAX_DEPTH, max_depth, max_elements);
    if (rc != TLV_OK) {
        if (diagnostic) tlv_diagnostic_init(diagnostic, rc, TLV_DIAGNOSTIC_SEVERITY_ERROR);
        return rc;
    }
    tlv_reader_diagnostic_t detail = {0};
    rc = tlv_tree_reader_visit(&reader, NULL, NULL, diagnostic ? &detail : NULL);
    if (diagnostic && rc != TLV_OK) *diagnostic = detail.diagnostic;
    return rc;
}
#endif
