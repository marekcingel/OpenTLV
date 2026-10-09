// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "document_internal.h"
#include "tlv/size.h"
#include <string.h>

tlv_result_t tlv_document_query_visit(const tlv_document_t* document, const tlv_query_t* query,
                                      tlv_document_query_visitor_t visitor, void* context) {
    tlv_query_matcher_t matcher;
    tlv_node_t* node;
    size_t depth = 0;
    tlv_result_t rc;
    if (!document || !query || !visitor) return TLV_ERR_NULL_ARG;
    rc = tlv_query_matcher_init(&matcher, query);
    if (rc != TLV_OK) return rc;
    node = document->first;
    while (node) {
        tlv_tag_t tag = document_node_tag(node);
        if (tlv_query_matcher_visit(&matcher, &tag, depth)) {
            document_query_callback((tlv_document_t*)document, 1);
            tlv_visit_result_t result = visitor(node, context);
            if (document_query_callback((tlv_document_t*)document, 0)) return TLV_ERR_INVALID_STATE;
            if (result == TLV_VISIT_STOP) return TLV_OK;
            if (result != TLV_VISIT_CONTINUE)
                return result == TLV_VISIT_ERROR ? TLV_ERR_VISITOR : TLV_ERR_CALLBACK;
        }
        if (node->first) {
            node = node->first;
            ++depth;
        } else {
            while (node->parent && !node->next) {
                node = node->parent;
                --depth;
            }
            node = node->next;
        }
    }
    return TLV_OK;
}

static tlv_visit_result_t first_path_match(tlv_node_t* node, void* context) {
    *(tlv_node_t**)context = node;
    return TLV_VISIT_STOP;
}

tlv_result_t tlv_document_find_path(const tlv_document_t* document, const tlv_query_t* query,
                                    tlv_node_t** node) {
    tlv_node_t* result = NULL;
    tlv_result_t rc;
    if (!node) return TLV_ERR_NULL_ARG;
    rc = tlv_document_query_visit(document, query, first_path_match, &result);
    if (rc != TLV_OK) return rc;
    *node = result;
    return TLV_OK;
}
