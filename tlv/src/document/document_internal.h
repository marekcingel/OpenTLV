// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#ifndef OPENTLV_DOCUMENT_INTERNAL_H
#define OPENTLV_DOCUMENT_INTERNAL_H
#include "tlv/document/document.h"
/* Metadata bridge for optional consumers; topology remains public node navigation. */
const tlv_format_t* document_format(const tlv_document_t* document);
int document_contains(const tlv_document_t* document, const tlv_node_t* node);
/* Exit returns 0 unchanged, 1 deferred erase, 2 deferred destruction. */
int document_query_callback(tlv_document_t* document, int active);

tlv_result_t document_edit_targets(tlv_document_t* document, tlv_node_t** targets, size_t count,
                                   tlv_document_query_edit_kind_t kind, tlv_tag_t tag,
                                   const uint8_t* value, size_t size, size_t* applied);
#endif
