// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#ifndef OPENTLV_DOCUMENT_INTERNAL_H
#define OPENTLV_DOCUMENT_INTERNAL_H
#include "tlv/document/document.h"
/* Metadata bridge for optional consumers; topology remains public node navigation. */
const tlv_format_t* document_format(const tlv_document_t* document);
int document_contains(const tlv_document_t* document, const tlv_node_t* node);
#endif
