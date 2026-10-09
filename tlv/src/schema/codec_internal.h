// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#ifndef TLV_SCHEMA_CODEC_INTERNAL_H
#define TLV_SCHEMA_CODEC_INTERNAL_H

#include "tlv/schema/number.h"

static tlv_result_t tlv_schema_codec_length_result(const tlv_schema_entry_t* rule, size_t width,
                                                   tlv_result_t result,
                                                   tlv_codec_diagnostic_t* diagnostic) {
    if (diagnostic) {
        diagnostic->codec.cause = TLV_CODEC_CAUSE_SCHEMA;
        tlv_codec_schema_detail_t* detail = &diagnostic->codec.detail.schema;
        detail->kind = result == TLV_ERR_INVALID_SCHEMA ? TLV_SCHEMA_ISSUE_DEFINITION
                                                        : TLV_SCHEMA_ISSUE_LENGTH;
        detail->tag = rule->tag;
        detail->field = rule->name;
        detail->has_length = 1;
        detail->min_length = rule->min_length;
        detail->max_length = rule->max_length;
        detail->actual_length = width;
        detail->length_multiple = rule->length_multiple;
        detail->length_flags = rule->flags;
    }
    return tlv_codec_diagnostic_result(diagnostic, result);
}

#endif
