// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/schema/number.h"

#include "codec_internal.h"

/* Field policy is borrowed from Schema; the primitive owns only conversion.
 * Selecting an output width is domain composition and never performs tag lookup. */
tlv_result_t tlv_schema_number_decode(const void* context, const uint8_t* data, size_t size,
                                      void* value, size_t capacity,
                                      tlv_codec_diagnostic_t* diagnostic) {
    tlv_codec_diagnostic_init(diagnostic, TLV_CODEC_OP_DECODE);
    const tlv_schema_number_t* rule = (const tlv_schema_number_t*)context;
    if (!rule || !rule->schema || !value || (!data && size))
        return tlv_codec_diagnostic_result(diagnostic, TLV_ERR_NULL_ARG);
    tlv_result_t result = tlv_schema_validate_length(rule->schema, size);
    if (result != TLV_OK)
        return tlv_schema_codec_length_result(rule->schema, size, result, diagnostic);
    return tlv_codec_diagnostic_result(
        diagnostic,
        tlv_number_decode(&rule->representation, data, size, value, capacity, diagnostic));
}

tlv_result_t tlv_schema_number_encode(const void* context, const void* value, size_t size,
                                      uint8_t* data, size_t capacity, size_t* written,
                                      tlv_codec_diagnostic_t* diagnostic) {
    tlv_codec_diagnostic_init(diagnostic, data ? TLV_CODEC_OP_ENCODE : TLV_CODEC_OP_MEASURE);
    const tlv_schema_number_t* rule = (const tlv_schema_number_t*)context;
    tlv_number_codec_config_t representation;
    tlv_result_t result;
    size_t width, limit;
    if (!written) return tlv_codec_diagnostic_result(diagnostic, TLV_ERR_NULL_ARG);
    *written = 0;
    if (!rule || !rule->schema || !value || (!data && capacity))
        return tlv_codec_diagnostic_result(diagnostic, TLV_ERR_NULL_ARG);
    representation = rule->representation;
    result = tlv_number_encode(&representation, value, size, NULL, 0, &width, NULL);
    if (result != TLV_OK) return tlv_codec_diagnostic_result(diagnostic, result);
    if (representation.width) {
        result = tlv_schema_validate_length(rule->schema, width);
        if (result != TLV_OK)
            return tlv_schema_codec_length_result(rule->schema, width, result, diagnostic);
        return tlv_codec_diagnostic_result(
            diagnostic,
            tlv_number_encode(&representation, value, size, data, capacity, written, diagnostic));
    }
    limit = representation.encoding == TLV_NUMBER_BCD ? 9 : 8;
    for (;;) {
        result = tlv_schema_validate_length(rule->schema, width);
        if (result == TLV_OK) break;
        if (result != TLV_ERR_SCHEMA || width == limit)
            return tlv_schema_codec_length_result(rule->schema, width, result, diagnostic);
        ++width;
    }
    representation.width = width;
    return tlv_codec_diagnostic_result(
        diagnostic,
        tlv_number_encode(&representation, value, size, data, capacity, written, diagnostic));
}
