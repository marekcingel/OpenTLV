// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/schema/number.h"

/* Field policy is borrowed from Schema; the primitive owns only conversion.
 * Selecting an output width is domain composition and never performs tag lookup. */
tlv_codec_result_t tlv_schema_number_decode(const void* context, const uint8_t* data, size_t size,
                                            void* value, size_t capacity) {
    const tlv_schema_number_t* rule = (const tlv_schema_number_t*)context;
    if (!rule || !rule->schema || !value || (!data && size)) return TLV_CODEC_ERR_NULL_ARG;
    if (tlv_schema_validate_length(rule->schema, size) != TLV_OK)
        return TLV_CODEC_ERR_INVALID_VALUE;
    return tlv_number_decode(&rule->representation, data, size, value, capacity);
}

tlv_codec_result_t tlv_schema_number_encode(const void* context, const void* value, size_t size,
                                            uint8_t* data, size_t capacity, size_t* written) {
    const tlv_schema_number_t* rule = (const tlv_schema_number_t*)context;
    tlv_number_codec_config_t representation;
    tlv_codec_result_t result;
    size_t width, limit;
    if (!written) return TLV_CODEC_ERR_NULL_ARG;
    *written = 0;
    if (!rule || !rule->schema || !value || (!data && capacity)) return TLV_CODEC_ERR_NULL_ARG;
    representation = rule->representation;
    result = tlv_number_encode(&representation, value, size, NULL, 0, &width);
    if (result != TLV_CODEC_OK) return result;
    if (representation.width) {
        if (tlv_schema_validate_length(rule->schema, width) != TLV_OK)
            return TLV_CODEC_ERR_INVALID_VALUE;
        return tlv_number_encode(&representation, value, size, data, capacity, written);
    }
    limit = representation.encoding == TLV_NUMBER_BCD ? 9 : 8;
    while (width <= limit && tlv_schema_validate_length(rule->schema, width) != TLV_OK) ++width;
    if (width > limit) return TLV_CODEC_ERR_INVALID_VALUE;
    representation.width = width;
    return tlv_number_encode(&representation, value, size, data, capacity, written);
}
