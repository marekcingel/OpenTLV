#ifndef OPENTLV_EMV_CODEC_INTERNAL_H
#define OPENTLV_EMV_CODEC_INTERNAL_H
#include "tlv/builtins/emv/emv_codec.h"
#include "tlv/schema/schema.h"
#include "tlv/schema/number.h"

typedef struct {
    const tlv_schema_entry_t* schema;
    tlv_emv_value_kind_t kind;
    unsigned argument; /* numeric BCD digits (0=binary), or CN maximum digits */
} emv_value_rule_t;

tlv_codec_result_t emv_value_decode(const void*, const uint8_t*, size_t, void*, size_t);
tlv_codec_result_t emv_value_encode(const void*, const void*, size_t, uint8_t*, size_t, size_t*);
#endif
