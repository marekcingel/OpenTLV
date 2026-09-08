#ifndef OPENTLV_EMV_INTERNAL_H
#define OPENTLV_EMV_INTERNAL_H
#include "tlv/codec/emv.h"

typedef struct {
    size_t min_length, max_length, step;
    tlv_emv_value_kind_t kind;
    unsigned argument; /* numeric BCD digits (0=binary), or CN maximum digits */
} emv_value_rule_t;

tlv_codec_result_t emv_value_decode(const void*, const uint8_t*, size_t,
                                   void*, size_t);
tlv_codec_result_t emv_value_encode(const void*, const void*, size_t,
                                   uint8_t*, size_t, size_t*);
#endif
