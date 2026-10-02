// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_EMV_CODEC_INTERNAL_H
#define OPENTLV_EMV_CODEC_INTERNAL_H
#include "tlv/builtins/emv/emv_codec.h"
#include "tlv/schema/schema.h"
#include "tlv/schema/number.h"

/* Operations implemented by this private semantic codec, not dictionary metadata. */
typedef enum {
    EMV_REP_ACCOUNT,
    EMV_REP_AFL,
    EMV_REP_BIOMETRIC,
    EMV_REP_CRYPTOGRAM,
    EMV_REP_CVM_RESULT,
    EMV_REP_DATE,
    EMV_REP_DIGITS,
    EMV_REP_NUMBER_LIST,
    EMV_REP_TIME,
    EMV_REP_TRACK2
} emv_representation_t;

typedef struct {
    const tlv_schema_entry_t* schema;
    emv_representation_t kind;
    unsigned argument; /* numeric BCD digits (0=binary), or CN maximum digits */
} emv_value_rule_t;

tlv_codec_result_t emv_value_decode(const void*, const uint8_t*, size_t, void*, size_t);
tlv_codec_result_t emv_value_encode(const void*, const void*, size_t, uint8_t*, size_t, size_t*);
#endif
