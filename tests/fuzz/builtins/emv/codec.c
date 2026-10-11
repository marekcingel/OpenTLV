// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/builtins/emv/presentation.h"
#include "common.h"
#include "tlv/builtins/emv/emv.h"
#include <string.h>

#define FUZZ_CODEC_DIGITS_CAPACITY 4096

/* Every fixed-size C representation a non-DIGITS EMV codec can decode into. */
typedef union {
    uint64_t                  number;
    tlv_emv_date_t            date;
    tlv_emv_time_t            time;
    tlv_emv_account_type_t    account;
    tlv_emv_cryptogram_info_t cryptogram;
    tlv_emv_biometric_type_t  biometric;
    tlv_emv_number_list_t     list;
    tlv_emv_afl_t             afl;
    tlv_emv_cvm_result_t      cvm_result;
    tlv_emv_track2_t          track2;
} fuzz_codec_fixed_value;

static size_t fixed_capacity(tlv_emv_value_kind_t kind) {
    switch (kind) {
        case TLV_EMV_VALUE_NUMBER:
        case TLV_EMV_VALUE_FLAGS: return sizeof(uint64_t);
        case TLV_EMV_VALUE_DATE: return sizeof(tlv_emv_date_t);
        case TLV_EMV_VALUE_TIME: return sizeof(tlv_emv_time_t);
        case TLV_EMV_VALUE_ACCOUNT: return sizeof(tlv_emv_account_type_t);
        case TLV_EMV_VALUE_CRYPTOGRAM: return sizeof(tlv_emv_cryptogram_info_t);
        case TLV_EMV_VALUE_BIOMETRIC: return sizeof(tlv_emv_biometric_type_t);
        case TLV_EMV_VALUE_NUMBER_LIST: return sizeof(tlv_emv_number_list_t);
        case TLV_EMV_VALUE_AFL: return sizeof(tlv_emv_afl_t);
        case TLV_EMV_VALUE_CVM_RESULT: return sizeof(tlv_emv_cvm_result_t);
        case TLV_EMV_VALUE_TRACK2: return sizeof(tlv_emv_track2_t);
        default: return 0;
    }
}

/* Field-by-field comparison avoids relying on padding bytes (e.g. inside
 * tlv_emv_cryptogram_info_t) being reproducibly initialized across calls. */
static int fixed_equal(tlv_emv_value_kind_t kind, const fuzz_codec_fixed_value* a,
                       const fuzz_codec_fixed_value* b) {
    switch (kind) {
        case TLV_EMV_VALUE_NUMBER:
        case TLV_EMV_VALUE_FLAGS: return a->number == b->number;
        case TLV_EMV_VALUE_DATE:
            return a->date.year == b->date.year && a->date.month == b->date.month &&
                   a->date.day == b->date.day;
        case TLV_EMV_VALUE_TIME:
            return a->time.hour == b->time.hour && a->time.minute == b->time.minute &&
                   a->time.second == b->time.second;
        case TLV_EMV_VALUE_ACCOUNT: return a->account == b->account;
        case TLV_EMV_VALUE_CRYPTOGRAM:
            return a->cryptogram.type == b->cryptogram.type &&
                   a->cryptogram.flags == b->cryptogram.flags;
        case TLV_EMV_VALUE_BIOMETRIC: return a->biometric == b->biometric;
        case TLV_EMV_VALUE_NUMBER_LIST: {
            size_t i;
            if (a->list.count != b->list.count) return 0;
            for (i = 0; i < a->list.count; ++i)
                if (a->list.values[i] != b->list.values[i]) return 0;
            return 1;
        }
        case TLV_EMV_VALUE_AFL: {
            size_t i;
            if (a->afl.count != b->afl.count) return 0;
            for (i = 0; i < a->afl.count; ++i)
                if (memcmp(&a->afl.entries[i], &b->afl.entries[i], sizeof(a->afl.entries[i])) != 0)
                    return 0;
            return 1;
        }
        case TLV_EMV_VALUE_CVM_RESULT:
            return a->cvm_result.method == b->cvm_result.method &&
                   a->cvm_result.condition == b->cvm_result.condition &&
                   a->cvm_result.result == b->cvm_result.result;
        case TLV_EMV_VALUE_TRACK2:
            return strcmp(a->track2.pan, b->track2.pan) == 0 &&
                   a->track2.expiration_year == b->track2.expiration_year &&
                   a->track2.expiration_month == b->track2.expiration_month &&
                   a->track2.service_code == b->track2.service_code &&
                   strcmp(a->track2.discretionary_data, b->track2.discretionary_data) == 0;
        default: return 0;
    }
}

static void check_fixed_roundtrip(const tlv_codec_t* codec, tlv_emv_value_kind_t kind,
                                  const fuzz_codec_fixed_value* value, size_t object_size) {
    uint8_t                encoded[256];
    size_t                 queried = SIZE_MAX, written = SIZE_MAX, written_short = SIZE_MAX;
    fuzz_codec_fixed_value decoded;
    FUZZ_CHECK(tlv_codec_encode(codec, value, object_size, NULL, 0, &queried, NULL) == TLV_OK);
    FUZZ_CHECK(queried > 0 && queried <= sizeof(encoded));
    memset(encoded, 0xa5, sizeof(encoded));
    FUZZ_CHECK(tlv_codec_encode(codec, value, object_size, encoded, sizeof(encoded), &written,
                                NULL) == TLV_OK);
    FUZZ_CHECK(written == queried);
    FUZZ_CHECK(tlv_codec_encode(codec, value, object_size, encoded, written - 1, &written_short,
                                NULL) == TLV_ERR_BUFFER_TOO_SHORT);
    FUZZ_CHECK(written_short == 0);
    memset(&decoded, 0x5a, sizeof(decoded));
    FUZZ_CHECK(tlv_codec_decode(codec, encoded, written, &decoded, object_size, NULL) == TLV_OK);
    FUZZ_CHECK(fixed_equal(kind, &decoded, value));
}

static void check_fixed(const tlv_codec_t* codec, tlv_emv_value_kind_t kind, const uint8_t* data,
                        size_t size) {
    fuzz_codec_fixed_value value;
    tlv_result_t           rc;
    size_t                 capacity = fixed_capacity(kind);
    if (!capacity) return;
    memset(&value, 0xa5, sizeof(value));
    /* One byte short of the documented representation must never succeed,
     * regardless of whether the raw bytes are otherwise a valid value. */
    if (capacity > 1)
        FUZZ_CHECK(tlv_codec_decode(codec, data, size, &value, capacity - 1, NULL) != TLV_OK);
    rc = tlv_codec_decode(codec, data, size, &value, capacity, NULL);
    FUZZ_CHECK(rc == TLV_OK || rc == TLV_ERR_INVALID_VALUE);
    if (rc == TLV_OK) check_fixed_roundtrip(codec, kind, &value, capacity);
}

static void check_digits(const tlv_codec_t* codec, const uint8_t* data, size_t size) {
    char         digits[FUZZ_CODEC_DIGITS_CAPACITY];
    char         decoded[FUZZ_CODEC_DIGITS_CAPACITY];
    uint8_t      encoded[FUZZ_CODEC_DIGITS_CAPACITY];
    tlv_result_t rc;
    size_t       queried = SIZE_MAX, written = SIZE_MAX, written_short = SIZE_MAX, digit_count;
    memset(digits, 0xa5, sizeof(digits));
    rc = tlv_codec_decode(codec, data, size, digits, sizeof(digits), NULL);
    FUZZ_CHECK(rc == TLV_OK || rc == TLV_ERR_INVALID_VALUE || rc == TLV_ERR_BUFFER_TOO_SHORT);
    if (rc != TLV_OK) return;
    digit_count = strlen(digits);
    FUZZ_CHECK(digit_count < sizeof(digits));
    /* decode_digits validates before checking capacity, so a capacity that
     * omits only the terminating NUL must fail this same input deterministically. */
    FUZZ_CHECK(tlv_codec_decode(codec, data, size, decoded, digit_count, NULL) ==
               TLV_ERR_BUFFER_TOO_SHORT);
    FUZZ_CHECK(tlv_codec_encode(codec, digits, digit_count, NULL, 0, &queried, NULL) == TLV_OK);
    FUZZ_CHECK(queried <= sizeof(encoded));
    memset(encoded, 0xa5, sizeof(encoded));
    FUZZ_CHECK(tlv_codec_encode(codec, digits, digit_count, encoded, sizeof(encoded), &written,
                                NULL) == TLV_OK);
    FUZZ_CHECK(written == queried);
    if (written > 0) {
        FUZZ_CHECK(tlv_codec_encode(codec, digits, digit_count, encoded, written - 1,
                                    &written_short, NULL) == TLV_ERR_BUFFER_TOO_SHORT);
        FUZZ_CHECK(written_short == 0);
    }
    memset(decoded, 0x5a, sizeof(decoded));
    FUZZ_CHECK(tlv_codec_decode(codec, encoded, written, decoded, sizeof(decoded), NULL) == TLV_OK);
    FUZZ_CHECK(strcmp(digits, decoded) == 0);
}

static void check_definition(const tlv_emv_definition_t* definition, const uint8_t* data,
                             size_t size) {
    if (!definition || !definition->codec) return;
    const tlv_emv_value_kind_t kind = tlv_emv_builtin_value_kind(definition);
    if (kind != TLV_EMV_VALUE_DIGITS && !fixed_capacity(kind)) return;
    const tlv_schema_entry_t* schema = definition->schema;
    FUZZ_CHECK(schema != NULL);
    const tlv_result_t length_result = tlv_schema_validate_length(schema, size);
    /* Builtin definitions are valid; a rejected wire length is a Schema finding,
     * distinct from invalid bytes in a representation of an admissible length. */
    FUZZ_CHECK(length_result == TLV_OK || length_result == TLV_ERR_SCHEMA);
    if (length_result == TLV_ERR_SCHEMA) {
        fuzz_codec_fixed_value value;
        tlv_codec_diagnostic_t diagnostic;
        FUZZ_CHECK(tlv_codec_decode(definition->codec, data, size, &value, sizeof value,
                                    &diagnostic) == TLV_ERR_SCHEMA);
        FUZZ_CHECK(diagnostic.diagnostic.code == TLV_ERR_SCHEMA);
        FUZZ_CHECK(diagnostic.codec.reported == TLV_ERR_SCHEMA);
        FUZZ_CHECK(diagnostic.codec.operation == TLV_CODEC_OP_DECODE);
        FUZZ_CHECK(diagnostic.codec.violation == TLV_CODEC_VIOLATION_NONE);
        FUZZ_CHECK(diagnostic.codec.cause == TLV_CODEC_CAUSE_SCHEMA);
        const tlv_schema_detail_t* detail = &diagnostic.codec.detail.schema;
        FUZZ_CHECK(detail->kind == TLV_SCHEMA_ISSUE_LENGTH && detail->has_length);
        FUZZ_CHECK(detail->min_length == schema->min_length);
        FUZZ_CHECK(detail->max_length == schema->max_length);
        FUZZ_CHECK(detail->actual_length == size);
        FUZZ_CHECK(detail->length_multiple == schema->length_multiple);
        FUZZ_CHECK(detail->length_flags == schema->flags);
        FUZZ_CHECK(tlv_codec_decode(definition->codec, data, size, &value, sizeof value, NULL) ==
                   TLV_ERR_SCHEMA);
        return;
    }
    if (kind == TLV_EMV_VALUE_DIGITS)
        check_digits(definition->codec, data, size);
    else
        check_fixed(definition->codec, kind, data, size);
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    int context;
    for (context = 0; context < TLV_EMV_CONTEXT_COUNT; ++context) {
        const tlv_emv_dictionary_t* dictionary = tlv_emv_dictionary_for((tlv_emv_context_t)context);
        size_t                      i;
        for (i = 0; i < dictionary->count; ++i)
            check_definition(&dictionary->entries[i], data, size);
    }
    return 0;
}
