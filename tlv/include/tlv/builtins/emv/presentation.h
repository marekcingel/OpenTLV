// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_BUILTINS_EMV_PRESENTATION_H
#define OPENTLV_BUILTINS_EMV_PRESENTATION_H

#include "tlv/builtins/emv/emv.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @file
 * @ingroup codecs
 * @brief Optional display and typed binding adapter for the builtin EMV profile.
 * This adapter is not part of dictionary resolution or codec execution.
 */

/**
 * @brief Optional presentation categories for immutable builtin EMV entries.
 *
 * These categories are not dictionary state and are not a runtime type system.
 *
 * #TLV_EMV_VALUE_BYTES, #TLV_EMV_VALUE_TEXT and #TLV_EMV_VALUE_TEMPLATE have
 * no codec: callers retain the reader's borrowed value. Text does not imply
 * UTF-8 or a terminating NUL. #TLV_EMV_VALUE_FLAGS preserves every wire bit,
 * including RFU bits, in a big-endian integer.
 *
 * @see tlv_emv_value_kind_description
 */
typedef enum {
    /** Opaque bytes; no codec. */
    TLV_EMV_VALUE_BYTES,
    /** Text bytes, not necessarily UTF-8 or NUL-terminated; no codec. */
    TLV_EMV_VALUE_TEXT,
    /** Semantic template of nested data objects; no codec. May have a primitive wire bit. */
    TLV_EMV_VALUE_TEMPLATE,
    /** `uint64_t`: binary or decimal BCD number. */
    TLV_EMV_VALUE_NUMBER,
    /** `uint64_t`: bit flags, every wire bit preserved. */
    TLV_EMV_VALUE_FLAGS,
    /** `char[]`: NUL-terminated decimal digits. */
    TLV_EMV_VALUE_DIGITS,
    /** #tlv_emv_date_t. */
    TLV_EMV_VALUE_DATE,
    /** #tlv_emv_time_t. */
    TLV_EMV_VALUE_TIME,
    /** #tlv_emv_account_type_t. */
    TLV_EMV_VALUE_ACCOUNT,
    /** #tlv_emv_cryptogram_info_t. */
    TLV_EMV_VALUE_CRYPTOGRAM,
    /** #tlv_emv_biometric_type_t. */
    TLV_EMV_VALUE_BIOMETRIC,
    /** #tlv_emv_number_list_t. */
    TLV_EMV_VALUE_NUMBER_LIST,
    /** #tlv_emv_afl_t. */
    TLV_EMV_VALUE_AFL,
    /** #tlv_emv_cvm_result_t. */
    TLV_EMV_VALUE_CVM_RESULT,
    /** #tlv_emv_track2_t. */
    TLV_EMV_VALUE_TRACK2,
    /** Not an entry in the builtin presentation profile. */
    TLV_EMV_VALUE_UNKNOWN
} tlv_emv_value_kind_t;

/** @brief Returns the presentation contract of an immutable builtin entry.
 * @param[in] definition Entry returned by tlv_emv_find() or a builtin dictionary.
 * @return Builtin presentation category, or #TLV_EMV_VALUE_UNKNOWN for NULL or
 *         an object outside the builtin tables.
 * @note This is an explicit builtin presentation profile, not codec discovery.
 * No callback identity or codec context is inspected. Caller-owned dictionaries
 * and runtime modules select their application representation themselves and
 * invoke their codecs directly; they do not need this adapter. Copies and custom
 * entries are deliberately excluded, even if their tag matches a builtin tag.
 */
TLV_API tlv_emv_value_kind_t tlv_emv_builtin_value_kind(const tlv_emv_definition_t* definition);

/**
 * @brief Describes a value kind's C representation and wire meaning.
 *
 * Intended for diagnostics or tooling, for example `"Bit flags"` for
 * #TLV_EMV_VALUE_FLAGS.
 *
 * @param kind Value kind to describe.
 *
 * @return A static, NUL-terminated description, never `NULL`. Every declared
 *         kind has one; any other value returns `"Unspecified representation"`.
 */
TLV_API const char* tlv_emv_value_kind_description(tlv_emv_value_kind_t kind);

#ifdef __cplusplus
}
#endif
#endif
