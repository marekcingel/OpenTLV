// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#ifndef OPENTLV_CODEC_DIAGNOSTIC_H
#define OPENTLV_CODEC_DIAGNOSTIC_H
#include "tlv/reader/diagnostic.h"
#include "tlv/schema/schema.h"
#ifdef __cplusplus
extern "C" {
#endif
/** @file
 * @brief Optional allocation-free conversion diagnostics and delegated causes.
 */
/** @brief Conversion operation at the diagnostic boundary. */
typedef enum tlv_codec_operation {
    TLV_CODEC_OP_DECODE, /**< Decode complete Value or structure bytes. */
    TLV_CODEC_OP_ENCODE, /**< Encode an application representation. */
    TLV_CODEC_OP_MEASURE /**< Validate and measure without writing. */
} tlv_codec_operation_t;
/** @brief Origin of the optional delegated cause. */
typedef enum tlv_codec_cause {
    TLV_CODEC_CAUSE_NONE,   /**< No lower-layer detail was supplied. */
    TLV_CODEC_CAUSE_READER, /**< Reader detail is active. */
    TLV_CODEC_CAUSE_SCHEMA  /**< Schema detail is active. */
} tlv_codec_cause_t;
/** @brief Detected callback contract violation, independent of a returned failure. */
typedef enum tlv_codec_violation {
    TLV_CODEC_VIOLATION_NONE,   /**< No detected callback breach. */
    TLV_CODEC_VIOLATION_RESULT, /**< Unknown or forbidden control result. */
    TLV_CODEC_VIOLATION_SIZE,   /**< Successful output exceeds caller storage. */
    TLV_CODEC_VIOLATION_TYPE,   /**< Successful conversion has the wrong type or span. */
    TLV_CODEC_VIOLATION_UTF8    /**< Successful text result is not valid UTF-8. */
} tlv_codec_violation_t;
/** @brief Schema cause fields without a second copy of the common diagnostic.
 * @note Tag, field and definition owner borrow the original input/schema.
 */
typedef struct tlv_codec_schema_detail {
    tlv_schema_issue_kind_t kind;                /**< Schema issue. */
    tlv_tag_t tag;                               /**< Affected identifier. */
    tlv_schema_definition_location_t definition; /**< Native definition evidence. */
    const char* field;                           /**< Borrowed field name. */
    int is_group;                                /**< Group rather than individual rule. */
    int has_occurs;                              /**< Occurrence fields are active. */
    size_t min_occurs;                           /**< Minimum occurrences. */
    size_t max_occurs;                           /**< Maximum occurrences. */
    size_t occurs;                               /**< Observed occurrences. */
    int has_length;                              /**< Length fields are active. */
    size_t min_length;                           /**< Minimum length. */
    size_t max_length;                           /**< Maximum length. */
    size_t actual_length;                        /**< Observed length. */
    int has_form;                                /**< Form fields are active. */
    tlv_schema_kind_t expected_form;             /**< Required form. */
    int actual_constructed;                      /**< Observed constructed flag. */
    size_t length_multiple;                      /**< Required length multiple. */
    uint32_t length_flags;                       /**< Schema length policy. */
} tlv_codec_schema_detail_t;
/** @brief Conversion detail accompanying one shared common diagnostic.
 * @note Only the member selected by cause is active. All borrows must outlive copies.
 */
typedef struct tlv_codec_detail {
    tlv_codec_operation_t operation; /**< Conversion operation. */
    tlv_result_t reported; /**< Provider result, including OK for a bad success payload. */
    tlv_codec_violation_t violation; /**< Detected callback breach. */
    const char* representation;      /**< Optional borrowed static representation name. */
    tlv_codec_cause_t cause;         /**< Active delegated detail. */
    union {
        tlv_reader_detail_t reader;       /**< Reader cause. */
        tlv_codec_schema_detail_t schema; /**< Schema cause. */
    } detail;                             /**< Discriminated lower-layer detail. */
} tlv_codec_detail_t;
/** @brief Copyable conversion diagnostic with one common location/path.
 * @note Caller-owned and optional. NULL avoids collecting detail. Callback diagnostics
 * must not point to temporary stack storage. All non-OK publications carry the returned
 * result in diagnostic.code; unknown detail/location remain unset.
 */
typedef struct tlv_codec_diagnostic {
    tlv_diagnostic_t diagnostic; /**< Common result, location and borrowed contexts. */
    tlv_codec_detail_t codec;    /**< Conversion and delegated cause. */
} tlv_codec_diagnostic_t;
/** @brief Clear optional conversion evidence for a new operation.
 * @param[out] diagnostic Optional destination.
 * @param[in] operation Conversion operation.
 */
TLV_API void tlv_codec_diagnostic_init(tlv_codec_diagnostic_t* diagnostic,
                                       tlv_codec_operation_t operation);
/** @brief Publish a conversion result without discarding supplied cause evidence.
 * @param[out] diagnostic Optional initialized destination.
 * @param[in] result Result to publish unchanged.
 * @return result. Decode may preserve NEED_MORE_DATA with informational severity.
 */
static inline tlv_result_t tlv_codec_diagnostic_result(tlv_codec_diagnostic_t* diagnostic,
                                                       tlv_result_t result) {
    if (diagnostic) {
        if (diagnostic->codec.violation == TLV_CODEC_VIOLATION_NONE)
            diagnostic->codec.reported = result;
        diagnostic->diagnostic.code = result;
        diagnostic->diagnostic.severity = result == TLV_OK || result == TLV_NEED_MORE_DATA
                                              ? TLV_DIAGNOSTIC_SEVERITY_INFO
                                              : TLV_DIAGNOSTIC_SEVERITY_ERROR;
    }
    return result;
}
#ifdef __cplusplus
}
#endif
#endif
