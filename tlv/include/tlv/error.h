// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_ERROR_H
#define OPENTLV_ERROR_H

#include "tlv/export.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 * @ingroup core
 * @brief Result codes shared by every OpenTLV C function that can fail.
 */

/** @addtogroup core
 * @{
 */

/**
 * @brief Result code returned by OpenTLV C functions.
 *
 * Zero is success. #TLV_END and #TLV_NEED_MORE_DATA are control statuses, not
 * failures: #TLV_END ends an iteration normally and #TLV_NEED_MORE_DATA asks
 * for more non-final input. Other nonzero values are failures. Unless a function
 * states otherwise, a nonzero result leaves its output parameters unchanged.
 * Which codes a function can return is documented on that function.
 *
 * @note Numeric values are release-specific during the breaking failure-model
 * migration and are not a stable ABI numbering contract.
 * @see tlv_strerror
 */
typedef enum tlv_result {
    /** The operation succeeded. */
    TLV_OK = 0,
    /** Caller-supplied destination or workspace capacity is insufficient. Incomplete
       input is #TLV_ERR_TRUNCATED or #TLV_NEED_MORE_DATA instead. */
    TLV_ERR_BUFFER_TOO_SHORT = 1,
    /** A length is malformed or outside the wire encoding range. */
    TLV_ERR_INVALID_LENGTH = 2,
    /** A required pointer argument is `NULL`. */
    TLV_ERR_NULL_ARG = 3,
    /** An allocation failed. */
    TLV_ERR_OUT_OF_MEMORY = 4,
    /** Control status: normal end of an iteration, or an empty single-read region.
       No element is published. This is not a failure. */
    TLV_END = 5,
    /** A tag is malformed or invalid for the format or standard. */
    TLV_ERR_INVALID_TAG = 6,
    /** A visitor callback requested an error stop. */
    TLV_ERR_VISITOR = 7,
    /** A configured depth, size, or element-count limit was exceeded. */
    TLV_ERR_LIMIT = 8,
    /** Input violates a schema rule; see tlv_schema_validate(). */
    TLV_ERR_SCHEMA = 9,
    /** An API configuration or argument descriptor is invalid. */
    TLV_ERR_INVALID_ARG = 10,
    /** Tag size violates the range supported by the operation. */
    TLV_ERR_INVALID_TAG_SIZE = 11,
    /** Text does not match the requested language grammar, such as Query syntax. */
    TLV_ERR_SYNTAX = 12,
    /** Unsigned value cannot fit the requested numeric width. */
    TLV_ERR_OVERFLOW = 13,
    /** Data or its application representation is invalid for the requested interpretation. */
    TLV_ERR_INVALID_VALUE = 14,
    /** A valid requested type or capability is not supported by the implementation. */
    TLV_ERR_UNSUPPORTED = 15,
    /** A schema definition is invalid, independently of the input being validated. */
    TLV_ERR_INVALID_SCHEMA = 16,
    /** A valid logical quantity exceeds the host address space. */
    TLV_ERR_NATIVE_SIZE = 17,
    /** Non-final Reader input is exhausted or incomplete; supply more bytes or mark it final. */
    TLV_NEED_MORE_DATA = 18,
    /** The operation is not allowed in the object's current lifecycle state. */
    TLV_ERR_INVALID_STATE = 19,
    /** A callback violated its return-value or successful-output contract. */
    TLV_ERR_CALLBACK = 20,
    /** Final input ends inside a required representation (Tag, Length, Value or trailer).
       More output or workspace capacity cannot repair it; supply complete input. */
    TLV_ERR_TRUNCATED = 21
} tlv_result_t;

/**
 * @brief Returns a readable description of a result code.
 *
 * @param result Result code to describe.
 *
 * @return A static, NUL-terminated string, never `NULL`; an unrecognized
 *         value yields `"unknown error"`. The caller must not free or modify it.
 */
TLV_API const char* tlv_strerror(tlv_result_t result);

#ifdef __cplusplus
}
#endif

/** @} */

#endif /* OPENTLV_ERROR_H */
