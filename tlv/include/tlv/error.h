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
 * Zero is success; every other value is an error. Unless a function states
 * otherwise, an error leaves its output parameters unchanged. Which codes a
 * function can return is documented on that function.
 *
 * @see tlv_strerror
 */
typedef enum tlv_result {
    /** The operation succeeded. */
    TLV_OK = 0,
    /** A supplied buffer is too small for the data or output required. */
    TLV_ERR_BUFFER_TOO_SHORT = 1,
    /** A length is malformed, out of range, or not representable as `size_t`. */
    TLV_ERR_INVALID_LENGTH = 2,
    /** A required pointer argument is `NULL`. */
    TLV_ERR_NULL_ARG = 3,
    /** An allocation failed. */
    TLV_ERR_OUT_OF_MEMORY = 4,
    /** No further element exists, or the input is empty. */
    TLV_ERR_END_OF_BUFFER = 5,
    /** A tag is malformed or invalid for the format or profile. */
    TLV_ERR_INVALID_TAG = 6,
    /** A visitor callback requested an error stop. */
    TLV_ERR_VISITOR = 7,
    /** A configured depth, size, or element-count limit was exceeded. */
    TLV_ERR_LIMIT = 8,
    /** Input violates a schema rule; see tlv_schema_validate(). */
    TLV_ERR_SCHEMA = 9,
    /** An argument has an invalid value that no more specific code describes. */
    TLV_ERR_INVALID_ARG = 10,
    /** Tag size violates the range supported by the operation. */
    TLV_ERR_INVALID_TAG_SIZE = 11,
    /** Byte order is unknown or unsupported. */
    TLV_ERR_INVALID_BYTE_ORDER = 12,
    /** Unsigned value cannot fit the requested numeric width. */
    TLV_ERR_OVERFLOW = 13,
    /** Universal primitive content is malformed or fails a canonical DER rule. */
    TLV_ERR_INVALID_VALUE = 14,
    /** Universal tag number has no implemented canonical validation. */
    TLV_ERR_UNSUPPORTED_TYPE = 15,
    /**
     * A required field is absent (tlv_schema_validate()).
     *
     * Reported when a rule's `min_occurs` exceeds its actual occurrence
     * count. It is distinct from #TLV_ERR_SCHEMA because its error offset is
     * the end of the enclosing parent's value: a scope boundary, not an
     * element. That offset can coincide with the start of an unrelated
     * sibling in the parent scope, so a tag read there is not reliably the
     * cause.
     *
     * Every other tlv_schema_validate() violation (forbidden or unknown tag,
     * duplicate or excess occurrence, kind mismatch, invalid rule table)
     * returns #TLV_ERR_SCHEMA with an offset anchored to the actual element.
     */
    TLV_ERR_SCHEMA_MISSING = 16
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
