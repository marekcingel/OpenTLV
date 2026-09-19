#ifndef OPENTLV_ERROR_H
#define OPENTLV_ERROR_H

#include "tlv/export.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum tlv_result {
    TLV_OK = 0,
    TLV_ERR_BUFFER_TOO_SHORT = 1,
    TLV_ERR_INVALID_LENGTH = 2,
    TLV_ERR_NULL_ARG = 3,
    TLV_ERR_OUT_OF_MEMORY = 4,
    TLV_ERR_END_OF_BUFFER = 5,
    TLV_ERR_INVALID_TAG = 6,
    TLV_ERR_VISITOR = 7,
    TLV_ERR_LIMIT = 8,
    TLV_ERR_SCHEMA = 9,
    TLV_ERR_INVALID_ARG = 10,
    /* Tag size violates the range supported by the operation. */
    TLV_ERR_INVALID_TAG_SIZE = 11,
    /* Byte order is unknown or unsupported. */
    TLV_ERR_INVALID_BYTE_ORDER = 12,
    /* Unsigned value cannot fit the requested numeric width. */
    TLV_ERR_OVERFLOW = 13,
    /* Universal primitive content is malformed or fails a canonical DER rule. */
    TLV_ERR_INVALID_VALUE = 14,
    /* Universal tag number has no implemented canonical validation. */
    TLV_ERR_UNSUPPORTED_TYPE = 15,
    /* tlv_schema_validate(): a required field (min_occurs > its actual
     * count) is absent. Distinct from TLV_ERR_SCHEMA because its offset is
     * the end of the enclosing parent's value - a scope boundary, not an
     * element - and can coincide with the start of an unrelated sibling in
     * the parent scope; a tag read at that offset is not reliably the cause.
     * Every other tlv_schema_validate() violation (forbidden/unknown tag,
     * duplicate/excess occurrence, kind mismatch, invalid rule table)
     * returns TLV_ERR_SCHEMA with an offset anchored to the actual element.
     */
    TLV_ERR_SCHEMA_MISSING = 16
} tlv_result_t;

/* Returns a readable description of an error code (static string; no need to free). */
TLV_API const char* tlv_strerror(tlv_result_t result);

#ifdef __cplusplus
}
#endif

#endif /* OPENTLV_ERROR_H */
