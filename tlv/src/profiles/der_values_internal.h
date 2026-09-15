#ifndef OPENTLV_DER_VALUES_INTERNAL_H
#define OPENTLV_DER_VALUES_INTERNAL_H
#include "tlv/error.h"
#include <stdint.h>
#include <stddef.h>

/* Validates one primitive UNIVERSAL element's content for DER canonical rules.
 * number is its tag number (already extracted and validated by the caller);
 * value/length describe its content, which is never NULL when length is nonzero.
 * Returns TLV_OK, TLV_ERR_INVALID_VALUE (malformed or noncanonical content), or
 * TLV_ERR_UNSUPPORTED_TYPE (no canonical rule implemented for this tag number).
 * No allocation and no recursion; a single bounded pass over the content. */
tlv_result_t tlv_der_validate_universal_value(uint64_t number, const uint8_t* value, size_t length);

#endif /* OPENTLV_DER_VALUES_INTERNAL_H */
