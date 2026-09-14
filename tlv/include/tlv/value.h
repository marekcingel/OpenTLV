#ifndef OPENTLV_VALUE_H
#define OPENTLV_VALUE_H

#include "tlv/error.h"
#include "tlv/length.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Non-owning, read-only TLV value. The caller owns the storage and keeps it
 * alive; no allocation, copying, or ownership transfer occurs. data may be
 * NULL only when length is zero. length may exceed what the current build's
 * size_t can address; validate with tlv_length_validate_native or convert
 * with tlv_length_to_size before pointer arithmetic, memory access, or
 * narrowing. */
typedef struct {
    const uint8_t* data;
    tlv_length_t length;
} tlv_value_t;

/* Checked initialization into caller-owned storage. Overlap with existing
 * contents of *value is not a concern; nothing is read from it. Required
 * null pointers (data when length is nonzero, value) return TLV_ERR_NULL_ARG,
 * checked before the native-length range. A length that cannot be
 * represented by the current build's size_t returns TLV_ERR_INVALID_LENGTH.
 * value is unchanged on every failure. Actual allocation bounds for data
 * remain the caller's responsibility; no memory is accessed. */
tlv_result_t tlv_value_init(const uint8_t* data, tlv_length_t length,
                            tlv_value_t* value);

/* Validates representation and pointer requirements only: data must be
 * non-NULL unless length is zero, and length must be representable by the
 * current build's size_t. Does not access memory and does not prove
 * sufficient allocation bounds. NULL value returns TLV_ERR_NULL_ARG. */
tlv_result_t tlv_value_validate(const tlv_value_t* value);

#ifdef __cplusplus
}
#endif

#endif /* OPENTLV_VALUE_H */
