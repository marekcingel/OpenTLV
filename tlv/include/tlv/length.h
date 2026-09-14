#ifndef OPENTLV_LENGTH_H
#define OPENTLV_LENGTH_H

#include "tlv/error.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Logical TLV value length. Always a 64-bit unsigned range, independent of
 * build configuration, the current build's size_t width, or wire format.
 * It may hold a value that cannot be used as an in-memory buffer length in
 * the current build; use the conversions below before native-size use. */
typedef uint64_t tlv_length_t;

/* Checked, lossless conversion from a native size. Every size_t value fits
 * tlv_length_t, so this cannot fail for its numeric domain. length is
 * required and must be non-NULL; NULL returns TLV_ERR_NULL_ARG and leaves
 * *length unchanged. */
tlv_result_t tlv_length_from_size(size_t size, tlv_length_t* length);

/* Checked, narrowing conversion to the current build's native size. Lengths
 * greater than SIZE_MAX are rejected with TLV_ERR_INVALID_LENGTH, leaving
 * *size unchanged. size is required and checked before the range comparison.
 * Passing this conversion does not prove that a buffer of that size exists,
 * is accessible, or has sufficient capacity; actual bounds remain the
 * caller's responsibility. */
tlv_result_t tlv_length_to_size(tlv_length_t length, size_t* size);

/* Reports whether length fits the current build's size_t range without
 * converting it or accessing any memory. Returns TLV_OK when it fits and
 * TLV_ERR_INVALID_LENGTH otherwise. Passing this check does not prove that
 * a buffer exists, is accessible, or has sufficient capacity. */
tlv_result_t tlv_length_validate_native(tlv_length_t length);

#ifdef __cplusplus
}
#endif

#endif /* OPENTLV_LENGTH_H */
