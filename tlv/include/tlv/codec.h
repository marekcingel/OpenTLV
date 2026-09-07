#ifndef OPENTLV_CODEC_H
#define OPENTLV_CODEC_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Value-conversion errors are independent of TLV framing errors. */
typedef enum tlv_codec_result {
    TLV_CODEC_OK = 0,
    TLV_CODEC_ERR_NULL_ARG,
    TLV_CODEC_ERR_BUFFER_TOO_SHORT,
    TLV_CODEC_ERR_INVALID_VALUE,
    TLV_CODEC_ERR_UNSUPPORTED
} tlv_codec_result_t;

/* Borrowed descriptor and optional immutable context; no allocation or ownership
 * transfer. Each codec documents its C representation and required alignment.
 * Callers supply correctly typed/aligned objects; capacities/sizes are bytes.
 * Callbacks must respect bounds and must not require heap allocation.
 * Decode consumes the entire raw value and may return a representation borrowing
 * input bytes. That input must then outlive the representation.
 * Encode with data == NULL and capacity == 0 validates the value and reports its
 * exact encoded size without writing. Normal success reports bytes written.
 * Callbacks may be NULL for unsupported directions. Errors propagate unchanged.
 * On error, destination contents are unspecified; wrappers report written == 0.
 * Input and output must not overlap unless the codec explicitly supports it.
 */
typedef struct tlv_codec {
    const void* context;
    tlv_codec_result_t (*decode)(const void* context, const uint8_t* data,
                                size_t size, void* value, size_t capacity);
    tlv_codec_result_t (*encode)(const void* context, const void* value,
                                size_t size, uint8_t* data, size_t capacity,
                                size_t* written);
} tlv_codec_t;

/* value is required even for empty representations. Decode data may be NULL
 * only for size == 0. Encode data may be NULL only for a size query. written
 * is required and must not alias input or destination storage.
 */
tlv_codec_result_t tlv_codec_decode(const tlv_codec_t* codec,
                                    const uint8_t* data, size_t size,
                                    void* value, size_t capacity);
tlv_codec_result_t tlv_codec_encode(const tlv_codec_t* codec,
                                    const void* value, size_t size,
                                    uint8_t* data, size_t capacity,
                                    size_t* written);
const char* tlv_codec_strerror(tlv_codec_result_t result);

#ifdef __cplusplus
}
#endif

#endif /* OPENTLV_CODEC_H */
