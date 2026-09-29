#ifndef OPENTLV_SCHEMA_NUMBER_H
#define OPENTLV_SCHEMA_NUMBER_H

#include "tlv/schema/schema.h"
#include "tlv/codec/number.h"

/** @file
 * @ingroup schemas
 * @brief Optional composition of field Schema and numeric Value conversion.
 *
 * The numeric primitive owns representation; Schema owns field-length validity.
 * This adapter selects a permitted output width without knowing an element tag.
 */
#ifdef __cplusplus
extern "C" {
#endif

/** @brief Borrowed field Schema composed with a uint64_t representation.
 * Configuration and referenced Schema must remain immutable and alive while
 * used. No allocation, tag lookup or ownership transfer occurs. Width zero
 * selects the shortest schema-permitted representation that fits. A fixed
 * width must satisfy Schema; it is never silently changed to another width.
 */
typedef struct tlv_schema_number {
    /** Required authoritative field constraints. */
    const tlv_schema_entry_t* schema;
    /** Numeric representation; contains no copy of field-length rules. */
    tlv_number_codec_config_t representation;
} tlv_schema_number_t;

/** @brief Validates field length, then delegates numeric decoding.
 * @param[in] context Required immutable #tlv_schema_number_t with a non-NULL schema.
 * @param[in] data Readable Value bytes; NULL only for size zero.
 * @param[in] size Value byte count.
 * @param[out] value Required uint64_t destination, disjoint from input/configuration.
 * @param[in] capacity Destination capacity in bytes.
 * @return #TLV_CODEC_ERR_NULL_ARG for missing pointers, #TLV_CODEC_ERR_INVALID_VALUE
 *         for a schema violation, otherwise the result of tlv_number_decode().
 * @note Output is unchanged on failure; no allocation occurs.
 */
TLV_API tlv_codec_result_t tlv_schema_number_decode(const void* context, const uint8_t* data,
                                                    size_t size, void* value, size_t capacity);

/** @brief Selects a fitting schema-permitted width, then delegates numeric encoding.
 * @param[in] context Required immutable #tlv_schema_number_t with a non-NULL schema.
 * @param[in] value Required readable uint64_t object.
 * @param[in] size Exactly sizeof(uint64_t).
 * @param[out] data Output, or NULL with zero capacity for a validated size query.
 * @param[in] capacity Output byte capacity.
 * @param[out] written Required byte count, zero on failure.
 * @return #TLV_CODEC_ERR_NULL_ARG for missing pointers, #TLV_CODEC_ERR_INVALID_VALUE
 *         if no supported width fits Schema, otherwise tlv_number_encode()'s result.
 * @note Output is unchanged on failure. All input storage, output, configuration
 *       and written must be disjoint. No allocation occurs.
 */
TLV_API tlv_codec_result_t tlv_schema_number_encode(const void* context, const void* value,
                                                    size_t size, uint8_t* data, size_t capacity,
                                                    size_t* written);

/** @brief Creates a codec borrowing an explicit Schema/number composition.
 * @param[in] config Borrowed immutable composition, validated on invocation.
 * @return Descriptor; NULL configuration fails when invoked.
 */
static inline tlv_codec_t tlv_schema_number_codec(const tlv_schema_number_t* config) {
    tlv_codec_t codec = {config, tlv_schema_number_decode, tlv_schema_number_encode};
    return codec;
}

#ifdef __cplusplus
}
#endif
#endif
