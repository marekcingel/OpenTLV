#ifndef OPENTLV_CODEC_STRUCTURE_H
#define OPENTLV_CODEC_STRUCTURE_H
#include "tlv/codec/codec.h"
#include "tlv/schema/schema.h"
#include "tlv/export.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 * @ingroup codecs
 * @brief Codec bindings between a complete TLV sequence and one application object.
 */

/** @addtogroup codecs
 * @{
 */

/**
 * @brief Descriptor mapping a complete TLV sequence to one caller-owned application object.
 *
 * Object bindings belong to the codec layer. The descriptor maps a complete
 * sequence, including nested elements, to a single application object. No tag
 * is prescribed for the complete object.
 *
 * Reader format, writer format, schema and context are all borrowed and must
 * outlive every use of the descriptor. The `decode` and `encode` callbacks
 * follow the alignment, ownership, capacity, overlap and error contracts of
 * #tlv_codec_t and receive their direction's format explicitly. They must be
 * stable across sizing and writing and must consume or produce the complete
 * sequence.
 *
 * Decode validates the entire structure before invoking the callback. Encode
 * validates the produced bytes before reporting success; a `NULL`/0 size
 * query relies on the callback to validate the object without producing
 * bytes. On any error the destination is unspecified and `written` is zero.
 *
 * @see tlv_structure_decode, tlv_structure_encode
 */
typedef struct tlv_structure_codec {
    /** Borrowed context passed to the object callbacks only; may be `NULL`. */
    const void* context;
    /**
     * Borrowed reader format. Required for decode and for validating encoded bytes.
     */
    const tlv_reader_format_t* reader_format;
    /**
     * Borrowed writer format. Required only for encode; decode-only codecs may use `NULL`.
     * Must describe the same wire encoding as `reader_format` for encode validation.
     */
    const tlv_writer_format_t* writer_format;
    /**
     * Optional nesting predicate; receives `reader_format->context`. `NULL`
     * makes every value opaque.
     */
    tlv_is_constructed_fn is_constructed;
    /** Optional borrowed schema; `NULL` validates framing and nesting only. */
    const tlv_structure_schema_t* schema;
    /**
     * Maximum nesting depth, following tlv_walk_tree() conventions. Zero is a
     * real limit; a value out of range returns #TLV_CODEC_ERR_INVALID_VALUE.
     */
    size_t max_depth;
    /** Maximum element count, following tlv_walk_tree() conventions. Zero is a real limit. */
    size_t max_elements;
    /** Converts a validated sequence to the application object; `NULL` if unsupported. */
    tlv_codec_result_t (*decode)(const void* context, const tlv_reader_format_t* format,
                                 const uint8_t* data, size_t size, void* value, size_t capacity);
    /** Converts the application object to a sequence; `NULL` if unsupported. */
    tlv_codec_result_t (*encode)(const void* context, const tlv_writer_format_t* format,
                                 const void* value, size_t size, uint8_t* data, size_t capacity,
                                 size_t* written);
} tlv_structure_codec_t;

/**
 * @brief Validates and decodes a complete sequence into an application object.
 *
 * The entire structure is validated against the descriptor's limits and
 * schema before the `decode` callback is invoked.
 *
 * @param[in]  codec    Structure codec descriptor.
 * @param[in]  data     Encoded sequence.
 * @param[in]  size     Size of `data` in bytes.
 * @param[out] value    Destination object, correctly typed and aligned.
 * @param[in]  capacity Size of `value` in bytes.
 *
 * @return #TLV_CODEC_OK on success.
 * @return #TLV_CODEC_ERR_NULL_ARG for missing required arguments.
 * @return #TLV_CODEC_ERR_INVALID_STRUCTURE if validation fails.
 * @return #TLV_CODEC_ERR_INVALID_VALUE if `max_depth` is out of range.
 * @return #TLV_CODEC_ERR_UNSUPPORTED if the descriptor has no decoder.
 *
 * @warning On error the contents of `value` are unspecified. The decoded
 *          object may borrow `data`, which must then outlive it.
 */
TLV_API tlv_codec_result_t tlv_structure_decode(const tlv_structure_codec_t* codec,
                                                const uint8_t* data, size_t size, void* value,
                                                size_t capacity);

/**
 * @brief Encodes an application object into a complete, validated sequence.
 *
 * With `data == NULL` and `capacity == 0` the call is a size query; the
 * `encode` callback is relied on to validate the object without producing
 * bytes.
 *
 * @param[in]  codec    Structure codec descriptor.
 * @param[in]  value    Application object to encode.
 * @param[in]  size     Size of `value` in bytes.
 * @param[out] data     Destination bytes; `NULL` only for a size query.
 * @param[in]  capacity Destination capacity in bytes.
 * @param[out] written  Receives the bytes written, or the required size for a query.
 *
 * @return #TLV_CODEC_OK on success.
 * @return #TLV_CODEC_ERR_NULL_ARG for missing required arguments.
 * @return #TLV_CODEC_ERR_BUFFER_TOO_SHORT if `capacity` is insufficient.
 * @return #TLV_CODEC_ERR_INVALID_STRUCTURE if the produced bytes fail validation.
 * @return #TLV_CODEC_ERR_INVALID_VALUE if `max_depth` is out of range.
 * @return #TLV_CODEC_ERR_UNSUPPORTED if the descriptor has no encoder.
 *
 * @warning On error the destination is unspecified and `*written` is zero.
 */
TLV_API tlv_codec_result_t tlv_structure_encode(const tlv_structure_codec_t* codec,
                                                const void* value, size_t size, uint8_t* data,
                                                size_t capacity, size_t* written);
#ifdef __cplusplus
}
#endif
/** @} */

#endif
