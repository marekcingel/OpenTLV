#ifndef OPENTLV_FORMAT_H
#define OPENTLV_FORMAT_H

#include "tlv/error.h"
#include "tlv/element.h"
#include "tlv/length.h"
#include "tlv/export.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 * @ingroup formats
 * @brief Canonical wire-to-element contract and borrowed source information.
 *
 * Formats alone interpret wire rules. Decode produces a semantic element and
 * framing/source information; encode regenerates a representation of that
 * element. For a bidirectional format, successful encoding must decode to an
 * equal identifier and equal value bytes. Exact source reproduction is the
 * separate tlv_source_preserve() operation. No operation allocates.
 */

/** @addtogroup formats
 * @{
 */

/**
 * @brief An optional, buffer-relative field range.
 */
typedef struct tlv_range {
    /** Byte offset relative to the element start. */
    size_t offset;
    /** Number of available bytes, never beyond the supplied buffer. */
    size_t size;
    /** Nonzero when this range is known; zero is distinct from an empty range. */
    int present;
} tlv_range_t;

/**
 * @brief Wire region involved in an operation.
 */
typedef enum tlv_region {
    TLV_REGION_HEADER = 0, /**< Entire header or an otherwise unnamed header field. */
    TLV_REGION_TAG,        /**< Identifier field. */
    TLV_REGION_LENGTH,     /**< Encoded length field. */
    TLV_REGION_VALUE,      /**< Semantic value bytes. */
    TLV_REGION_TRAILER     /**< Trailing framing. */
} tlv_region_t;

/**
 * @brief Format-produced failure detail, initialized to zero by the caller.
 */
typedef struct tlv_format_error {
    tlv_region_t region; /**< Region being interpreted. */
    size_t offset;       /**< Known failure position relative to the input/output start. */
    int has_offset;      /**< Whether offset is known. */
    tlv_size_t required; /**< Expected logical extent, when known. */
    int has_required;    /**< Whether required is known. */
    tlv_range_t tag;     /**< Available identifier field. */
    tlv_range_t length;  /**< Available length bytes, including truncated prefixes. */
    tlv_range_t value;   /**< Known available value range. */
} tlv_format_error_t;

/**
 * @brief Logical framing sizes, before any native buffer conversion.
 */
typedef struct tlv_encoding {
    tlv_size_t header;  /**< Bytes preceding Value. */
    tlv_size_t value;   /**< Semantic Value bytes. */
    tlv_size_t trailer; /**< Bytes following Value. */
    tlv_size_t total;   /**< Checked sum of header, value and trailer. */
} tlv_encoding_t;

struct tlv_format;

/**
 * @brief Immutable borrowed representation of one decoded element.
 *
 * All ranges are relative to data. Header, value and trailer partition size.
 * The source buffer, descriptor and its immutable context must outlive this
 * value. Copying only copies descriptors. Never modify the source buffer while
 * a source is live. Mutation of an element does not mutate this source.
 */
typedef struct tlv_source {
    const uint8_t* data;             /**< Original encoded bytes. */
    size_t size;                     /**< Complete native encoded extent. */
    tlv_range_t header;              /**< Header, possibly empty. */
    tlv_range_t tag;                 /**< Optional explicit identifier field. */
    tlv_range_t length;              /**< Optional explicit length field. */
    tlv_range_t value;               /**< Value, possibly empty. */
    tlv_range_t trailer;             /**< Trailer, possibly empty. */
    tlv_element_t element;           /**< Original semantic value for mutation checks. */
    const struct tlv_format* format; /**< Borrowed originating descriptor. */
} tlv_source_t;

/**
 * @brief Complete decode result; published only on successful decoding.
 */
typedef struct tlv_decoded {
    tlv_element_t element; /**< Canonical content. */
    tlv_source_t source;   /**< Original representation and ranges. */
} tlv_decoded_t;

/**
 * @brief Decode one complete element and validate its framing.
 *
 * @param[in]  context Borrowed immutable format configuration.
 * @param[in]  data    Input bytes; NULL only when size is zero.
 * @param[in]  size    Available native bytes.
 * @param[out] result  Element and source ranges on success.
 * @param[out] error   Partial failure information; always non-NULL.
 *
 * @return #TLV_OK on success.
 * @return A wire or buffer error reported by the format.
 *
 * @note Callbacks never allocate or retain data. The core initializes outputs.
 */
typedef tlv_result_t (*tlv_decode_fn)(const void* context, const uint8_t* data, size_t size,
                                      tlv_decoded_t* result, tlv_format_error_t* error);

/**
 * @brief Compute exact logical framing sizes and validate encoding constraints.
 *
 * @param[in]  context  Borrowed immutable configuration.
 * @param[in]  element  Semantic input. A NULL value pointer with nonzero size is
 * permitted for a size-only query if this format does not inspect content.
 * @param[out] encoding Exact framing sizes on success.
 * @param[out] error    Failure information; always non-NULL.
 *
 * @return #TLV_OK on success.
 * @return #TLV_ERR_OVERFLOW if logical size arithmetic overflows.
 * @return A format error if the semantic input cannot be represented.
 */
typedef tlv_result_t (*tlv_measure_fn)(const void* context, const tlv_element_t* element,
                                       tlv_encoding_t* encoding, tlv_format_error_t* error);

/**
 * @brief Encode a complete header, value and trailer into sufficient storage.
 *
 * @param[in]  context  Borrowed immutable configuration.
 * @param[in]  element  Valid readable semantic input; must not overlap data.
 * @param[out] data     Output buffer.
 * @param[in]  capacity Native writable extent.
 * @param[out] written  Complete bytes written on success.
 * @param[out] error    Failure information; always non-NULL.
 *
 * @return #TLV_OK on success.
 * @return A format error if encoding fails.
 *
 * @warning On failure, destination bytes are unspecified.
 */
typedef tlv_result_t (*tlv_encode_fn)(const void* context, const tlv_element_t* element,
                                      uint8_t* data, size_t capacity, size_t* written,
                                      tlv_format_error_t* error);

/**
 * @brief Identify a value containing elements in this same format.
 *
 * @param[in] context Borrowed configuration.
 * @param[in] tag     Successfully decoded identifier, possibly absent.
 *
 * @return Nonzero for a constructed value; zero for an opaque value.
 */
typedef int (*tlv_is_constructed_fn)(const void* context, const tlv_tag_t* tag);

/**
 * @brief Lightweight canonical wire-format descriptor.
 *
 * Context is caller-owned, borrowed and immutable. Reading uses decode only;
 * writing requires measure and encode together. No legacy field callback path
 * exists in Reader/Writer. NULL is_constructed means all values are opaque.
 */
typedef struct tlv_format {
    const void* context;                  /**< Borrowed immutable configuration. */
    tlv_decode_fn decode;                 /**< Complete framing decoder, or NULL. */
    tlv_measure_fn measure;               /**< Logical sizing, or NULL with encode. */
    tlv_encode_fn encode;                 /**< Complete encoder, or NULL with measure. */
    tlv_is_constructed_fn is_constructed; /**< Optional nesting predicate. */
} tlv_format_t;

/**
 * @brief Initialize a descriptor without allocation.
 *
 * @param[out] format  Destination, unchanged on failure.
 * @param[in]  context Borrowed immutable configuration; may be NULL.
 * @param[in]  decode  Decoder, or NULL for write-only.
 * @param[in]  measure Sizing callback; paired with encode.
 * @param[in]  encode  Encoder; paired with measure.
 *
 * @return #TLV_OK on success.
 * @return #TLV_ERR_INVALID_ARG for a `NULL` destination, incomplete write
 *         capability or no capabilities.
 */
TLV_API tlv_result_t tlv_format_init(tlv_format_t* format, const void* context,
                                     tlv_decode_fn decode, tlv_measure_fn measure,
                                     tlv_encode_fn encode);

/**
 * @brief Return nonzero if format has decoding capability; NULL returns zero.
 */
TLV_API int tlv_format_can_read(const tlv_format_t* format);

/**
 * @brief Return nonzero if format has complete encoding capability; NULL returns zero.
 */
TLV_API int tlv_format_can_write(const tlv_format_t* format);

/**
 * @brief Decode and validate one complete element, preserving source information.
 *
 * @param[in]  format  Borrowed readable descriptor.
 * @param[in]  data    Input, NULL only when size is zero.
 * @param[in]  size    Native available extent.
 * @param[out] decoded Complete result, unchanged on failure.
 * @param[out] error   Optional failure detail; unchanged on success.
 *
 * @return #TLV_OK on success.
 * @return #TLV_ERR_END_OF_BUFFER if the input is empty.
 * @return #TLV_ERR_NULL_ARG for a missing required argument or decode callback.
 * @return #TLV_ERR_INVALID_ARG if the decoder produces inconsistent source ranges.
 * @return Any decoder error, propagated unchanged.
 */
TLV_API tlv_result_t tlv_format_decode(const tlv_format_t* format, const uint8_t* data, size_t size,
                                       tlv_decoded_t* decoded, tlv_format_error_t* error);

/**
 * @brief Compute exact logical sizes without requiring a destination buffer.
 *
 * @param[in]  format   Writable descriptor.
 * @param[in]  element  Input; content-dependent formats require readable value bytes.
 * @param[out] encoding Logical result, unchanged on failure.
 * @param[out] error    Optional failure detail.
 *
 * @return #TLV_OK on success.
 * @return #TLV_ERR_OVERFLOW if logical size arithmetic overflows.
 * @return #TLV_ERR_NULL_ARG for a missing required argument or write capability.
 * @return #TLV_ERR_INVALID_ARG if the measured framing sizes are inconsistent.
 * @return Any measurement error, propagated unchanged.
 */
TLV_API tlv_result_t tlv_format_measure(const tlv_format_t* format, const tlv_element_t* element,
                                        tlv_encoding_t* encoding, tlv_format_error_t* error);

/**
 * @brief Encode semantic content using the format's configured policy.
 *
 * @param[in]  format   Writable descriptor.
 * @param[in]  element  Readable input, not overlapping output.
 * @param[out] data     Destination; NULL only when capacity is zero.
 * @param[in]  capacity Native capacity.
 * @param[out] written  Bytes written; required capacity on buffer shortage.
 * @param[out] error    Optional failure detail.
 *
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NATIVE_SIZE if the encoded size exceeds `SIZE_MAX`.
 * @return #TLV_ERR_BUFFER_TOO_SHORT if the destination cannot hold the element.
 * @return #TLV_ERR_NULL_ARG for a missing required argument or write capability.
 * @return #TLV_ERR_INVALID_LENGTH if the encoded size differs from measurement.
 * @return Any measurement or encoder error, propagated unchanged.
 *
 * @note Preflight errors leave destination unchanged; callback errors may modify it.
 */
TLV_API tlv_result_t tlv_format_encode(const tlv_format_t* format, const tlv_element_t* element,
                                       uint8_t* data, size_t capacity, size_t* written,
                                       tlv_format_error_t* error);

/**
 * @brief Reproduce immutable source bytes only if element still equals the source.
 *
 * This does not re-encode, convert formats, or reuse stale framing after mutation.
 * The source descriptor/configuration and bytes must remain alive and unchanged.
 * Overlapping source/destination is supported. NULL data with zero capacity queries size.
 *
 * @param[in]  source   Original successful decode result's source.
 * @param[in]  element  Current semantic content, checked byte-for-byte.
 * @param[out] data     Destination, or NULL for sizing.
 * @param[in]  capacity Native capacity.
 * @param[out] written  Size on success or buffer shortage; unchanged for other errors.
 *
 * @return #TLV_OK on success.
 * @return #TLV_ERR_INVALID_ARG if the semantic content has changed.
 * @return #TLV_ERR_NULL_ARG if a required argument or source reference is `NULL`.
 * @return #TLV_ERR_NATIVE_SIZE if the value size exceeds `SIZE_MAX`.
 * @return #TLV_ERR_BUFFER_TOO_SHORT if the destination cannot hold the source.
 */
TLV_API tlv_result_t tlv_source_preserve(const tlv_source_t* source, const tlv_element_t* element,
                                         uint8_t* data, size_t capacity, size_t* written);

/** @} */

#ifdef __cplusplus
}
#endif

#endif
