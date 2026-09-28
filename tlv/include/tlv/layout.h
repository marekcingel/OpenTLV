#ifndef OPENTLV_LAYOUT_H
#define OPENTLV_LAYOUT_H

#include "tlv/format.h"
#include "tlv/endian.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 * @ingroup formats
 * @brief Public field-layout composition primitives for canonical formats.
 *
 * These primitives compose field codecs into a single decode/measure/encode
 * contract. Reader and Writer never inspect the composition. Context and
 * codec configuration remain borrowed and immutable. Callbacks do not allocate.
 * These types configure Format composition; runtime ranges of a decoded element
 * are represented separately by #tlv_source_t and #tlv_range_t.
 */

/** @addtogroup formats
 * @{
 */

/**
 * @brief Decode identifier bytes and their consumed extent.
 *
 * @param[in]  context  Borrowed immutable codec configuration.
 * @param[in]  data     Beginning of the identifier field.
 * @param[in]  size     Available bytes.
 * @param[out] tag      Borrowed identifier on success.
 * @param[out] consumed Encoded identifier width on success.
 *
 * @return #TLV_OK on success.
 * @return An identifier or buffer error reported by the codec.
 */
typedef tlv_result_t (*tlv_read_tag_fn)(const void* context, const uint8_t* data, size_t size,
                                        tlv_tag_t* tag, size_t* consumed);

/**
 * @brief Decode a wire count without narrowing to native size.
 *
 * @param[in]  context  Borrowed immutable codec configuration.
 * @param[in]  data     Beginning of the length field.
 * @param[in]  size     Available bytes.
 * @param[out] length   Logical wire count on success, before applying layout scope.
 * @param[out] consumed Encoded width; on failure may report available prefix bytes.
 *
 * @return #TLV_OK on success.
 * @return A length or buffer error reported by the codec.
 */
typedef tlv_result_t (*tlv_read_length_fn)(const void* context, const uint8_t* data, size_t size,
                                           tlv_size_t* length, size_t* consumed);

/**
 * @brief Resolve terminated framing after an identifier.
 *
 * @param[in]  context      Borrowed immutable codec configuration.
 * @param[in]  tag          Already decoded identifier.
 * @param[in]  data         Bytes after the identifier.
 * @param[in]  size         Available bytes.
 * @param[out] length_size  Available length field extent, also on failure when known.
 * @param[out] value_size   Logical value byte count, excluding framing.
 * @param[out] trailer_size Validated trailer extent on success.
 * @param[out] error        Failure location relative to data; initialized by the caller.
 *
 * @return #TLV_OK on success.
 * @return A framing or buffer error reported by the resolver.
 *
 * @note Definite counts need not fit the input yet.
 */
typedef tlv_result_t (*tlv_resolve_bounds_fn)(const void* context, const tlv_tag_t* tag,
                                              const uint8_t* data, size_t size, size_t* length_size,
                                              tlv_size_t* value_size, size_t* trailer_size,
                                              tlv_format_error_t* error);

/**
 * @brief Encode an identifier, or query its width with NULL output.
 *
 * @param[in]  context  Borrowed immutable codec configuration.
 * @param[out] data     Destination, or NULL for sizing.
 * @param[in]  capacity Available native capacity; zero for sizing.
 * @param[in]  tag      Identifier to validate and encode.
 * @param[out] written  Exact encoded width on success, identical for sizing and writing.
 *
 * @return #TLV_OK on success.
 * @return An identifier or buffer error reported by the codec.
 *
 * @warning Failure may modify the destination.
 */
typedef tlv_result_t (*tlv_write_tag_fn)(const void* context, uint8_t* data, size_t capacity,
                                         const tlv_tag_t* tag, size_t* written);

/**
 * @brief Encode a logical count into a length field.
 *
 * @param[in]  context  Borrowed immutable codec configuration.
 * @param[out] data     Destination for the field.
 * @param[in]  capacity Available native capacity.
 * @param[in]  length   Wire count after applying layout scope.
 * @param[out] written  Exact encoded width on success.
 *
 * @return #TLV_OK on success.
 * @return A length or buffer error reported by the codec.
 *
 * @warning Failure may modify the destination.
 */
typedef tlv_result_t (*tlv_write_length_fn)(const void* context, uint8_t* data, size_t capacity,
                                            tlv_size_t length, size_t* written);

/**
 * @brief Validate a logical count and query its encoded field width.
 *
 * @param[in]  context Borrowed immutable codec configuration.
 * @param[in]  length  Wire count after applying layout scope.
 * @param[out] size    Exact native width of the encoded field on success.
 *
 * @return #TLV_OK on success.
 * @return A length error reported by the codec.
 *
 * @note No buffer is accessed.
 */
typedef tlv_result_t (*tlv_length_size_fn)(const void* context, tlv_size_t length, size_t* size);

/**
 * @brief Order of explicit identifier and length fields.
 */
typedef enum tlv_element_order {
    TLV_ELEMENT_ORDER_TLV = 0, /**< Identifier followed by length. */
    TLV_ELEMENT_ORDER_LTV      /**< Length followed by identifier. */
} tlv_element_order_t;

/**
 * @brief Meaning of the encoded count in a field layout.
 */
typedef enum tlv_length_scope {
    TLV_LENGTH_SCOPE_VALUE = 0,    /**< Value bytes only. */
    TLV_LENGTH_SCOPE_TAG_AND_VALUE /**< Identifier and value bytes. */
} tlv_length_scope_t;

/**
 * @brief Borrowed field codec composition for a contiguous header and value.
 *
 * The optional bounds resolver supports terminated values on the TLV path.
 * It returns a validated trailer; formats with an encoder-dependent trailer
 * implement the canonical measure/encode operations directly instead.
 * A count including the identifier is normalized here, not in Reader/Writer.
 */
typedef struct tlv_field_layout {
    const void* context;              /**< Immutable codec context. */
    tlv_read_tag_fn read_tag;         /**< Identifier decoder. */
    tlv_read_length_fn read_length;   /**< Count decoder. */
    tlv_resolve_bounds_fn resolve;    /**< Optional terminated framing resolver. */
    tlv_write_tag_fn write_tag;       /**< Identifier encoder and width query. */
    tlv_write_length_fn write_length; /**< Count encoder. */
    tlv_length_size_fn length_size;   /**< Count width query. */
    tlv_element_order_t order;        /**< Wire field order. */
    tlv_length_scope_t scope;         /**< Wire count meaning. */
} tlv_field_layout_t;

/**
 * @brief Decode a field composition; context points to #tlv_field_layout_t.
 *
 * @copydetails tlv_decode_fn
 */
TLV_API tlv_result_t tlv_fields_decode(const void* context, const uint8_t* data, size_t size,
                                       tlv_decoded_t* result, tlv_format_error_t* error);

/**
 * @brief Measure a field composition; context points to #tlv_field_layout_t.
 *
 * @copydetails tlv_measure_fn
 */
TLV_API tlv_result_t tlv_fields_measure(const void* context, const tlv_element_t* element,
                                        tlv_encoding_t* encoding, tlv_format_error_t* error);

/**
 * @brief Encode a field composition; context points to #tlv_field_layout_t.
 *
 * @copydetails tlv_encode_fn
 */
TLV_API tlv_result_t tlv_fields_encode(const void* context, const tlv_element_t* element,
                                       uint8_t* data, size_t capacity, size_t* written,
                                       tlv_format_error_t* error);

/**
 * @brief Initialize a canonical descriptor borrowing a field composition.
 *
 * @param[out] format Descriptor, unchanged on failure.
 * @param[in]  layout Immutable composition that outlives the descriptor.
 *
 * @return #TLV_OK on success.
 * @return #TLV_ERR_INVALID_ARG for incomplete capabilities or invalid configuration.
 */
TLV_API tlv_result_t tlv_fields_format_init(tlv_format_t* format, const tlv_field_layout_t* layout);

/**
 * @brief Fixed-width binary fields, independent of any protocol.
 */
typedef struct tlv_binary_layout {
    size_t tag_size;                   /**< Identifier width; nonzero. */
    size_t length_size;                /**< Count width, one through eight bytes. */
    tlv_byte_order_t length_order;     /**< Explicit big or little endian. */
    tlv_element_order_t element_order; /**< Field ordering. */
    tlv_length_scope_t length_scope;   /**< Count semantics. */
} tlv_binary_layout_t;

/**
 * @brief Decode binary fields; context points to #tlv_binary_layout_t.
 *
 * @copydetails tlv_decode_fn
 */
TLV_API tlv_result_t tlv_binary_decode(const void* context, const uint8_t* data, size_t size,
                                       tlv_decoded_t* result, tlv_format_error_t* error);

/**
 * @brief Measure binary fields; context points to #tlv_binary_layout_t.
 *
 * @copydetails tlv_measure_fn
 */
TLV_API tlv_result_t tlv_binary_measure(const void* context, const tlv_element_t* element,
                                        tlv_encoding_t* encoding, tlv_format_error_t* error);

/**
 * @brief Encode binary fields; context points to #tlv_binary_layout_t.
 *
 * @copydetails tlv_encode_fn
 */
TLV_API tlv_result_t tlv_binary_encode(const void* context, const tlv_element_t* element,
                                       uint8_t* data, size_t capacity, size_t* written,
                                       tlv_format_error_t* error);

/** @} */

#ifdef __cplusplus
}
#endif

#endif
