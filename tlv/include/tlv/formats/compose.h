// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_FORMATS_COMPOSE_H
#define OPENTLV_FORMATS_COMPOSE_H

#include "tlv/format.h"
#include "tlv/endian.h"
#include "tlv/field/encoding.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 * @ingroup formats
 * @brief Public field composition primitives for canonical formats.
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
 * @brief Order of explicit identifier and length fields.
 */
typedef enum tlv_element_order {
    TLV_ELEMENT_ORDER_TLV = 0, /**< Identifier followed by length. */
    TLV_ELEMENT_ORDER_LTV      /**< Length followed by identifier. */
} tlv_element_order_t;

/**
 * @brief Meaning of the encoded count in a field composition.
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
typedef struct tlv_field_composition {
    const void* context;              /**< Immutable codec context. */
    tlv_read_tag_fn read_tag;         /**< Identifier decoder. */
    tlv_read_length_fn read_length;   /**< Count decoder. */
    tlv_resolve_bounds_fn resolve;    /**< Optional terminated framing resolver. */
    tlv_write_tag_fn write_tag;       /**< Identifier encoder and width query. */
    tlv_write_length_fn write_length; /**< Count encoder. */
    tlv_length_size_fn length_size;   /**< Count width query. */
    tlv_element_order_t order;        /**< Wire field order. */
    tlv_length_scope_t scope;         /**< Wire count meaning. */
} tlv_field_composition_t;

/**
 * @brief Decode a field composition; context points to #tlv_field_composition_t.
 *
 * @copydetails tlv_decode_fn
 */
TLV_API tlv_result_t tlv_fields_decode(const void* context, const uint8_t* data, size_t size,
                                       tlv_decoded_t* result, tlv_format_error_t* error);

/**
 * @brief Measure a field composition; context points to #tlv_field_composition_t.
 *
 * @copydetails tlv_measure_fn
 */
TLV_API tlv_result_t tlv_fields_measure(const void* context, const tlv_element_t* element,
                                        tlv_encoding_t* encoding, tlv_format_error_t* error);

/**
 * @brief Encode a field composition; context points to #tlv_field_composition_t.
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
 * @param[in]  composition Immutable composition that outlives the descriptor.
 *
 * @return #TLV_OK on success.
 * @return #TLV_ERR_INVALID_ARG for incomplete capabilities or invalid configuration.
 */
TLV_API tlv_result_t tlv_fields_format_init(tlv_format_t* format,
                                            const tlv_field_composition_t* composition);

/**
 * @brief Fixed-width binary fields, independent of any protocol.
 */
typedef struct tlv_binary_composition {
    size_t tag_size;                   /**< Identifier width; nonzero. */
    size_t length_size;                /**< Count width, one through eight bytes. */
    tlv_byte_order_t length_order;     /**< Explicit big or little endian. */
    tlv_element_order_t element_order; /**< Field ordering. */
    tlv_length_scope_t length_scope;   /**< Count semantics. */
} tlv_binary_composition_t;

/**
 * @brief Decode binary fields; context points to #tlv_binary_composition_t.
 *
 * @copydetails tlv_decode_fn
 */
TLV_API tlv_result_t tlv_binary_decode(const void* context, const uint8_t* data, size_t size,
                                       tlv_decoded_t* result, tlv_format_error_t* error);

/**
 * @brief Measure binary fields; context points to #tlv_binary_composition_t.
 *
 * @copydetails tlv_measure_fn
 */
TLV_API tlv_result_t tlv_binary_measure(const void* context, const tlv_element_t* element,
                                        tlv_encoding_t* encoding, tlv_format_error_t* error);

/**
 * @brief Encode binary fields; context points to #tlv_binary_composition_t.
 *
 * @copydetails tlv_encode_fn
 */
TLV_API tlv_result_t tlv_binary_encode(const void* context, const tlv_element_t* element,
                                       uint8_t* data, size_t capacity, size_t* written,
                                       tlv_format_error_t* error);

/**
 * @brief Fixed binary TLV framing with identifier-selected tag-only elements.
 *
 * Identifiers listed in tag_only omit both Length and Value; all other tags
 * use fields. Selection compares raw identifier bytes, without numeric or
 * protocol interpretation. Listed identifiers require an empty semantic Value.
 * A decoded tag-only element has an absent Length range and present empty
 * Value and Trailer ranges immediately after Tag. No terminator policy is implied.
 *
 * Configuration, table and identifier bytes are borrowed and immutable and
 * must outlive the descriptor. No operation allocates. fields must use TLV
 * ordering and VALUE scope, with nonzero tag_size and length_size in 1..8.
 * Duplicate table entries are permitted and have no additional effect.
 */
typedef struct tlv_tagged_binary_composition {
    tlv_binary_composition_t fields; /**< Default binary TLV field configuration. */
    const tlv_tag_t* tag_only;       /**< Identifier table; NULL only when count is zero. */
    size_t count; /**< Number of entries; each must have fields.tag_size bytes. */
} tlv_tagged_binary_composition_t;

/**
 * @brief Field codec composition with identifier-selected tag-only elements.
 *
 * The borrowed immutable fields, table and identifier bytes must outlive all
 * operations. Fields must provide both reading and writing, use TLV/VALUE
 * framing and have no bounds resolver. Table identifiers use semantic byte
 * identity and must be encodable by fields.write_tag. Duplicate entries are
 * harmless. Tag-only elements omit Length and require an empty Value; their
 * source Value/Trailer ranges are present and empty immediately after Tag.
 * No skip or stop policy is implied. No operation allocates.
 */
typedef struct tlv_tagged_fields_composition {
    tlv_field_composition_t fields; /**< Default field codec composition. */
    const tlv_tag_t* tag_only;      /**< Borrowed table; NULL only when count is zero. */
    size_t count;                   /**< Number of table entries. */
} tlv_tagged_fields_composition_t;

/** @brief Decode identifier-selected field framing.
 * @copydetails tlv_decode_fn
 * @note context points to a valid immutable #tlv_tagged_fields_composition_t.
 */
TLV_API tlv_result_t tlv_tagged_fields_decode(const void* context, const uint8_t* data, size_t size,
                                              tlv_decoded_t* result, tlv_format_error_t* error);

/** @brief Measure identifier-selected field framing.
 * @copydetails tlv_measure_fn
 * @note context points to a valid immutable #tlv_tagged_fields_composition_t.
 * Nonempty tag-only Values return #TLV_ERR_INVALID_LENGTH.
 */
TLV_API tlv_result_t tlv_tagged_fields_measure(const void* context, const tlv_element_t* element,
                                               tlv_encoding_t* encoding, tlv_format_error_t* error);

/** @brief Encode identifier-selected field framing.
 * @copydetails tlv_encode_fn
 * @note context points to a valid immutable #tlv_tagged_fields_composition_t.
 */
TLV_API tlv_result_t tlv_tagged_fields_encode(const void* context, const tlv_element_t* element,
                                              uint8_t* data, size_t capacity, size_t* written,
                                              tlv_format_error_t* error);

/** @brief Initialize a bidirectional identifier-selected field format.
 * @param[out] format Descriptor, unchanged on failure.
 * @param[in] composition Borrowed immutable composition, which must outlive format.
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG for a missing required pointer.
 * @return #TLV_ERR_INVALID_ARG for incomplete codecs, unsupported framing or an invalid table.
 * @return A tag encoder error for an unrepresentable table identifier.
 */
TLV_API tlv_result_t tlv_tagged_fields_format_init(
    tlv_format_t* format, const tlv_tagged_fields_composition_t* composition);

/**
 * @brief Decode identifier-selected binary framing.
 *
 * @copydetails tlv_decode_fn
 * @note context points to a valid immutable #tlv_tagged_binary_composition_t.
 */
TLV_API tlv_result_t tlv_tagged_binary_decode(const void* context, const uint8_t* data, size_t size,
                                              tlv_decoded_t* result, tlv_format_error_t* error);

/**
 * @brief Measure identifier-selected binary framing.
 *
 * @copydetails tlv_measure_fn
 * @note context points to a valid immutable #tlv_tagged_binary_composition_t.
 * Tag-only elements with nonempty Value return #TLV_ERR_INVALID_LENGTH.
 */
TLV_API tlv_result_t tlv_tagged_binary_measure(const void* context, const tlv_element_t* element,
                                               tlv_encoding_t* encoding, tlv_format_error_t* error);

/**
 * @brief Encode identifier-selected binary framing.
 *
 * @copydetails tlv_encode_fn
 * @note context points to a valid immutable #tlv_tagged_binary_composition_t.
 * Tag-only elements with nonempty Value return #TLV_ERR_INVALID_LENGTH.
 */
TLV_API tlv_result_t tlv_tagged_binary_encode(const void* context, const tlv_element_t* element,
                                              uint8_t* data, size_t capacity, size_t* written,
                                              tlv_format_error_t* error);

/**
 * @brief Initialize a bidirectional descriptor with identifier-selected framing.
 *
 * @param[out] format Descriptor; unchanged on failure.
 * @param[in] composition Borrowed immutable configuration; must outlive format.
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG if format or composition is NULL.
 * @return #TLV_ERR_INVALID_ARG for invalid widths, ordering, scope or table entries.
 * @return #TLV_ERR_INVALID_BYTE_ORDER for unsupported length byte order.
 */
TLV_API tlv_result_t tlv_tagged_binary_format_init(
    tlv_format_t* format, const tlv_tagged_binary_composition_t* composition);

/** @} */

#ifdef __cplusplus
}
#endif

#endif
