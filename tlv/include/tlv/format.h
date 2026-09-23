#ifndef OPENTLV_FORMAT_H
#define OPENTLV_FORMAT_H

#include "tlv/error.h"
#include "tlv/view.h"
#include "tlv/export.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 * @ingroup formats
 * @brief Reader and writer format descriptors that define a TLV wire encoding.
 *
 * A format is a pair of stateless callback tables (one for reading, one for
 * writing) plus an optional borrowed, immutable context. Concrete formats
 * live under `tlv/builtins/<protocol>/`; custom formats are built with
 * tlv_reader_format_init() and tlv_writer_format_init().
 *
 * Callbacks must not allocate, retain buffers, or access memory beyond the
 * size or capacity they are given. All sizes are in bytes. A format defines
 * its own tag encoding and valid tag lengths, and rejects tags it does not
 * support, for example with #TLV_ERR_INVALID_TAG_SIZE; #tlv_tag_t itself has no
 * length limit. A reader callback returns a tag that borrows the input bytes it
 * was given, and it must not point the tag anywhere else.
 * Callback errors propagate unchanged through the generic reader and writer.
 */

/** @addtogroup formats
 * @{
 */

/**
 * @brief Callback that decodes a tag from the start of a buffer.
 *
 * @param[in]  context  Format context, borrowed; may be `NULL`.
 * @param[in]  data     Bytes starting at the tag.
 * @param[in]  size     Number of readable bytes in `data`.
 * @param[out] tag      Receives the decoded tag.
 * @param[out] consumed Receives the number of bytes the tag occupies; at
 *                      least one on success.
 *
 * @return #TLV_OK on success, or an error code that propagates unchanged.
 */
typedef tlv_result_t (*tlv_read_tag_fn)(const void* context, const uint8_t* data, size_t size,
                                        tlv_tag_t* tag, size_t* consumed);

/**
 * @brief Callback that decodes a length field from the start of a buffer.
 *
 * @param[in]  context  Format context, borrowed; may be `NULL`.
 * @param[in]  data     Bytes starting at the length field (after the tag).
 * @param[in]  size     Number of readable bytes in `data`.
 * @param[out] length   Receives the decoded value length.
 * @param[out] consumed Receives the number of bytes the length field occupies.
 *
 * @return #TLV_OK on success, or an error code that propagates unchanged.
 */
typedef tlv_result_t (*tlv_read_length_fn)(const void* context, const uint8_t* data, size_t size,
                                           size_t* length, size_t* consumed);

/**
 * @brief Optional callback that replaces read_length during element reading.
 *
 * Reports the length-field size, the borrowed value size, and the trailing
 * framing size separately. All three ranges must fit `size`, in that order.
 * The callback may inspect nested framing to resolve a terminated value. It
 * follows the same allocation and buffer-lifetime rules as
 * #tlv_read_length_fn.
 *
 * @param[in]  context      Format context, borrowed; may be `NULL`.
 * @param[in]  tag          The already parsed tag.
 * @param[in]  data         Bytes starting after the tag.
 * @param[in]  size         Number of readable bytes in `data`.
 * @param[out] length_size  Receives the size of the length field.
 * @param[out] value_size   Receives the size of the value.
 * @param[out] trailer_size Receives the size of trailing framing, such as a
 *                          BER end-of-contents marker.
 *
 * @return #TLV_OK on success, or an error code that propagates unchanged.
 */
typedef tlv_result_t (*tlv_read_value_bounds_fn)(const void* context, const tlv_tag_t* tag,
                                                 const uint8_t* data, size_t size,
                                                 size_t* length_size, size_t* value_size,
                                                 size_t* trailer_size);

/**
 * @brief Optional callback that parses a whole element header at once.
 *
 * Replaces `read_tag`, `read_length` and `read_value_bounds` for formats whose
 * fields are not laid out as tag, then length, then value (for example
 * Bluetooth LTV, where the length precedes the type). The callback sees the
 * first byte of the element and reports the tag, the size of everything that
 * precedes the value (the header), the borrowed value size, and the trailing
 * framing size. The three ranges must fit `size`, in that order. It follows
 * the same allocation and buffer-lifetime rules as #tlv_read_tag_fn.
 *
 * @param[in]  context      Format context, borrowed; may be `NULL`.
 * @param[in]  data         Bytes starting at the element.
 * @param[in]  size         Number of readable bytes in `data`.
 * @param[out] tag          Receives the decoded tag.
 * @param[out] header_size  Receives the number of bytes before the value.
 * @param[out] value_size   Receives the size of the value.
 * @param[out] trailer_size Receives the size of trailing framing; zero when
 *                          the format has none.
 *
 * @return #TLV_OK on success, or an error code that propagates unchanged.
 */
typedef tlv_result_t (*tlv_read_element_fn)(const void* context, const uint8_t* data, size_t size,
                                            tlv_tag_t* tag, size_t* header_size, size_t* value_size,
                                            size_t* trailer_size);

/**
 * @brief Callback that encodes a tag.
 *
 * Called with `data == NULL` and `capacity == 0`, it validates the tag and
 * reports its encoded size without writing; actual writes report that same
 * size.
 *
 * @param[in]  context  Format context, borrowed; may be `NULL`.
 * @param[out] data     Destination, or `NULL` for a size query.
 * @param[in]  capacity Destination capacity in bytes.
 * @param[in]  tag      Tag to encode.
 * @param[out] written  Receives the encoded size; initialized on success.
 *
 * @return #TLV_OK on success, or an error code that propagates unchanged.
 */
typedef tlv_result_t (*tlv_write_tag_fn)(const void* context, uint8_t* data, size_t capacity,
                                         const tlv_tag_t* tag, size_t* written);

/**
 * @brief Callback that encodes a length field.
 *
 * @param[in]  context  Format context, borrowed; may be `NULL`.
 * @param[out] data     Destination for the length field.
 * @param[in]  capacity Destination capacity in bytes.
 * @param[in]  length   Value length to encode.
 * @param[out] written  Receives the encoded size; initialized on success.
 *
 * @return #TLV_OK on success, or an error code that propagates unchanged.
 */
typedef tlv_result_t (*tlv_write_length_fn)(const void* context, uint8_t* data, size_t capacity,
                                            size_t length, size_t* written);

/**
 * @brief Callback that validates a length and reports its exact encoded size.
 *
 * The reported size is exactly what #tlv_write_length_fn writes for the same length.
 *
 * @param[in]  context Format context, borrowed; may be `NULL`.
 * @param[in]  length  Value length to encode.
 * @param[out] size    Receives the size of the length field.
 *
 * @return #TLV_OK on success, or an error code that propagates unchanged.
 */
typedef tlv_result_t (*tlv_length_size_fn)(const void* context, size_t length, size_t* size);

/**
 * @brief Optional callback that encodes a whole element header at once.
 *
 * Replaces `write_tag`, `write_length` and `length_size` for formats whose
 * header is not a tag followed by a length. The header is everything that
 * precedes the value. Called with `data == NULL` and `capacity == 0`, it
 * validates the tag and length and reports the header size without writing;
 * actual writes report that same size.
 *
 * @param[in]  context  Format context, borrowed; may be `NULL`.
 * @param[out] data     Destination, or `NULL` for a size query.
 * @param[in]  capacity Destination capacity in bytes.
 * @param[in]  tag      Tag to encode.
 * @param[in]  length   Value length to encode.
 * @param[out] written  Receives the header size; initialized on success.
 *
 * @return #TLV_OK on success, or an error code that propagates unchanged.
 */
typedef tlv_result_t (*tlv_write_header_fn)(const void* context, uint8_t* data, size_t capacity,
                                            const tlv_tag_t* tag, size_t length, size_t* written);

/**
 * @brief Stateless reading format with optional borrowed, immutable configuration.
 *
 * The descriptor and context must outlive every reader and operation that
 * uses them. `read_tag` and `read_length` are required unless `read_element`
 * is set; `read_value_bounds` is optional and, when non-`NULL`, replaces
 * `read_length` in element parsing. A non-`NULL` `read_element` replaces all
 * three, so every generic operation (reader, scanner, walker, schemas) works
 * on formats with a different field order. Callbacks must not allocate, retain buffers, or access
 * memory beyond `size`. On success they initialize their outputs.
 *
 * Reading borrows input bytes; value decoding and tree visits are separate
 * concerns.
 *
 * @see tlv_reader_format_init
 */
typedef struct tlv_reader_format {
    /** Borrowed, immutable configuration passed to every callback; may be `NULL`. */
    const void* context;
    /** Tag decoder. Required. */
    tlv_read_tag_fn read_tag;
    /** Length decoder. Required. */
    tlv_read_length_fn read_length;
    /** Optional replacement for `read_length`; `NULL` when unused. */
    tlv_read_value_bounds_fn read_value_bounds;
    /**
     * Optional whole-element parser that replaces `read_tag`, `read_length`
     * and `read_value_bounds`; `NULL` when unused.
     */
    tlv_read_element_fn read_element;
} tlv_reader_format_t;

/**
 * @brief Stateless writing format with optional borrowed, immutable configuration.
 *
 * The descriptor and context must outlive every writer and operation that
 * uses them. `write_tag`, `write_length` and `length_size` are all required
 * unless `write_header` is set, which replaces the three. Callbacks must not allocate,
 * retain buffers, or access memory beyond `capacity`. Successful write
 * callbacks initialize `written`. Value encoding is a separate concern.
 *
 * @see tlv_writer_format_init
 */
typedef struct tlv_writer_format {
    /** Borrowed, immutable configuration passed to every callback; may be `NULL`. */
    const void* context;
    /** Tag encoder and size query. Required. */
    tlv_write_tag_fn write_tag;
    /** Length-field encoder. Required. */
    tlv_write_length_fn write_length;
    /** Length validator and size query. Required. */
    tlv_length_size_fn length_size;
    /**
     * Optional whole-header encoder that replaces `write_tag`, `write_length`
     * and `length_size`; `NULL` when unused.
     */
    tlv_write_header_fn write_header;
} tlv_writer_format_t;

/**
 * @brief Initializes a reader format in caller-owned storage.
 *
 * Does not allocate. The supplied pointers are stored, not copied: the
 * descriptor and context follow the reading lifetime and callback contracts
 * documented for #tlv_reader_format_t. `read_value_bounds` is initialized to
 * `NULL`; callers can assign it after initialization.
 *
 * @param[out] format      Descriptor to initialize.
 * @param[in]  context     Borrowed context passed to callbacks; may be `NULL`.
 * @param[in]  read_tag    Tag decoder. Required.
 * @param[in]  read_length Length decoder. Required.
 *
 * @return #TLV_OK on success; every field is set.
 * @return #TLV_ERR_INVALID_ARG if `format` or either callback is `NULL`.
 *
 * @note On failure the descriptor is unchanged.
 */
TLV_API tlv_result_t tlv_reader_format_init(tlv_reader_format_t* format, const void* context,
                                            tlv_read_tag_fn read_tag,
                                            tlv_read_length_fn read_length);

/**
 * @brief Initializes a writer format in caller-owned storage.
 *
 * Does not allocate. Only the supplied pointers are stored; the descriptor
 * and context follow the writing lifetime and callback contracts documented
 * for #tlv_writer_format_t.
 *
 * @param[out] format       Descriptor to initialize.
 * @param[in]  context      Borrowed context passed to callbacks; may be `NULL`.
 * @param[in]  write_tag    Tag encoder. Required.
 * @param[in]  write_length Length encoder. Required.
 * @param[in]  length_size  Length size query. Required.
 *
 * @return #TLV_OK on success; every field is set.
 * @return #TLV_ERR_INVALID_ARG if `format` or any callback is `NULL`.
 *
 * @note On failure the descriptor is unchanged.
 */
TLV_API tlv_result_t tlv_writer_format_init(tlv_writer_format_t* format, const void* context,
                                            tlv_write_tag_fn write_tag,
                                            tlv_write_length_fn write_length,
                                            tlv_length_size_fn length_size);

/**
 * @brief Initializes a reader format that parses whole elements.
 *
 * For formats whose field order is not tag, length, value. Does not allocate;
 * the supplied pointers are stored, not copied. `read_tag`, `read_length` and
 * `read_value_bounds` are initialized to `NULL`.
 *
 * @param[out] format       Descriptor to initialize.
 * @param[in]  context      Borrowed context passed to the callback; may be `NULL`.
 * @param[in]  read_element Element parser. Required.
 *
 * @return #TLV_OK on success; every field is set.
 * @return #TLV_ERR_INVALID_ARG if `format` or `read_element` is `NULL`.
 *
 * @note On failure the descriptor is unchanged.
 */
TLV_API tlv_result_t tlv_reader_format_init_element(tlv_reader_format_t* format,
                                                    const void* context,
                                                    tlv_read_element_fn read_element);

/**
 * @brief Initializes a writer format that encodes whole element headers.
 *
 * For formats whose field order is not tag, length, value. Does not allocate;
 * the supplied pointers are stored, not copied. `write_tag`, `write_length`
 * and `length_size` are initialized to `NULL`.
 *
 * @param[out] format       Descriptor to initialize.
 * @param[in]  context      Borrowed context passed to the callback; may be `NULL`.
 * @param[in]  write_header Header encoder. Required.
 *
 * @return #TLV_OK on success; every field is set.
 * @return #TLV_ERR_INVALID_ARG if `format` or `write_header` is `NULL`.
 *
 * @note On failure the descriptor is unchanged.
 */
TLV_API tlv_result_t tlv_writer_format_init_header(tlv_writer_format_t* format, const void* context,
                                                   tlv_write_header_fn write_header);

/**
 * @brief Optional nesting predicate used by tree traversal and structure validation.
 *
 * Called only with successfully parsed tags, using the reader format's
 * context. No value decoding occurs. Passing `NULL` at a call site means all
 * values are opaque.
 *
 * @param[in] context The reader format's context.
 * @param[in] tag     A successfully parsed tag.
 *
 * @return Nonzero if the tag's value is a sequence in the same reader
 *         format, zero otherwise.
 */
typedef int (*tlv_is_constructed_fn)(const void* context, const tlv_tag_t* tag);

#ifdef __cplusplus
}
#endif

/** @} */

#endif /* OPENTLV_FORMAT_H */
