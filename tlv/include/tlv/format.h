#ifndef OPENTLV_FORMAT_H
#define OPENTLV_FORMAT_H

#include "tlv/error.h"
#include "tlv/element.h"
#include "tlv/export.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 * @ingroup formats
 * @brief Format descriptor that defines a TLV wire encoding.
 *
 * A format is a stateless callback table plus an optional borrowed, immutable
 * context. Its read and write callback groups are independently optional: a
 * format that leaves a group unset simply cannot be used in that direction
 * (see tlv_format_can_read() and tlv_format_can_write()), rather than needing
 * a separate, incompatible type. Concrete formats live under
 * `tlv/builtins/<protocol>/`; custom formats are built with tlv_format_init()
 * and tlv_format_init_element().
 *
 * Callbacks must not allocate, retain buffers, or access memory beyond the
 * size or capacity they are given. All sizes are in bytes. Logical value
 * lengths use #tlv_size_t, independent of native pointer width; buffer
 * capacities, offsets and encoded field extents use `size_t`. Length
 * callbacks normalize wire-specific counts to value bytes without native
 * narrowing. The reader checks these quantities against available memory
 * before publishing a #tlv_element_t. Its raw length field is retained
 * in `element.length`, separately from the decoded `element.value.size`.
 * A format defines
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
 * @param[out] length   Receives the decoded logical value byte count, excluding
 *                      framing, even when it exceeds the native address space.
 * @param[out] consumed Receives the number of bytes the length field occupies.
 *                      On failure may report its available raw byte extent for
 *                      diagnostics (at most `size`), including a truncated
 *                      prefix. The reader initializes it to zero; leaving it
 *                      zero means no raw field is known. `length` is used only
 *                      on success.
 *
 * @return #TLV_OK on success, or an error code that propagates unchanged.
 */
typedef tlv_result_t (*tlv_read_length_fn)(const void* context, const uint8_t* data, size_t size,
                                           tlv_size_t* length, size_t* consumed);

/**
 * @brief Optional callback that replaces read_length during element reading.
 *
 * Reports the length-field size, the borrowed value size, and the trailing
 * framing size separately. The length field must fit `size`; the reader
 * validates the resolved value and trailer against the remaining input.
 * Definite sizes must be reported without requiring the payload to fit.
 * The callback may inspect nested framing to resolve a terminated value. It
 * follows the same allocation and buffer-lifetime rules as
 * #tlv_read_length_fn.
 *
 * @param[in]  context      Format context, borrowed; may be `NULL`.
 * @param[in]  tag          The already parsed tag.
 * @param[in]  data         Bytes starting after the tag.
 * @param[in]  size         Number of readable bytes in `data`.
 * @param[out] length_size  Receives the size of the length field. On failure may
 *                          report its available raw extent, as for the
 *                          `consumed` output of #tlv_read_length_fn.
 * @param[out] value_size   Receives the resolved logical value byte count.
 * @param[out] trailer_size Receives the size of trailing framing, such as a
 *                          BER end-of-contents marker.
 *
 * @return #TLV_OK on success, or an error code that propagates unchanged.
 */
typedef tlv_result_t (*tlv_read_value_bounds_fn)(const void* context, const tlv_tag_t* tag,
                                                 const uint8_t* data, size_t size,
                                                 size_t* length_size, tlv_size_t* value_size,
                                                 size_t* trailer_size);

/**
 * @brief Optional callback that parses a whole element header at once.
 *
 * Replaces `read_tag`, `read_length` and `read_value_bounds` for formats whose
 * fields are not laid out as tag, then length, then value (for example
 * Bluetooth LTV, where the length precedes the type). The callback sees the
 * first byte of the element and reports the tag, the size of everything that
 * precedes the value (the header), the borrowed value size, and the trailing
 * framing size. The header must fit `size`; the reader validates value and
 * trailer extents afterwards. Decoding a definite header must not require
 * the declared value bytes to be present. It follows
 * the same allocation and buffer-lifetime rules as #tlv_read_tag_fn.
 *
 * @param[in]  context      Format context, borrowed; may be `NULL`.
 * @param[in]  data         Bytes starting at the element.
 * @param[in]  size         Number of readable bytes in `data`.
 * @param[out] tag          Receives the decoded tag.
 * @param[out] raw_length   Receives the original length field, borrowing bytes
 *                          within the header; `{ NULL, 0 }` when absent.
 *                          On failure may report the available length bytes,
 *                          even if no numeric value could be decoded. The
 *                          reader initializes this descriptor to zero.
 * @param[out] header_size  Receives the number of bytes before the value.
 * @param[out] value_size   Receives the decoded logical value byte count.
 * @param[out] trailer_size Receives the size of trailing framing; zero when
 *                          the format has none.
 *
 * @return #TLV_OK on success, or an error code that propagates unchanged.
 */
typedef tlv_result_t (*tlv_read_element_fn)(const void* context, const uint8_t* data, size_t size,
                                            tlv_tag_t* tag, tlv_length_t* raw_length,
                                            size_t* header_size, tlv_size_t* value_size,
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
                                            tlv_size_t length, size_t* written);

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
typedef tlv_result_t (*tlv_length_size_fn)(const void* context, tlv_size_t length, size_t* size);

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
                                            const tlv_tag_t* tag, tlv_size_t length,
                                            size_t* written);

/**
 * @brief Optional nesting predicate used by tree traversal and structure validation.
 *
 * Called only with successfully parsed tags, using the format's context. No
 * value decoding occurs. A `NULL` #tlv_format_t::is_constructed means all
 * values are opaque.
 *
 * @param[in] context The format's context.
 * @param[in] tag     A successfully parsed tag.
 *
 * @return Nonzero if the tag's value is a sequence in the same format, zero
 *         otherwise.
 */
typedef int (*tlv_is_constructed_fn)(const void* context, const tlv_tag_t* tag);

/**
 * @brief Stateless format descriptor with optional borrowed, immutable configuration.
 *
 * The descriptor and context must outlive every reader, writer and operation
 * that uses them. The descriptor itself is a plain, trivially copyable value;
 * copying it shallow-copies `context` without copying or extending the
 * lifetime of whatever it points to.
 * @see @docs{guides/memory,format context ownership and lifetime} for the
 * full ownership, copying and sharing contract.
 *
 * Read and write capability are independently optional:
 * `read_tag` and `read_length` are required for reading unless `read_element`
 * is set, and `write_tag`, `write_length` and `length_size` are required for
 * writing unless `write_header` is set. A format that leaves an entire group
 * unset (all `NULL`) simply cannot be used in that direction; see
 * tlv_format_can_read() and tlv_format_can_write(). `read_value_bounds` is
 * optional and, when non-`NULL`, replaces `read_length` in element parsing. A
 * non-`NULL` `read_element` replaces `read_tag`, `read_length` and
 * `read_value_bounds`, so every generic read operation (reader, scanner,
 * walker, schemas) works on formats with a different field order. A
 * non-`NULL` `write_header` replaces `write_tag`, `write_length` and
 * `length_size` the same way for encoding. Callbacks must not allocate,
 * retain buffers, or access memory beyond `size` or `capacity`. On success
 * they initialize their outputs.
 *
 * Reading borrows input bytes; value decoding and tree visits are separate
 * concerns.
 *
 * @see tlv_format_init, tlv_format_init_element
 */
typedef struct tlv_format {
    /**
     * Borrowed, immutable configuration passed to every callback; may be
     * `NULL`. The caller owns it and must keep it valid and unchanged for as
     * long as this descriptor (or anything built from it) is used.
     */
    const void* context;
    /** Tag decoder. Required for reading unless `read_element` is set. */
    tlv_read_tag_fn read_tag;
    /** Length decoder. Required for reading unless `read_element` is set. */
    tlv_read_length_fn read_length;
    /** Optional replacement for `read_length`; `NULL` when unused. */
    tlv_read_value_bounds_fn read_value_bounds;
    /**
     * Optional whole-element parser that replaces `read_tag`, `read_length`
     * and `read_value_bounds`; `NULL` when unused.
     */
    tlv_read_element_fn read_element;
    /** Tag encoder and size query. Required for writing unless `write_header` is set. */
    tlv_write_tag_fn write_tag;
    /** Length-field encoder. Required for writing unless `write_header` is set. */
    tlv_write_length_fn write_length;
    /** Length validator and size query. Required for writing unless `write_header` is set. */
    tlv_length_size_fn length_size;
    /**
     * Optional whole-header encoder that replaces `write_tag`, `write_length`
     * and `length_size`; `NULL` when unused.
     */
    tlv_write_header_fn write_header;
    /**
     * Optional nesting predicate that reports whether a parsed tag's value is
     * a sequence in this same format; `NULL` means every value is opaque to
     * generic tree traversal and structure validation.
     */
    tlv_is_constructed_fn is_constructed;
} tlv_format_t;

/**
 * @brief Initializes a format's classic tag/length read and write callbacks in caller-owned
 * storage.
 *
 * Does not allocate. The supplied pointers are stored, not copied: the
 * descriptor and context follow the lifetime and callback contracts
 * documented for #tlv_format_t. Read and write capability are independently
 * optional: pass both `read_tag` and `read_length` for read capability, or
 * both `NULL` to leave reading unsupported; pass `write_tag`, `write_length`
 * and `length_size` for write capability, or all three `NULL` to leave
 * writing unsupported. At least one of the two groups must be given.
 * `read_value_bounds`, `read_element`, `write_header` and `is_constructed`
 * are initialized to `NULL`; callers can assign them directly after
 * initialization.
 *
 * @param[out] format       Descriptor to initialize.
 * @param[in]  context      Borrowed context passed to callbacks; may be `NULL`.
 * @param[in]  read_tag     Tag decoder, or `NULL` to leave reading unsupported.
 * @param[in]  read_length  Length decoder, or `NULL` to leave reading unsupported.
 * @param[in]  write_tag    Tag encoder, or `NULL` to leave writing unsupported.
 * @param[in]  write_length Length encoder, or `NULL` to leave writing unsupported.
 * @param[in]  length_size  Length size query, or `NULL` to leave writing unsupported.
 *
 * @return #TLV_OK on success; every field is set.
 * @return #TLV_ERR_INVALID_ARG if `format` is `NULL`; if exactly one of
 *         `read_tag`/`read_length` is `NULL`; if `write_tag`, `write_length`
 *         and `length_size` are not all `NULL` or all non-`NULL`; or if both
 *         the read and write groups are left unset.
 *
 * @note On failure the descriptor is unchanged.
 */
TLV_API tlv_result_t tlv_format_init(tlv_format_t* format, const void* context,
                                     tlv_read_tag_fn read_tag, tlv_read_length_fn read_length,
                                     tlv_write_tag_fn write_tag, tlv_write_length_fn write_length,
                                     tlv_length_size_fn length_size);

/**
 * @brief Initializes a format's whole-element read and write callbacks in caller-owned storage.
 *
 * For formats whose field order is not tag, length, value. Does not allocate;
 * the supplied pointers are stored, not copied. `read_element` and
 * `write_header` are independently optional, but not both `NULL`.
 * `read_tag`, `read_length`, `read_value_bounds`, `write_tag`, `write_length`,
 * `length_size` and `is_constructed` are initialized to `NULL`.
 *
 * @param[out] format       Descriptor to initialize.
 * @param[in]  context      Borrowed context passed to the callbacks; may be `NULL`.
 * @param[in]  read_element Element parser, or `NULL` to leave reading unsupported.
 * @param[in]  write_header Header encoder, or `NULL` to leave writing unsupported.
 *
 * @return #TLV_OK on success; every field is set.
 * @return #TLV_ERR_INVALID_ARG if `format` is `NULL`, or if `read_element` and
 *         `write_header` are both `NULL`.
 *
 * @note On failure the descriptor is unchanged.
 */
TLV_API tlv_result_t tlv_format_init_element(tlv_format_t* format, const void* context,
                                             tlv_read_element_fn read_element,
                                             tlv_write_header_fn write_header);

/**
 * @brief Reports whether a format can be used for reading.
 *
 * @param[in] format Format to query; may be `NULL`.
 *
 * @return Nonzero if `format` is not `NULL` and has either `read_element` set
 *         or both `read_tag` and `read_length` set, zero otherwise.
 */
TLV_API int tlv_format_can_read(const tlv_format_t* format);

/**
 * @brief Reports whether a format can be used for writing.
 *
 * @param[in] format Format to query; may be `NULL`.
 *
 * @return Nonzero if `format` is not `NULL` and has either `write_header` set
 *         or all of `write_tag`, `write_length` and `length_size` set, zero
 *         otherwise.
 */
TLV_API int tlv_format_can_write(const tlv_format_t* format);

#ifdef __cplusplus
}
#endif

/** @} */

#endif /* OPENTLV_FORMAT_H */
