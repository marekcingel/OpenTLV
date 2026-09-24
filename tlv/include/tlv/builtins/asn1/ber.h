#ifndef OPENTLV_BUILTINS_ASN1_BER_H
#define OPENTLV_BUILTINS_ASN1_BER_H

#include "tlv/error.h"
#include "tlv/format.h"
#include "tlv/writer/writer.h"
#include "tlv/length.h"
#include "tlv/export.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 * @ingroup formats
 * @brief ASN.1 BER reader and writer formats, indefinite-length framing and length codec.
 */

/** @addtogroup formats
 * @{
 */

/**
 * @brief ASN.1 identifier-octet class bits (ITU-T X.690 section 8.1).
 *
 * Independent of any particular encoding-rule profile; shared by the DER and
 * CER profiles.
 */
typedef enum tlv_asn1_class {
    /** UNIVERSAL class. */
    TLV_ASN1_UNIVERSAL = 0,
    /** APPLICATION class. */
    TLV_ASN1_APPLICATION = 1,
    /** Context-specific class. */
    TLV_ASN1_CONTEXT_SPECIFIC = 2,
    /** PRIVATE class. */
    TLV_ASN1_PRIVATE = 3
} tlv_asn1_class_t;

/**
 * @brief Identifier octet bit layout below the class field (X.690 section 8.1.2).
 *
 * Bit 5 is the constructed/primitive flag. The low 5 bits are the
 * low-tag-number field, which escapes to high-tag-number form by being
 * all-ones (31).
 */
enum {
    /** Bit position of the class field within the identifier octet. */
    TLV_ASN1_CLASS_SHIFT = 6,
    /** Mask of the constructed/primitive flag (bit 5). */
    TLV_ASN1_CONSTRUCTED_BIT = 0x20,
    /** Mask of the low-tag-number field. */
    TLV_ASN1_TAG_NUMBER_MASK = 0x1F,
    /** Low-tag-number value that escapes to high-tag-number form. */
    TLV_ASN1_LOW_TAG_LIMIT = 31,
    /**
     * Longest tag, in bytes, that the BER, CER and DER formats read, write or
     * construct. This is a limit of these formats, not of #tlv_tag_t.
     */
    TLV_ASN1_TAG_MAX_SIZE = 8
};

/**
 * @brief Returns the ASN.1 class of a BER tag.
 *
 * @param tag A successfully parsed or created BER tag; must be non-`NULL`
 *            and nonempty.
 *
 * @return The identifier-octet class.
 */
static inline tlv_asn1_class_t tlv_ber_tag_class(const tlv_tag_t* tag) {
    return (tlv_asn1_class_t)(tag->data[0] >> TLV_ASN1_CLASS_SHIFT);
}
/**
 * @brief Reports whether a BER tag has the constructed bit set.
 *
 * @param tag A successfully parsed or created BER tag; must be non-`NULL`
 *            and nonempty.
 *
 * @return Nonzero if constructed, zero if primitive.
 */
static inline int tlv_ber_tag_is_constructed(const tlv_tag_t* tag) {
    return (tag->data[0] & TLV_ASN1_CONSTRUCTED_BIT) != 0;
}

/**
 * @brief Constructs a raw BER tag from its class, form and tag number.
 *
 * Unlike the corresponding DER and CER tag constructors, this does not
 * enforce any canonical primitive/constructed rule tied to a universal type
 * number; only the reserved EOC identifier (universal class, tag number 0,
 * in either form) is rejected, matching #tlv_reader_format_ber and
 * #tlv_writer_format_ber.
 *
 * @param[in]  tag_class   ASN.1 class.
 * @param[in]  constructed Nonzero for constructed form, zero for primitive.
 * @param[in]  number      Tag number.
 * @param[out] storage     Destination for the tag bytes; #TLV_ASN1_TAG_MAX_SIZE
 *                         writable bytes. Must outlive every use of the tag.
 * @param[out] tag         Receives a tag that borrows `storage`.
 *
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG if `storage` or `tag` is `NULL`.
 * @return #TLV_ERR_INVALID_TAG if `tag_class` or `constructed` is out of
 *         range, or the identifier is the reserved EOC tag.
 * @return #TLV_ERR_INVALID_TAG_SIZE if the tag would exceed #TLV_ASN1_TAG_MAX_SIZE.
 *
 * @note The destination is unchanged on failure.
 */
TLV_API tlv_result_t tlv_ber_tag_make(tlv_asn1_class_t tag_class, int constructed, uint64_t number,
                                      uint8_t* storage, tlv_tag_t* tag);
/**
 * @brief Extracts the numeric tag number from a BER tag.
 *
 * @param[in]  tag    A successfully parsed or created BER tag.
 * @param[out] number Receives the tag number.
 *
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG if a required pointer is `NULL`.
 * @return #TLV_ERR_INVALID_TAG if the encoding is invalid or the number
 *         exceeds `uint64_t`.
 * @return #TLV_ERR_INVALID_TAG_SIZE for an empty tag or one exceeding
 *         #TLV_ASN1_TAG_MAX_SIZE.
 *
 * @note `*number` is unchanged on failure.
 */
TLV_API tlv_result_t tlv_ber_tag_number(const tlv_tag_t* tag, uint64_t* number);

/**
 * @brief Reader format for raw BER-TLV.
 *
 * Accepts tags up to #TLV_ASN1_TAG_MAX_SIZE bytes, including high-tag-number form, and
 * definite lengths up to `SIZE_MAX`. Reads accept nonminimal definite lengths
 * and constructed indefinite lengths. Tag bytes are preserved (including
 * `9F 1C`); ASN.1 semantics are not validated.
 *
 * @see tlv_writer_format_ber
 */
extern TLV_API const tlv_reader_format_t tlv_reader_format_ber;
/**
 * @brief Writer format for raw BER-TLV.
 *
 * Writes definite lengths using the shortest length encoding. Use
 * tlv_ber_write_indefinite() for explicit indefinite framing.
 *
 * @see tlv_reader_format_ber
 */
extern TLV_API const tlv_writer_format_t tlv_writer_format_ber;

/**
 * @brief Maximum simultaneous constructed scopes while resolving an indefinite element.
 *
 * Counts the element itself and its definite constructed descendants. The
 * implementation uses a fixed stack, without allocation or recursion.
 */
enum { TLV_BER_MAX_DEPTH = 64 };

/**
 * @brief Reports the encoded size of an explicit indefinite element.
 *
 * The encoding is `tag + 80 + encoded children + 00 00`. Only constructed
 * tags are accepted. The query validates the tag and size overflow without
 * inspecting child bytes.
 *
 * @param[in]  tag    Constructed element tag.
 * @param[in]  length Size of the encoded children in bytes.
 * @param[out] size   Receives the complete encoded size.
 *
 * @return #TLV_OK on success.
 * @return An error code for a null output, an invalid or non-constructed
 *         tag, or size overflow.
 *
 * @note `*size` is unchanged on failure.
 * @see tlv_ber_write_indefinite
 */
TLV_API tlv_result_t tlv_ber_indefinite_encoded_size(tlv_tag_t tag, size_t length, size_t* size);

/**
 * @brief Writes an explicit indefinite-length constructed element.
 *
 * The ordinary BER writer remains definite-length. The encoding is
 * `tag + 80 + encoded children + 00 00`. Only constructed tags are
 * accepted. Child framing and nesting are validated before the buffer is
 * changed.
 *
 * @param[out] data     Destination buffer. `NULL` with zero `capacity` queries
 *                      the size.
 * @param[in]  capacity Destination capacity in bytes.
 * @param[in]  tag      Constructed element tag.
 * @param[in]  value    Already encoded children. Must not include the
 *                      enclosing EOC, and must not overlap the destination.
 * @param[in]  length   Size of `value` in bytes.
 * @param[out] written  Receives the encoded size.
 *
 * @return #TLV_OK on success.
 * @return An error code for invalid arguments, a non-constructed or invalid
 *         tag, malformed children, or insufficient capacity.
 *
 * @note All outputs remain unchanged on failure.
 * @see tlv_ber_indefinite_encoded_size
 */
TLV_API tlv_result_t tlv_ber_write_indefinite(uint8_t* data, size_t capacity, tlv_tag_t tag,
                                              const uint8_t* value, size_t length, size_t* written);

/**
 * @brief Appends an explicit indefinite-length element to a writer.
 *
 * Follows the contract of tlv_ber_write_indefinite(), writing at the
 * writer's current position.
 *
 * @param[in,out] writer Writer initialized with #tlv_writer_format_ber.
 * @param[in]     tag    Constructed element tag.
 * @param[in]     value  Already encoded children, without the enclosing EOC.
 * @param[in]     length Size of `value` in bytes.
 *
 * @return #TLV_OK on success; the writer position advances.
 * @return An error code as for tlv_ber_write_indefinite().
 *
 * @note On failure the writer position is unchanged.
 */
TLV_API tlv_result_t tlv_ber_writer_write_indefinite(tlv_writer_t* writer, tlv_tag_t tag,
                                                     const uint8_t* value, size_t length);

/**
 * @brief Nesting predicate for tree traversal of BER data.
 *
 * Matches #tlv_is_constructed_fn.
 *
 * @param context Unused; may be `NULL`.
 * @param tag     A successfully parsed BER tag.
 *
 * @return Nonzero if the tag is constructed, zero otherwise.
 */
TLV_API int tlv_ber_is_constructed(const void* context, const tlv_tag_t* tag);

/*
 * The definite-length field codec below (X.690 section 8.1.3) is standalone,
 * independent of the format callbacks above and of any value payload. It uses
 * #tlv_length_t so the decoded value has the same 64-bit range on every
 * build, regardless of the current build's `size_t` width; convert with
 * tlv_length_to_size() before using it as a native buffer length. Byte order
 * is fixed by the BER definite-length encoding itself; there is no runtime
 * order parameter.
 */

/**
 * @brief Bytes needed for the shortest definite encoding of any #tlv_length_t.
 *
 * One prefix octet plus up to 8 big-endian value octets for `UINT64_MAX`.
 * Use this constant to size a destination buffer for tlv_ber_length_encode().
 *
 * @note It is smaller than the largest field tlv_ber_length_decode() can
 *       still accept, since BER permits nonminimal (zero-padded) definite
 *       encodings with up to 127 length octets (X.690 section 8.1.3.4);
 *       decoding such padding needs no buffer this large, only reading one.
 */
enum { TLV_BER_LENGTH_MAX_ENCODED_SIZE = 9 };

/**
 * @brief Decodes one BER definite-length field starting at `data[0]`.
 *
 * Accepts the short form directly, or the long form as a length-of-length
 * octet followed by that many big-endian value octets. Nonminimal
 * (zero-padded) long-form encodings are accepted when the numeric value
 * still fits #tlv_length_t; excess leading octets must be zero. The
 * indefinite marker (0x80 alone) and the reserved 0xFF prefix are rejected,
 * as is a padded value wider than #tlv_length_t or nonzero excess padding.
 *
 * This does not process the indefinite-length marker or constructed EOC
 * framing; see tlv_ber_write_indefinite() and #tlv_reader_format_ber.
 *
 * @param[in]  data      Encoded field. May be `NULL` only when `data_size` is zero.
 * @param[in]  data_size Number of readable bytes in `data`.
 * @param[out] value     Receives the decoded length. Required.
 * @param[out] consumed  Receives the number of bytes the field occupies. Required.
 *
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG if a required pointer is `NULL`.
 * @return #TLV_ERR_INVALID_LENGTH for the indefinite marker, the reserved
 *         0xFF prefix, a value wider than #tlv_length_t, or nonzero excess padding.
 * @return #TLV_ERR_BUFFER_TOO_SHORT if the field claims more length octets
 *         than `data_size` provides.
 *
 * @note On any failure `*value` and `*consumed` are unchanged.
 */
TLV_API tlv_result_t tlv_ber_length_decode(const uint8_t* data, size_t data_size,
                                           tlv_length_t* value, size_t* consumed);

/**
 * @brief Encodes a length using the shortest BER definite form.
 *
 * Uses the short form below 128, otherwise the long form with the minimal
 * number of value octets. Supports a size query: `out` may be `NULL` only
 * when `out_capacity` is zero, in which case no bytes are written and
 * `*written` receives the required size.
 *
 * @param[in]  value        Length to encode.
 * @param[out] out          Destination; may be `NULL` only for a size query.
 * @param[in]  out_capacity Destination capacity in bytes; see
 *                          #TLV_BER_LENGTH_MAX_ENCODED_SIZE.
 * @param[out] written      Receives the encoded (or required) size. Required.
 *
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG if a required pointer is `NULL`.
 * @return #TLV_ERR_BUFFER_TOO_SHORT if `out_capacity` is smaller than the
 *         required size; nothing is partially written.
 *
 * @note On any failure `*written` is unchanged.
 */
TLV_API tlv_result_t tlv_ber_length_encode(tlv_length_t value, uint8_t* out, size_t out_capacity,
                                           size_t* written);

#ifdef __cplusplus
}
#endif
/** @} */

#endif
