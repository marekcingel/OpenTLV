// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_BUILTINS_ASN1_BER_H
#define OPENTLV_BUILTINS_ASN1_BER_H

#include "tlv/error.h"
#include "tlv/config.h"
#if OPENTLV_WRITER
#include "tlv/writer/writer.h"
#endif
#include "tlv/builtins/asn1/identifier.h"
#include "tlv/format.h"
#include "tlv/size.h"
#include "tlv/export.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 * @ingroup formats
 * @brief ASN.1 BER framing over generic variable-width identifier and length primitives.
 *
 * ASN.1 class/form interpretation, identifier restrictions, reserved length
 * prefixes and indefinite/EOC handling belong to this builtin. The existing
 * raw BER-TLV compatibility contract is retained; see #tlv_format_ber for its
 * validation limits. No operation requires a runtime engine or allocates.
 */

/** @addtogroup formats
 * @{
 */

/**
 * @brief Constructs a raw BER tag from its class, form and tag number.
 *
 * Unlike the corresponding DER and CER tag constructors, this does not
 * enforce any canonical primitive/constructed rule tied to a universal type
 * number; only the reserved EOC identifier (universal class, tag number 0,
 * in either form) is rejected, matching #tlv_format_ber.
 *
 * @param[in]  tag_class   ASN.1 class.
 * @param[in]  constructed One for constructed form, zero for primitive.
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
 * @brief Format for raw BER-TLV.
 *
 * Accepts tags up to #TLV_ASN1_TAG_MAX_SIZE bytes, including high-tag-number form, and
 * logical definite counts up to #TLV_SIZE_MAX; complete input/output must fit
 * native buffers. Reads accept nonminimal definite lengths
 * and constructed indefinite lengths. Tag bytes are preserved (including
 * `9F 1C`); ASN.1 semantics are not validated. Writes definite lengths using
 * the shortest length encoding. Use tlv_ber_write_indefinite() for explicit
 * indefinite framing.
 *
 * A zero first high-tag-number payload digit and UNIVERSAL tag zero in either
 * form are rejected. For raw-tag compatibility, high-tag-number encodings of
 * numbers below 31 remain accepted. Other UNIVERSAL assignments and type/form
 * constraints are not validated here (including reserved number 15). These
 * limits are not a claim of complete X.690 conformance. The generic Variable
 * primitives do not impose any of these ASN.1 policies.
 */
extern TLV_API const tlv_format_t tlv_format_ber;

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
 * @param[out] data     Destination buffer. `NULL` with zero `capacity` reports
 *                      #TLV_ERR_BUFFER_TOO_SHORT for a valid element. Use
 *                      tlv_ber_indefinite_encoded_size() for a size query.
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

#if OPENTLV_WRITER
/**
 * @brief Appends an explicit indefinite-length element to a writer.
 *
 * Follows the contract of tlv_ber_write_indefinite(), writing at the
 * writer's current position.
 *
 * @param[in,out] writer Writer initialized with #tlv_format_ber.
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
#endif

/*
 * The definite-length field codec below (X.690 section 8.1.3) is standalone,
 * independent of the format callbacks above and of any value payload. It uses
 * #tlv_size_t so the decoded value has the same 64-bit range on every
 * build, regardless of the current build's `size_t` width; convert with
 * tlv_size_to_native() before using it as a native buffer length. Byte order
 * is fixed by the BER definite-length encoding itself; there is no runtime
 * order parameter.
 */

/**
 * @brief Bytes needed for the shortest definite encoding of any #tlv_size_t.
 *
 * One prefix octet plus up to 8 big-endian value octets for `UINT64_MAX`.
 * Use this constant to size a destination buffer for tlv_ber_length_encode().
 *
 * @note It is smaller than the largest field tlv_ber_length_decode() can
 *       still accept, since BER permits nonminimal (zero-padded) definite
 *       encodings with up to 126 length octets (0xFF is reserved);
 *       decoding such padding needs no buffer this large, only reading one.
 */
enum { TLV_BER_LENGTH_MAX_ENCODED_SIZE = 9 };

/**
 * @brief Decodes one BER definite-length field starting at `data[0]`.
 *
 * Accepts the short form directly, or the long form as a length-of-length
 * octet followed by that many big-endian value octets. Nonminimal
 * (zero-padded) long-form encodings are accepted when the numeric value
 * still fits #tlv_size_t; excess leading octets must be zero. The
 * indefinite marker (0x80 alone) and the reserved 0xFF prefix are rejected,
 * as is a padded value wider than #tlv_size_t or nonzero excess padding.
 *
 * This does not process the indefinite-length marker or constructed EOC
 * framing; see tlv_ber_write_indefinite() and #tlv_format_ber.
 *
 * @param[in]  data      Encoded field. May be `NULL` only when `data_size` is zero.
 * @param[in]  data_size Number of readable bytes in `data`.
 * @param[out] value     Receives the decoded length. Required.
 * @param[out] consumed  Receives the number of bytes the field occupies. Required.
 *
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG if a required pointer is `NULL`.
 * @return #TLV_ERR_INVALID_LENGTH for the indefinite marker, the reserved
 *         0xFF prefix, a value wider than #tlv_size_t, or nonzero excess padding.
 * @return #TLV_ERR_TRUNCATED if the field claims more length octets
 *         than `data_size` provides.
 *
 * @note On any failure `*value` and `*consumed` are unchanged.
 */
TLV_API tlv_result_t tlv_ber_length_decode(const uint8_t* data, size_t data_size, tlv_size_t* value,
                                           size_t* consumed);

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
TLV_API tlv_result_t tlv_ber_length_encode(tlv_size_t value, uint8_t* out, size_t out_capacity,
                                           size_t* written);

/**
 * @brief BER policy writing constructed elements with indefinite length and EOC.
 * Reads all supported BER framing; rejects primitive encoding. Context is immutable.
 */
TLV_API extern const tlv_format_t tlv_format_ber_indefinite;

/**
 * @brief Decode one BER identifier without requiring a following length or value.
 *
 * Applies the raw identifier policy documented for #tlv_format_ber. Class and
 * constructed bits remain part of the borrowed identifier's byte identity.
 *
 * @param[in]  data     Input bytes; NULL only when size is zero.
 * @param[in]  size     Available bytes.
 * @param[out] tag      Borrowed identifier on success; data must outlive its use.
 * @param[out] consumed Identifier width on success.
 *
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG for a missing required pointer.
 * @return #TLV_ERR_INVALID_TAG for a reserved EOC tag or zero first payload digit.
 * @return #TLV_ERR_INVALID_TAG_SIZE if the identifier exceeds the supported width.
 * @return #TLV_ERR_TRUNCATED for an incomplete identifier.
 * @note Both outputs remain unchanged on failure. An invalid available first
 * payload digit is reported before later truncation or width errors.
 */
TLV_API tlv_result_t tlv_ber_read_identifier(const uint8_t* data, size_t size, tlv_tag_t* tag,
                                             size_t* consumed);

#ifdef __cplusplus
}
#endif

/** @} */

#endif
