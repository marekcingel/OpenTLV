#ifndef OPENTLV_BUILTINS_ASN1_CODEC_H
#define OPENTLV_BUILTINS_ASN1_CODEC_H
#include "tlv/codec/codec.h"
#include "tlv/export.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 * @ingroup codecs
 * @brief Value codecs for ASN.1 primitive universal types (ITU-T X.690).
 *
 * Use tlv_codec_decode() and tlv_codec_encode() with these codecs on a raw
 * value already read by a BER-family format (#tlv_reader_format_ber, or a
 * DER or CER profile reader). A codec interprets only the value bytes it is
 * given; it never reads a tag, so callers choose the codec matching an
 * element's universal type themselves, for example from a schema or
 * dictionary.
 *
 * Every codec enforces the same canonical content rules ITU-T X.690 section
 * 11 defines for DER and CER, even when the raw value was read through the
 * more permissive BER format: BOOLEAN accepts only content `00` or `FF`,
 * INTEGER and ENUMERATED reject non-minimal two's complement encodings, and
 * so on. A non-canonical but otherwise legal plain-BER encoding (for example
 * a BOOLEAN of `01`) is rejected with #TLV_CODEC_ERR_INVALID_VALUE.
 *
 * BIT STRING and OCTET STRING decode into a representation that borrows the
 * input value bytes; that input must then outlive the representation, as
 * with any zero-copy tlv_codec_t decode. Every other codec's representation
 * is self-contained.
 */

/** @addtogroup codecs
 * @{
 */

/**
 * @brief BOOLEAN codec (X.690 section 8.2 and 11.1): one content byte, `bool`.
 *
 * Decode requires exactly one content byte, `00` (`false`) or `FF` (`true`);
 * any other content, including any other length, is
 * #TLV_CODEC_ERR_INVALID_VALUE. Encode always writes one byte, `00` or `FF`.
 */
extern TLV_API const tlv_codec_t tlv_asn1_codec_boolean;

/**
 * @brief INTEGER codec (X.690 section 8.3 and 11.2): minimal two's complement, `int64_t`.
 *
 * Decode requires the minimal big-endian two's complement encoding X.690
 * defines (no redundant all-zero or all-one leading byte); content needing
 * more than 8 bytes in that minimal form has no `int64_t` representation and
 * is rejected with #TLV_CODEC_ERR_INVALID_VALUE. Encode always writes the
 * minimal two's complement encoding of the given value, 1 to 8 bytes.
 */
extern TLV_API const tlv_codec_t tlv_asn1_codec_integer;

/**
 * @brief ENUMERATED codec (X.690 section 8.4 and 11.2).
 *
 * Same content rules and `int64_t` representation as #tlv_asn1_codec_integer;
 * ENUMERATED and INTEGER share identical wire content rules under X.690
 * section 11.2.
 *
 * @see tlv_asn1_codec_integer
 */
extern TLV_API const tlv_codec_t tlv_asn1_codec_enumerated;

/**
 * @brief Decoded BIT STRING content (X.690 section 8.6): unused-bit count and borrowed bits.
 */
typedef struct tlv_asn1_bit_string {
    /** Unused low-order bits of the last byte of `data`, 0-7; 0 when `length` is 0. */
    uint8_t unused_bits;
    /** Borrowed content bytes, excluding the leading unused-bits octet. `NULL` only when `length`
     * is 0. */
    const uint8_t* data;
    /** Length of `data` in bytes, excluding the leading unused-bits octet. */
    size_t length;
} tlv_asn1_bit_string_t;

/**
 * @brief BIT STRING codec (X.690 section 8.6 and 11.2): #tlv_asn1_bit_string_t.
 *
 * Decode requires at least the leading unused-bits octet, `unused_bits` in
 * 0-7, and every trailing unused bit of the last content byte clear; the
 * result borrows `data`. Encode reproduces those same requirements from the
 * representation's fields, rejecting a set trailing unused bit, an
 * `unused_bits` outside 0-7, or a nonzero `unused_bits` with an empty
 * `data`.
 */
extern TLV_API const tlv_codec_t tlv_asn1_codec_bit_string;

/** @brief Decoded OCTET STRING content (X.690 section 8.7): borrowed, unconstrained bytes. */
typedef struct tlv_asn1_octet_string {
    /** Borrowed content bytes. `NULL` only when `length` is 0. */
    const uint8_t* data;
    /** Length of `data` in bytes. */
    size_t length;
} tlv_asn1_octet_string_t;

/**
 * @brief OCTET STRING codec (X.690 section 8.7 and 11.2): #tlv_asn1_octet_string_t.
 *
 * Every byte sequence, including empty content, is valid; decode borrows
 * the input value and encode reproduces it unchanged.
 */
extern TLV_API const tlv_codec_t tlv_asn1_codec_octet_string;

/**
 * @brief NULL codec (X.690 section 8.8 and 11.2): no representation.
 *
 * Decode requires empty content and writes nothing to `*value`; per
 * tlv_codec_decode(), `value` must still be a non-`NULL` object, of any type
 * and any capacity including zero. Encode reads nothing from `value` and
 * always reports zero bytes written.
 */
extern TLV_API const tlv_codec_t tlv_asn1_codec_null;

/**
 * @brief Maximum number of arcs #tlv_asn1_oid_t can hold.
 *
 * Generous for every OBJECT IDENTIFIER or RELATIVE-OID seen in practice;
 * decode reports #TLV_CODEC_ERR_INVALID_VALUE if the content needs more.
 */
enum { TLV_ASN1_OID_MAX_ARCS = 32 };

/** @brief Decoded OBJECT IDENTIFIER or RELATIVE-OID arc values (X.690 section 8.19 and 8.20). */
typedef struct tlv_asn1_oid {
    /** Arc values in order; only the first `count` entries are populated. */
    uint64_t arcs[TLV_ASN1_OID_MAX_ARCS];
    /** Number of populated entries in `arcs`. */
    size_t count;
} tlv_asn1_oid_t;

/**
 * @brief OBJECT IDENTIFIER codec (X.690 section 8.19 and 11.3): #tlv_asn1_oid_t.
 *
 * The content's first subidentifier decodes to two arcs following X.690
 * section 8.19.4: `arcs[0]` is 0, 1 or 2, and `arcs[1]` is its remainder
 * (below 40 when `arcs[0]` is 0 or 1, unbounded when `arcs[0]` is 2); `count`
 * is therefore always at least 2 on success. Every subidentifier must be a
 * minimal base-128 encoding (no redundant leading `80` byte) whose value
 * fits `uint64_t`; more subidentifiers than #TLV_ASN1_OID_MAX_ARCS `- 1`
 * allows is #TLV_CODEC_ERR_INVALID_VALUE. Encode rejects `arcs[0]` outside
 * 0-2, `arcs[1]` >= 40 when `arcs[0]` < 2, and arc combinations that would
 * overflow `uint64_t`.
 *
 * @see tlv_asn1_codec_relative_oid
 */
extern TLV_API const tlv_codec_t tlv_asn1_codec_oid;

/**
 * @brief RELATIVE-OID codec (X.690 section 8.20 and 11.3): #tlv_asn1_oid_t.
 *
 * Every content subidentifier decodes to exactly one arc, without OBJECT
 * IDENTIFIER's first-subidentifier combining rule; `count` is therefore
 * always at least 1 on success. Subidentifier encoding and arc-count rules
 * otherwise match #tlv_asn1_codec_oid.
 *
 * @see tlv_asn1_codec_oid
 */
extern TLV_API const tlv_codec_t tlv_asn1_codec_relative_oid;

#ifdef __cplusplus
}
#endif
/** @} */

#endif /* OPENTLV_BUILTINS_ASN1_CODEC_H */
