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
 * @brief Value codecs for ASN.1 primitive, string and time universal types (ITU-T X.690).
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
 * BIT STRING, OCTET STRING, the restricted character string types
 * (UTF8String, NumericString, PrintableString, IA5String, VisibleString,
 * BMPString, UniversalString) and the fractional-seconds part of
 * GeneralizedTime decode into a representation that borrows the input value
 * bytes; that input must then outlive the representation, as with any
 * zero-copy tlv_codec_t decode. Every other codec's representation is
 * self-contained.
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

/**
 * @brief One named bit of a BIT STRING (X.680's `NamedBitList` notation, for example
 * `digitalSignature(0)` in a `KeyUsage`).
 *
 * Purely descriptive: unrelated to #tlv_asn1_codec_bit_string's own decode/encode, which never
 * interpret individual bit positions.
 */
typedef struct tlv_asn1_named_bit {
    /** Bit position; 0 is the most significant bit of the first content octet (X.680 clause 22). */
    size_t position;
    /** Borrowed, NUL-terminated display name. */
    const char* name;
} tlv_asn1_named_bit_t;

/**
 * @brief Tests whether one bit of a decoded BIT STRING is set.
 *
 * A DER-encoded BIT STRING omits trailing zero bits (its canonical content rule), so per X.680's
 * `NamedBitList` convention a `position` at or beyond the encoded bit count (`8 * bits->length`)
 * is implicitly clear rather than an error.
 *
 * @param[in] bits     Decoded BIT STRING to test; must not be `NULL`.
 * @param[in] position Bit position, 0 = the most significant bit of the first content octet.
 *
 * @return Nonzero if the bit is set.
 * @return 0 if the bit is clear, or `position` is at or beyond the encoded content.
 */
TLV_API int tlv_asn1_bit_string_test(const tlv_asn1_bit_string_t* bits, size_t position);

/**
 * @brief Looks up a named bit's display name by position in a table.
 *
 * @param[in] names    Borrowed table of named bits; may be `NULL` only when `count` is 0.
 * @param[in] count    Number of entries in `names`.
 * @param[in] position Bit position to find.
 *
 * @return The borrowed, NUL-terminated name of the entry whose `position` matches.
 * @return `NULL` if no entry matches.
 */
TLV_API const char* tlv_asn1_named_bit_find(const tlv_asn1_named_bit_t* names, size_t count,
                                            size_t position);

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

/**
 * @brief Decoded restricted character string content (X.690 section 8.23): borrowed bytes.
 *
 * Shared by every codec whose valid content is a byte sequence restricted to
 * a fixed character set: UTF8String, NumericString, PrintableString,
 * IA5String and VisibleString.
 */
typedef struct tlv_asn1_string {
    /** Borrowed content bytes. `NULL` only when `length` is 0. */
    const uint8_t* data;
    /** Length of `data` in bytes. */
    size_t length;
} tlv_asn1_string_t;

/**
 * @brief UTF8String codec (X.690 section 8.23): #tlv_asn1_string_t.
 *
 * Decode requires well-formed UTF-8: no overlong encoding, no surrogate code
 * point (U+D800-U+DFFF), no code point above U+10FFFF, and no truncated or
 * malformed continuation byte. Encode enforces the same rule and reproduces
 * the content unchanged.
 */
extern TLV_API const tlv_codec_t tlv_asn1_codec_utf8_string;

/**
 * @brief NumericString codec (X.690 section 8.23): #tlv_asn1_string_t.
 *
 * Every content byte must be `0`-`9` or the space character; any other byte
 * is #TLV_CODEC_ERR_INVALID_VALUE on decode or encode.
 */
extern TLV_API const tlv_codec_t tlv_asn1_codec_numeric_string;

/**
 * @brief PrintableString codec (X.690 section 8.23): #tlv_asn1_string_t.
 *
 * Every content byte must be a letter, digit, space, or one of
 * `'()+,-./:=?`; any other byte is #TLV_CODEC_ERR_INVALID_VALUE on decode or
 * encode.
 */
extern TLV_API const tlv_codec_t tlv_asn1_codec_printable_string;

/**
 * @brief IA5String codec (X.690 section 8.23): #tlv_asn1_string_t.
 *
 * Every content byte must be 7-bit ASCII (`0x00`-`0x7F`); any other byte is
 * #TLV_CODEC_ERR_INVALID_VALUE on decode or encode.
 */
extern TLV_API const tlv_codec_t tlv_asn1_codec_ia5_string;

/**
 * @brief VisibleString codec (X.690 section 8.23): #tlv_asn1_string_t.
 *
 * Every content byte must be a printable ASCII character, space through `~`
 * (`0x20`-`0x7E`); any other byte is #TLV_CODEC_ERR_INVALID_VALUE on decode
 * or encode.
 */
extern TLV_API const tlv_codec_t tlv_asn1_codec_visible_string;

/** @brief Decoded BMPString content (X.690 section 8.23): borrowed UCS-2 code units. */
typedef struct tlv_asn1_bmp_string {
    /** Borrowed content bytes, `length * 2` of them, big-endian UCS-2 code units.
     *  `NULL` only when `length` is 0. */
    const uint8_t* data;
    /** Number of UCS-2 code units in `data`. */
    size_t length;
} tlv_asn1_bmp_string_t;

/**
 * @brief BMPString codec (X.690 section 8.23): #tlv_asn1_bmp_string_t.
 *
 * Decode requires content whose length is a multiple of 2 bytes and whose
 * every big-endian 16-bit code unit is outside the surrogate range
 * (U+D800-U+DFFF); use tlv_read_u16_be() on `data + 2 * i` to read code unit
 * `i`. Encode enforces the same rule and reproduces the content unchanged.
 */
extern TLV_API const tlv_codec_t tlv_asn1_codec_bmp_string;

/** @brief Decoded UniversalString content (X.690 section 8.23): borrowed UCS-4 code points. */
typedef struct tlv_asn1_universal_string {
    /** Borrowed content bytes, `length * 4` of them, big-endian UCS-4 code points.
     *  `NULL` only when `length` is 0. */
    const uint8_t* data;
    /** Number of UCS-4 code points in `data`. */
    size_t length;
} tlv_asn1_universal_string_t;

/**
 * @brief UniversalString codec (X.690 section 8.23): #tlv_asn1_universal_string_t.
 *
 * Decode requires content whose length is a multiple of 4 bytes and whose
 * every big-endian 32-bit code point is at most U+10FFFF and outside the
 * surrogate range (U+D800-U+DFFF); use tlv_read_u32_be() on `data + 4 * i` to
 * read code point `i`. Encode enforces the same rule and reproduces the
 * content unchanged.
 */
extern TLV_API const tlv_codec_t tlv_asn1_codec_universal_string;

/**
 * @brief Decoded UTCTime content (X.690 section 8.26 and 11.8): a two-digit-year timestamp.
 *
 * Calendar fields are range-checked only (for example day 1-31); a
 * calendar-invalid date such as 30 February is not detected.
 */
typedef struct tlv_asn1_utc_time {
    /** Four-digit year, derived from the wire's two-digit year by the
     *  convention X.680 recommends and widely used profiles (for example
     *  RFC 5280) apply: 0-49 maps to 2000-2049, 50-99 maps to 1950-1999. */
    int32_t year;
    /** Month, 1-12. */
    uint8_t month;
    /** Day of month, 1-31. */
    uint8_t day;
    /** Hour, 0-23. */
    uint8_t hour;
    /** Minute, 0-59. */
    uint8_t minute;
    /** Second, 0-59. */
    uint8_t second;
} tlv_asn1_utc_time_t;

/**
 * @brief UTCTime codec (X.690 section 8.26 and 11.8): #tlv_asn1_utc_time_t.
 *
 * Decode requires the canonical `YYMMDDHHMMSSZ` form (13 bytes, UTC only,
 * seconds mandatory) and range-checks every calendar field; `year` is
 * derived from the two-digit wire year as #tlv_asn1_utc_time_t documents.
 * Encode requires `year` in 1950-2049 (every other year has no two-digit
 * representation under that same convention) and every other field in its
 * documented range, and always reproduces the canonical form.
 */
extern TLV_API const tlv_codec_t tlv_asn1_codec_utc_time;

/**
 * @brief Decoded GeneralizedTime content (X.690 section 8.26 and 11.7): a four-digit-year
 * timestamp.
 *
 * Calendar fields are range-checked only (for example day 1-31); a
 * calendar-invalid date such as 30 February is not detected.
 */
typedef struct tlv_asn1_generalized_time {
    /** Four-digit year, taken from the wire as-is, 0-9999. */
    int32_t year;
    /** Month, 1-12. */
    uint8_t month;
    /** Day of month, 1-31. */
    uint8_t day;
    /** Hour, 0-23. */
    uint8_t hour;
    /** Minute, 0-59. */
    uint8_t minute;
    /** Second, 0-59. */
    uint8_t second;
    /** Borrowed decimal digits after the fractional-seconds `.`, excluding the `.`
     *  and the trailing `Z`. `NULL` when there is no fractional part. */
    const uint8_t* fraction_digits;
    /** Length of `fraction_digits` in bytes; 0 when there is no fractional part. */
    size_t fraction_digits_length;
} tlv_asn1_generalized_time_t;

/**
 * @brief GeneralizedTime codec (X.690 section 8.26 and 11.7): #tlv_asn1_generalized_time_t.
 *
 * Decode requires the canonical `YYYYMMDDHHMMSS[.fraction]Z` form (UTC only,
 * seconds mandatory, an optional fractional-seconds part whose digits never
 * end in `0`) and range-checks every calendar field; the result borrows
 * `fraction_digits`. Encode requires `year` in 0-9999 and every other field
 * in its documented range, rejects a non-digit byte or a trailing `0` in
 * `fraction_digits`, and rejects a `fraction_digits_length` of 0 paired with
 * a non-`NULL` `fraction_digits` or vice versa.
 */
extern TLV_API const tlv_codec_t tlv_asn1_codec_generalized_time;

/**
 * @brief ObjectDescriptor codec (X.690 section 11.2): #tlv_asn1_octet_string_t.
 *
 * ObjectDescriptor is `[UNIVERSAL 7] IMPLICIT GraphicString`; like OCTET
 * STRING, every byte sequence is valid content, since X.690 places no
 * canonical byte-level restriction on GraphicString's character set. Decode
 * and encode behave exactly as #tlv_asn1_codec_octet_string.
 */
extern TLV_API const tlv_codec_t tlv_asn1_codec_object_descriptor;

/**
 * @brief TeletexString codec (X.690 section 8.23 and 11.2): #tlv_asn1_octet_string_t.
 *
 * TeletexString (T61String)'s character set is a complex legacy (ISO
 * 2022-based) encoding X.690 places no canonical byte-level restriction on;
 * every byte sequence is valid content, as with OCTET STRING. Decode and
 * encode behave exactly as #tlv_asn1_codec_octet_string.
 */
extern TLV_API const tlv_codec_t tlv_asn1_codec_teletex_string;

/**
 * @brief VideotexString codec (X.690 section 8.23 and 11.2): #tlv_asn1_octet_string_t.
 *
 * Same treatment as #tlv_asn1_codec_teletex_string: a complex legacy
 * character set X.690 does not canonically restrict at the byte level.
 */
extern TLV_API const tlv_codec_t tlv_asn1_codec_videotex_string;

/**
 * @brief GraphicString codec (X.690 section 8.23 and 11.2): #tlv_asn1_octet_string_t.
 *
 * Same treatment as #tlv_asn1_codec_teletex_string.
 */
extern TLV_API const tlv_codec_t tlv_asn1_codec_graphic_string;

/**
 * @brief GeneralString codec (X.690 section 8.23 and 11.2): #tlv_asn1_octet_string_t.
 *
 * Same treatment as #tlv_asn1_codec_teletex_string.
 */
extern TLV_API const tlv_codec_t tlv_asn1_codec_general_string;

/**
 * @brief Generic TIME codec (X.690 section 11.7 and X.680 clause 38): #tlv_asn1_string_t.
 *
 * TIME's concrete ISO 8601-based syntax varies far more than
 * DATE/TIME-OF-DAY/DATE-TIME/DURATION below (week dates, ordinal dates,
 * fractional seconds, UTC offsets, intervals). Decode and encode only check
 * VisibleString's character-set restriction, not the fuller ISO 8601
 * canonical-form grammar.
 */
extern TLV_API const tlv_codec_t tlv_asn1_codec_time;

/** @brief Decoded DATE content (X.690 section 11.x): a calendar date. */
typedef struct tlv_asn1_date {
    /** Four-digit year, 0-9999. */
    int32_t year;
    /** Month, 1-12. */
    uint8_t month;
    /** Day of month, 1-31. */
    uint8_t day;
} tlv_asn1_date_t;

/**
 * @brief DATE codec (X.690 section 11.x): #tlv_asn1_date_t.
 *
 * Decode requires the canonical `YYYYMMDD` digit-only form (no `-`
 * separators) and range-checks the calendar fields (for example day 1-31);
 * a calendar-invalid date such as 30 February is not detected. Encode
 * requires `year` in 0-9999 and every other field in its documented range,
 * and always reproduces the canonical form.
 */
extern TLV_API const tlv_codec_t tlv_asn1_codec_date;

/** @brief Decoded TIME-OF-DAY content (X.690 section 11.x): a local time of day. */
typedef struct tlv_asn1_time_of_day {
    /** Hour, 0-23. */
    uint8_t hour;
    /** Minute, 0-59. */
    uint8_t minute;
    /** Second, 0-59. */
    uint8_t second;
} tlv_asn1_time_of_day_t;

/**
 * @brief TIME-OF-DAY codec (X.690 section 11.x): #tlv_asn1_time_of_day_t.
 *
 * Decode requires the canonical `HHMMSS` digit-only form (no `:` separators)
 * and range-checks every field. Encode requires every field in its
 * documented range and always reproduces the canonical form.
 */
extern TLV_API const tlv_codec_t tlv_asn1_codec_time_of_day;

/** @brief Decoded DATE-TIME content (X.690 section 11.x): a DATE immediately followed by a
 *  TIME-OF-DAY. */
typedef struct tlv_asn1_date_time {
    /** Four-digit year, 0-9999. */
    int32_t year;
    /** Month, 1-12. */
    uint8_t month;
    /** Day of month, 1-31. */
    uint8_t day;
    /** Hour, 0-23. */
    uint8_t hour;
    /** Minute, 0-59. */
    uint8_t minute;
    /** Second, 0-59. */
    uint8_t second;
} tlv_asn1_date_time_t;

/**
 * @brief DATE-TIME codec (X.690 section 11.x): #tlv_asn1_date_time_t.
 *
 * Decode requires the canonical `YYYYMMDDHHMMSS` digit-only form (no `-`,
 * `:` or `T` separators) and range-checks every calendar field. Encode
 * requires `year` in 0-9999 and every other field in its documented range,
 * and always reproduces the canonical form.
 */
extern TLV_API const tlv_codec_t tlv_asn1_codec_date_time;

/**
 * @brief DURATION codec (X.690 section 11.x): #tlv_asn1_string_t.
 *
 * Content is the ISO 8601 duration string without its leading `P`
 * designator, for example `2Y10M15DT10H20M30S`. Decode and encode validate
 * designator/digit structure and component order (`Y`, `M`, `D`, then
 * optionally `T` followed by `H`, `M`, `S`), but do not enforce ISO 8601's
 * omission of zero-valued components, and accept a fractional value only on
 * the seconds component.
 */
extern TLV_API const tlv_codec_t tlv_asn1_codec_duration;

/**
 * @brief Maximum number of arcs #tlv_asn1_iri_t can hold.
 *
 * Generous for every OID-IRI or RELATIVE-OID-IRI seen in practice; decode
 * reports #TLV_CODEC_ERR_INVALID_VALUE if the content needs more.
 */
enum { TLV_ASN1_IRI_MAX_ARCS = 32 };

/** @brief One borrowed arc label of a #tlv_asn1_iri_t. */
typedef struct tlv_asn1_iri_arc {
    /** Borrowed arc label bytes (valid UTF-8, never containing `/`). Never `NULL`. */
    const uint8_t* data;
    /** Length of `data` in bytes; always nonzero. */
    size_t length;
} tlv_asn1_iri_arc_t;

/** @brief Decoded OID-IRI or RELATIVE-OID-IRI content (X.690 section 8.21 and 8.22): arc labels. */
typedef struct tlv_asn1_iri {
    /** Arc labels in order; only the first `count` entries are populated. */
    tlv_asn1_iri_arc_t arcs[TLV_ASN1_IRI_MAX_ARCS];
    /** Number of populated entries in `arcs`. */
    size_t count;
} tlv_asn1_iri_t;

/**
 * @brief OID-IRI codec (X.690 section 8.21 and 11.3): #tlv_asn1_iri_t.
 *
 * Content is the UTF-8 encoding of `/`-separated arc labels, with a leading
 * `/` marking the absolute path (not itself an arc). Decode splits content
 * into borrowed per-arc spans; encode joins them back with `/` separators
 * and the leading `/`, rejecting an empty arc, a non-UTF-8 arc, or an arc
 * containing `/`. Checks arc-separator structure only, not each arc's
 * characters against the fuller RFC 3987 IRI-label restrictions X.680's IRI
 * value notation defines.
 *
 * @see tlv_asn1_codec_relative_oid_iri
 */
extern TLV_API const tlv_codec_t tlv_asn1_codec_oid_iri;

/**
 * @brief RELATIVE-OID-IRI codec (X.690 section 8.22 and 11.3): #tlv_asn1_iri_t.
 *
 * Same as #tlv_asn1_codec_oid_iri, except content has no leading `/` (it is
 * a relative path) and encode does not add one.
 *
 * @see tlv_asn1_codec_oid_iri
 */
extern TLV_API const tlv_codec_t tlv_asn1_codec_relative_oid_iri;

#ifdef __cplusplus
}
#endif
/** @} */

#endif /* OPENTLV_BUILTINS_ASN1_CODEC_H */
