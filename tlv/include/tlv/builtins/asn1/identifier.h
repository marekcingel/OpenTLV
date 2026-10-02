// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_BUILTINS_ASN1_IDENTIFIER_H
#define OPENTLV_BUILTINS_ASN1_IDENTIFIER_H

#include "tlv/tag.h"
#include "tlv/export.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 * @ingroup formats
 * @brief Shared ASN.1 identifier classes, bit layout and accessors.
 *
 * Accessors inspect an already valid identifier without applying BER, DER or
 * CER policy. Format-specific constructors and number readers validate tags
 * according to their encoding-rule contract.
 */
/** @addtogroup formats
 * @{
 */
/**
 * @brief ASN.1 identifier-octet class bits (ITU-T X.690 section 8.1).
 *
 * Independent of any particular encoding rule set; shared by the DER and
 * CER rules.
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
 * @brief Returns the ASN.1 class of an ASN.1 tag.
 *
 * @param tag A successfully parsed or created ASN.1 tag; must be non-`NULL`
 *            and nonempty.
 *
 * @return The identifier-octet class.
 */
static inline tlv_asn1_class_t tlv_asn1_tag_class(const tlv_tag_t* tag) {
    return (tlv_asn1_class_t)(tag->data[0] >> TLV_ASN1_CLASS_SHIFT);
}

/**
 * @brief Reports whether an ASN.1 tag has the constructed bit set.
 *
 * @param tag A successfully parsed or created ASN.1 tag; must be non-`NULL`
 *            and nonempty.
 *
 * @return Nonzero if constructed, zero if primitive.
 */
static inline int tlv_asn1_tag_is_constructed(const tlv_tag_t* tag) {
    return (tag->data[0] & TLV_ASN1_CONSTRUCTED_BIT) != 0;
}

/**
 * @brief Shared ASN.1 constructed predicate for Format and tree traversal.
 *
 * @param context Unused; may be `NULL`.
 * @param tag A successfully parsed or created ASN.1 tag; non-`NULL` and nonempty.
 * @return Nonzero if constructed, zero otherwise.
 */
TLV_API int tlv_asn1_is_constructed(const void* context, const tlv_tag_t* tag);
/** @} */
#ifdef __cplusplus
}
#endif
#endif
