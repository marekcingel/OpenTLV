#ifndef OPENTLV_PROFILES_EMV_H
#define OPENTLV_PROFILES_EMV_H

#include "tlv/schemas/schema.h"
#include "tlv/codec/emv.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Scope: EMV Contact Book 3 v4.4, October 2022, Annex A and the nested
 * biometric tags in Annex C. No Contactless kernels, proprietary dictionaries,
 * or subsequent specification bulletins. Untagged data elements are not tags.
 * Use &tlv_reader_format_ber with generic I/O; this profile does not parse TLV.
 * Tag constants that exceed TLV_TAG_MAX_SIZE are omitted from all tables.
 */
#define TLV_EMV_SPECIFICATION "EMV Contact Book 3 v4.4 (October 2022)"

typedef enum {
    TLV_EMV_CONTEXT_BASE = 0,          /* ordinary application data */
    TLV_EMV_CONTEXT_BIT,               /* inside 7F60 */
    TLV_EMV_CONTEXT_BHT,               /* inside A1 within 7F60 */
    TLV_EMV_CONTEXT_BHT_FORMAT,        /* inside level-2 A1/A2 within BHT */
    TLV_EMV_CONTEXT_BIT_GROUP,         /* inside BF4A/BF4B, or terminal group */
    TLV_EMV_CONTEXT_BIOMETRIC_COUNTERS, /* inside BF4C */
    TLV_EMV_CONTEXT_BIOMETRIC_ATTEMPTS, /* inside BF4D */
    TLV_EMV_CONTEXT_BIOMETRIC_VERIFICATION, /* inside BF4E */
    TLV_EMV_CONTEXT_COUNT
} tlv_emv_context_t;

/* AIP masks for the uint64_t FLAGS representation (Annex C1). */
#define TLV_EMV_AIP_XDA_SUPPORTED UINT64_C(0x8000)
#define TLV_EMV_AIP_SDA_SUPPORTED UINT64_C(0x4000)
#define TLV_EMV_AIP_DDA_SUPPORTED UINT64_C(0x2000)
#define TLV_EMV_AIP_CARDHOLDER_VERIFICATION_SUPPORTED UINT64_C(0x1000)
#define TLV_EMV_AIP_TERMINAL_RISK_MANAGEMENT_REQUIRED UINT64_C(0x0800)
#define TLV_EMV_AIP_ISSUER_AUTHENTICATION_SUPPORTED UINT64_C(0x0400)
#define TLV_EMV_AIP_CDA_SUPPORTED UINT64_C(0x0100)

/* Public constants are all the same universal tlv_tag_t as generic I/O. */
#define EMV_BEGIN(scope)
#define EMV_TAG(scope, name, size, b1, b2, min, max, step, kind, arg) \
    extern const tlv_tag_t tlv_emv_tag_##name;
#define EMV_END(scope)
#include "tlv/profiles/emv_tags.def"
#undef EMV_BEGIN
#undef EMV_TAG
#undef EMV_END

typedef struct {
    const tlv_schema_entry_t* schema;
    const char* name; /* stable symbolic name from emv_tags.def */
    tlv_emv_value_kind_t value_kind;
    const tlv_codec_t* codec; /* NULL when no conversion is provided */
    size_t length_step; /* permitted lengths: min + n * step */
} tlv_emv_definition_t;

extern const tlv_schema_t tlv_emv_schema; /* BASE context */
/* Immutable static tables; no allocation. Invalid contexts return NULL.
 * Contexts are explicit and never fall back to the base dictionary.
 */
const tlv_schema_t* tlv_emv_schema_for(tlv_emv_context_t context);
const tlv_emv_definition_t* tlv_emv_find(tlv_emv_context_t context,
                                       const tlv_tag_t* tag);
/* Adds length-step checks (AFL, CVM lists, BIC, RSA exponents, etc.) to the
 * generic schema's inclusive bounds. NULL -> TLV_ERR_NULL_ARG.
 * Not a transaction validator: key-dependent lengths, required/duplicate tags,
 * template membership and cryptographic/value semantics are separate checks.
 */
tlv_result_t tlv_emv_validate_length(const tlv_emv_definition_t* definition,
                                    size_t length);

#ifdef __cplusplus
}
#endif
#endif /* OPENTLV_PROFILES_EMV_H */
