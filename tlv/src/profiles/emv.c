#include "tlv/profiles/emv.h"
#include "../codec/emv_internal.h"

#define EMV_WIRE_1(b1, b2) {{b1}, 1}
#define EMV_WIRE_2(b1, b2) {{b1, b2}, 2}
#define EMV_WIRE(size, b1, b2) EMV_WIRE_##size(b1, b2)
#define EMV_COUNT(array) (sizeof(array) / sizeof((array)[0]))

/* Each context has its own indices: BER tag bytes alone do not identify
 * semantics (e.g. 81 in BASE versus BHT). All tables use one dictionary.
 */
#define EMV_BEGIN(scope) enum { emv_index_start_##scope = -1,
#define EMV_TAG(scope, name, size, b1, b2, min, max, step, kind, arg) emv_index_##name,
#define EMV_END(scope) emv_count_##scope };
#include "tlv/profiles/emv_tags.def"
#undef EMV_BEGIN
#undef EMV_TAG
#undef EMV_END

#define EMV_BEGIN(scope)
#define EMV_TAG(scope, name, size, b1, b2, min, max, step, kind, arg) \
    const tlv_tag_t tlv_emv_tag_##name = EMV_WIRE(size, b1, b2);
#define EMV_END(scope)
#include "tlv/profiles/emv_tags.def"
#undef EMV_BEGIN
#undef EMV_TAG
#undef EMV_END

/* A leading sentinel makes even an empty reduced-capacity table valid C99. */
#define EMV_BEGIN(scope) static const tlv_schema_entry_t entries_##scope[] = { \
    {{{0}, 0}, 0, 0, 0},
#define EMV_TAG(scope, name, size, b1, b2, min, max, step, kind, arg) \
    {EMV_WIRE(size, b1, b2), min, max, 0},
#define EMV_END(scope) };
#include "tlv/profiles/emv_tags.def"
#undef EMV_BEGIN
#undef EMV_TAG
#undef EMV_END

#define EMV_BEGIN(scope) {entries_##scope + 1, emv_count_##scope},
#define EMV_TAG(scope, name, size, b1, b2, min, max, step, kind, arg)
#define EMV_END(scope)
static const tlv_schema_t schemas[] = {
#include "tlv/profiles/emv_tags.def"
};
#undef EMV_BEGIN
#undef EMV_TAG
#undef EMV_END

const tlv_schema_t tlv_emv_schema = {entries_BASE + 1, emv_count_BASE};

/* No identity codecs for opaque values, text, or nested templates. */
#define EMV_CODEC_BYTES(name, min, max, step, kind, arg)
#define EMV_CODEC_TEXT EMV_CODEC_BYTES
#define EMV_CODEC_TEMPLATE EMV_CODEC_BYTES
#define EMV_CODEC_NUMBER(name, min, max, step, kind, arg) \
    static const emv_value_rule_t rule_##name = {min, max, step, TLV_EMV_VALUE_##kind, arg}; \
    static const tlv_codec_t codec_##name = {&rule_##name, emv_value_decode, emv_value_encode};
#define EMV_CODEC_FLAGS EMV_CODEC_NUMBER
#define EMV_CODEC_DIGITS EMV_CODEC_NUMBER
#define EMV_CODEC_DATE EMV_CODEC_NUMBER
#define EMV_CODEC_TIME EMV_CODEC_NUMBER
#define EMV_CODEC_ACCOUNT EMV_CODEC_NUMBER
#define EMV_CODEC_CRYPTOGRAM EMV_CODEC_NUMBER
#define EMV_CODEC_BIOMETRIC EMV_CODEC_NUMBER
#define EMV_CODEC_NUMBER_LIST EMV_CODEC_NUMBER
#define EMV_BEGIN(scope)
#define EMV_TAG(scope, name, size, b1, b2, min, max, step, kind, arg) \
    EMV_CODEC_##kind(name, min, max, step, kind, arg)
#define EMV_END(scope)
#include "tlv/profiles/emv_tags.def"
#undef EMV_BEGIN
#undef EMV_TAG
#undef EMV_END

#define EMV_POINTER_BYTES(name) NULL
#define EMV_POINTER_TEXT(name) NULL
#define EMV_POINTER_TEMPLATE(name) NULL
#define EMV_POINTER_NUMBER(name) &codec_##name
#define EMV_POINTER_FLAGS EMV_POINTER_NUMBER
#define EMV_POINTER_DIGITS EMV_POINTER_NUMBER
#define EMV_POINTER_DATE EMV_POINTER_NUMBER
#define EMV_POINTER_TIME EMV_POINTER_NUMBER
#define EMV_POINTER_ACCOUNT EMV_POINTER_NUMBER
#define EMV_POINTER_CRYPTOGRAM EMV_POINTER_NUMBER
#define EMV_POINTER_BIOMETRIC EMV_POINTER_NUMBER
#define EMV_POINTER_NUMBER_LIST EMV_POINTER_NUMBER
#define EMV_BEGIN(scope) static const tlv_emv_definition_t definitions_##scope[] = {
#define EMV_TAG(scope, name, size, b1, b2, min, max, step, kind, arg) \
    {&entries_##scope[emv_index_##name + 1], #name, TLV_EMV_VALUE_##kind, EMV_POINTER_##kind(name), step},
#define EMV_END(scope) {NULL, NULL, TLV_EMV_VALUE_BYTES, NULL, 0}};
#include "tlv/profiles/emv_tags.def"
#undef EMV_BEGIN
#undef EMV_TAG
#undef EMV_END

#define EMV_BEGIN(scope) definitions_##scope,
#define EMV_TAG(scope, name, size, b1, b2, min, max, step, kind, arg)
#define EMV_END(scope)
static const tlv_emv_definition_t* const definitions[] = {
#include "tlv/profiles/emv_tags.def"
};
#undef EMV_BEGIN
#undef EMV_TAG
#undef EMV_END

const tlv_schema_t* tlv_emv_schema_for(tlv_emv_context_t context) {
    if ((unsigned)context >= EMV_COUNT(schemas)) return NULL;
    return context == TLV_EMV_CONTEXT_BASE ? &tlv_emv_schema : &schemas[context];
}

const tlv_emv_definition_t* tlv_emv_find(tlv_emv_context_t context,
                                       const tlv_tag_t* tag) {
    const tlv_schema_t* schema = tlv_emv_schema_for(context);
    const tlv_schema_entry_t* entry = tlv_schema_find(schema, tag);
    if (!entry) return NULL;
    return &definitions[context][entry - schema->entries];
}

tlv_result_t tlv_emv_validate_length(const tlv_emv_definition_t* definition,
                                    size_t length) {
    tlv_result_t result;
    if (!definition) return TLV_ERR_NULL_ARG;
    result = tlv_schema_validate_length(definition->schema, length);
    if (result != TLV_OK) return result;
    if (!definition->length_step ||
        (length - definition->schema->min_length) % definition->length_step)
        return TLV_ERR_INVALID_LENGTH;
    return TLV_OK;
}
