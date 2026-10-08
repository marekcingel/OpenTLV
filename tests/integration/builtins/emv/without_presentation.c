// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/builtins/emv/emv.h"
#include "tlv/builtins/emv/emv_schema.h"
#include "tlv/codec/values.h"
#include "tlv/reader/reader.h"
#include <stdio.h>
#include <string.h>

#define CHECK(condition)                                                                           \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            fprintf(stderr, "line %d: %s\n", __LINE__, #condition);                                \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

int main(void) {
    const uint8_t               wire[] = {0x9F, 0x02, 6, 0, 0, 0, 0, 0x12, 0x34};
    const uint8_t               gpo[] = {0x77, 10, 0x82, 2, 0, 0, 0x94, 4, 8, 1, 1, 0};
    const uint8_t               missing_afl[] = {0x77, 4, 0x82, 2, 0, 0};
    tlv_element_t               element;
    const tlv_emv_definition_t* entry;
    uint64_t                    amount = 0;
    uint8_t                     encoded[6];
    size_t                      consumed = 0, written = 0;
    int                         context;
    CHECK(tlv_read(wire, sizeof(wire), &tlv_format_emv, &element, &consumed) == TLV_OK);
    CHECK(consumed == sizeof(wire));
    entry = tlv_emv_find(TLV_EMV_CONTEXT_BASE, &element.tag);
    CHECK(entry && entry->codec);
    CHECK(tlv_tag_equal(entry->definition->tag, tlv_emv_tag_amount_authorised));
    CHECK(tlv_emv_validate_length(entry, 6) == TLV_OK);
    CHECK(tlv_emv_validate_length(entry, 5) == TLV_ERR_SCHEMA);
    CHECK(tlv_codec_decode(entry->codec, element.value.data, 6, &amount, sizeof(amount)) ==
          TLV_CODEC_OK);
    CHECK(amount == 1234);
    CHECK(tlv_codec_encode(entry->codec, &amount, sizeof(amount), encoded, sizeof(encoded),
                           &written) == TLV_CODEC_OK);
    CHECK(written == 6 && memcmp(encoded, wire + 3, 6) == 0);
    CHECK(tlv_schema_validate(gpo, sizeof(gpo), &tlv_format_emv, &tlv_emv_structure_schema, 8, 100,
                              NULL) == TLV_OK);
    CHECK(tlv_schema_validate(missing_afl, sizeof(missing_afl), &tlv_format_emv,
                              &tlv_emv_structure_schema, 8, 100, NULL) != TLV_OK);
    for (context = 0; context < TLV_EMV_CONTEXT_COUNT; ++context) {
        const tlv_emv_dictionary_t* dictionary = tlv_emv_dictionary_for((tlv_emv_context_t)context);
        size_t                      i;
        CHECK(dictionary != NULL);
        for (i = 0; i < dictionary->count; ++i) {
            uint8_t   bytes[16];
            tlv_tag_t copied;
            entry = &dictionary->entries[i];
            CHECK(entry->definition->tag.size <= sizeof(bytes));
            memcpy(bytes, entry->definition->tag.data, entry->definition->tag.size);
            copied = tlv_tag(bytes, entry->definition->tag.size);
            CHECK(tlv_emv_dictionary_find(dictionary, &copied) == entry);
            CHECK(entry->definition->tag.data == entry->schema->tag.data);
        }
    }
    {
        /* A caller's representation for the same bytes need not match the builtin profile. */
        const tlv_definition_t     definition = {element.tag, "Caller field"};
        const tlv_schema_entry_t   field = {element.tag, 1, 1, 0, "caller", 0};
        const tlv_emv_definition_t custom = {&definition, &field, &tlv_codec_uint8};
        const tlv_emv_dictionary_t dictionary = {&custom, 1};
        const uint8_t              raw[] = {42};
        uint8_t                    value = 0;
        entry = tlv_emv_dictionary_find(&dictionary, &element.tag);
        CHECK(entry == &custom);
        CHECK(tlv_emv_validate_length(entry, 1) == TLV_OK);
        CHECK(tlv_codec_decode(entry->codec, raw, 1, &value, sizeof(value)) == TLV_CODEC_OK);
        CHECK(value == 42);
    }
    return 0;
}
