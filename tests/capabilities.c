// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#include "tlv/config.h"
#include "tlv/tlv.h"
#include "tlv/formats/fixed.h"
#include "tlv/tree.h"
#if OPENTLV_READER
#include "tlv/reader/reader.h"
#endif
#if OPENTLV_WRITER
#include "tlv/writer/writer.h"
#endif
#if OPENTLV_DOCUMENT
#include "tlv/document/document.h"
#endif
#if OPENTLV_QUERY
#include "tlv/query/query.h"
#endif
#if OPENTLV_SCHEMA
#include "tlv/schema/schema.h"
#endif
#if OPENTLV_CODEC
#include "tlv/codec/values.h"
#endif
#include <stdio.h>
#include <string.h>

#if !OPENTLV_READER && defined(OPENTLV_READER_H)
#error Unrelated public headers must not import Reader
#endif
#if !OPENTLV_WRITER && defined(OPENTLV_WRITER_H)
#error Unrelated public headers must not import Writer
#endif

#define CHECK(expr)                                                                                \
    do {                                                                                           \
        if (!(expr)) {                                                                             \
            fprintf(stderr, "line %d: %s\n", __LINE__, #expr);                                     \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

#if OPENTLV_DOCUMENT
static int constructed(const void* context, const tlv_tag_t* tag) {
    (void)context;
    return tag->size == 1 && tag->data[0] == 2;
}
#endif

int main(void) {
    tlv_fixed_format_t config = {0};
    tlv_format_t       format;
    const uint8_t      wire[] = {1, 1, 42};
    config.tag_size = 1;
    config.length_size = 1;
    config.length_order = TLV_BYTE_ORDER_BIG_ENDIAN;
    CHECK(tlv_fixed_format_init(&format, &config) == TLV_OK);
    CHECK(tlv_config_reader() == OPENTLV_READER);
    CHECK(tlv_config_writer() == OPENTLV_WRITER);
    CHECK(tlv_config_query() == OPENTLV_QUERY);
    CHECK(tlv_config_schema() == OPENTLV_SCHEMA);
    CHECK(tlv_config_codec() == OPENTLV_CODEC);
    CHECK(tlv_tag_equal(tlv_tag(wire, 1), tlv_tag(wire, 1)));
    {
        /* Field encodings are available through the umbrella even with every
         * optional capability and builtin disabled. */
        const tlv_fixed_identifier_t identifier = {3};
        const tlv_fixed_length_t     length = {8, TLV_BYTE_ORDER_LITTLE_ENDIAN};
        const uint8_t                tag_bytes[] = {0x9F, 0, 0xFF};
        const uint8_t count_bytes[] = {0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01};
        uint8_t       output[8];
        tlv_tag_t     tag = {0};
        tlv_size_t    count = 0;
        size_t        used = 0;
        CHECK(tlv_fixed_identifier_read(&identifier, tag_bytes, sizeof tag_bytes, &tag, &used) ==
              TLV_OK);
        CHECK(tag.data == tag_bytes && tag.size == sizeof tag_bytes && used == sizeof tag_bytes);
        CHECK(tlv_fixed_identifier_write(&identifier, &tag, NULL, 0, &used) == TLV_OK);
        CHECK(used == sizeof tag_bytes);
        CHECK(tlv_fixed_identifier_write(&identifier, &tag, output, sizeof output, &used) ==
              TLV_OK);
        CHECK(used == sizeof tag_bytes && memcmp(output, tag_bytes, used) == 0);
        CHECK(tlv_fixed_length_read(&length, count_bytes, sizeof count_bytes, &count, &used) ==
              TLV_OK);
        CHECK(count == UINT64_C(0x0123456789ABCDEF) && used == sizeof count_bytes);
        CHECK(tlv_fixed_length_write(&length, count, NULL, 0, &used) == TLV_OK);
        CHECK(used == sizeof count_bytes);
        CHECK(tlv_fixed_length_write(&length, count, output, sizeof output, &used) == TLV_OK);
        CHECK(used == sizeof count_bytes && memcmp(output, count_bytes, used) == 0);
    }
#if OPENTLV_READER
    {
        tlv_reader_t  reader;
        tlv_element_t element;
        CHECK(tlv_reader_init(&reader, wire, sizeof wire, &format) == TLV_OK);
        CHECK(tlv_reader_next(&reader, &element) == TLV_OK);
        CHECK(element.value.size == 1 && element.value.data[0] == 42);
        CHECK(tlv_reader_at_end(&reader));
    }
#endif
#if OPENTLV_WRITER
    {
        uint8_t output[3];
        size_t  written = 0;
        CHECK(tlv_write(output, sizeof output, &format, tlv_tag(wire, 1), wire + 2, 1, &written) ==
              TLV_OK);
        CHECK(written == sizeof wire && memcmp(output, wire, sizeof wire) == 0);
    }
#endif
#if OPENTLV_DOCUMENT
    {
        const uint8_t          container = 2;
        tlv_document_options_t options;
        tlv_document_t*        document = NULL;
        tlv_node_t *           parent = NULL, *child = NULL;
        format.is_constructed = constructed;
        CHECK(tlv_document_options_init(&options, &format) == TLV_OK);
        CHECK(tlv_document_create(&options, &document) == TLV_OK);
        CHECK(tlv_document_insert(document, NULL, NULL, tlv_tag(&container, 1), NULL, 0, &parent) ==
              TLV_OK);
        CHECK(tlv_document_insert(document, parent, NULL, tlv_tag(wire, 1), wire + 2, 1, &child) ==
              TLV_OK);
        CHECK(tlv_document_count(document) == 2 && tlv_node_first_child(parent) == child);
#if OPENTLV_QUERY && OPENTLV_QUERY_FRONTEND
        {
            tlv_query_t query;
            CHECK(tlv_query_parse("02/01", &query, NULL) == TLV_OK);
            CHECK(tlv_document_find_path(document, &query) == child);
        }
#endif
#if OPENTLV_WRITER
        {
            const uint8_t expected[] = {2, 3, 1, 1, 42};
            uint8_t       output[5];
            size_t        written = 0;
            CHECK(tlv_document_encode(document, output, sizeof output, &written) == TLV_OK);
            CHECK(written == sizeof expected && memcmp(output, expected, written) == 0);
        }
#endif
#if !OPENTLV_READER
        {
            uint64_t revision = tlv_document_revision(document);
            CHECK(tlv_node_set_value(parent, wire, sizeof wire) == TLV_ERR_UNSUPPORTED_TYPE);
            CHECK(tlv_document_revision(document) == revision);
            CHECK(tlv_node_first_child(parent) == child && tlv_document_count(document) == 2);
        }
#endif
        CHECK(tlv_node_set_value(child, wire, 1) == TLV_OK);
        tlv_node_erase(child);
        CHECK(tlv_document_count(document) == 1);
        tlv_document_free(document);
#if OPENTLV_READER
        options.retain_source_locations = 1;
        CHECK(tlv_document_parse(wire, sizeof wire, &options, &document, NULL) == TLV_OK);
        CHECK(tlv_document_count(document) == 1);
        CHECK(tlv_node_source_location(tlv_document_first(document)).has_offset);
        CHECK(tlv_node_source_location(tlv_document_first(document)).header_size == 2);
        tlv_document_free(document);
#endif
        /* Programmatic trees need neither a decoder nor an encoder. */
        format.decode = NULL;
        format.measure = NULL;
        format.encode = NULL;
        CHECK(tlv_document_options_init(&options, &format) == TLV_OK);
        options.retain_source_locations = 1;
        CHECK(tlv_document_create(&options, &document) == TLV_OK);
        CHECK(tlv_document_insert(document, NULL, NULL, tlv_tag(wire, 1), wire + 2, 1, &child) ==
              TLV_OK);
        CHECK(!tlv_node_source_location(child).has_offset);
        tlv_document_free(document);
    }
#endif
#if OPENTLV_QUERY && OPENTLV_QUERY_FRONTEND
    {
        tlv_query_t query;
        CHECK(tlv_query_parse("01", &query, NULL) == TLV_OK);
        CHECK(tlv_query_count(&query) == 1);
        tlv_query_matcher_t matcher;
        tlv_tag_t           tag = tlv_tag(wire, 1);
        CHECK(tlv_query_matcher_init(&matcher, &query) == TLV_OK);
        CHECK(tlv_query_matcher_visit(&matcher, &tag, 0));
    }
#endif
#if OPENTLV_SCHEMA
    {
        tlv_schema_entry_t entry = {0};
        entry.min_length = 1;
        entry.max_length = 1;
        CHECK(tlv_schema_validate_length(&entry, 1) == TLV_OK);
        CHECK(tlv_schema_validate_length(&entry, 2) != TLV_OK);
    }
#endif
#if OPENTLV_CODEC
    {
        uint8_t value = 0;
        CHECK(tlv_codec_decode(&tlv_codec_uint8, wire + 2, 1, &value, sizeof value) ==
              TLV_CODEC_OK);
        CHECK(value == 42);
    }
#endif
    return 0;
}
