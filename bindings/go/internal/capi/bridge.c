// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#include "bridge.h"
#include <stdlib.h>
#if OPENTLV_DOCUMENT
#include <tlv/document/document.h>
#endif
#if OPENTLV_FORMAT_BER
#include <tlv/builtins/asn1/ber.h>
#endif
#if OPENTLV_FORMAT_DER
#include <tlv/builtins/asn1/der.h>
#endif
#if OPENTLV_FORMAT_CER
#include <tlv/builtins/asn1/cer.h>
#endif
#if OPENTLV_EMV
#include <tlv/builtins/emv/format.h>
#endif
#if OPENTLV_LLDP
#include <tlv/builtins/lldp/lldp.h>
#endif
#if OPENTLV_BLUETOOTH
#include <tlv/builtins/bluetooth/bluetooth_ltv.h>
#endif
#if OPENTLV_DHCP
#include <tlv/builtins/dhcp/dhcpv4.h>
#endif
#if OPENTLV_NFC
#include <tlv/builtins/nfc/type2.h>
#endif

/* All descriptors, contexts and cursors are call-local. No Go pointer is retained. */
static tlv_result_t resolve(go_format config, tlv_format_t* format, tlv_fixed_format_t* fixed) {
    switch (config.kind) {
        case GO_FORMAT_FIXED:
            fixed->tag_size = config.tag_size;
            fixed->length_size = config.length_size;
            fixed->length_order = (tlv_byte_order_t)config.byte_order;
            fixed->element_order = (tlv_element_order_t)config.element_order;
            fixed->length_scope = (tlv_length_scope_t)config.length_scope;
            return tlv_fixed_format_init(format, fixed);
#if OPENTLV_FORMAT_BER
        case GO_FORMAT_BER: *format = tlv_format_ber; return TLV_OK;
        case GO_FORMAT_BER_INDEFINITE: *format = tlv_format_ber_indefinite; return TLV_OK;
#endif
#if OPENTLV_FORMAT_DER
        case GO_FORMAT_DER: *format = tlv_format_der; return TLV_OK;
#endif
#if OPENTLV_FORMAT_CER
        case GO_FORMAT_CER: *format = tlv_format_cer; return TLV_OK;
#endif
#if OPENTLV_EMV
        case GO_FORMAT_EMV: *format = tlv_format_emv; return TLV_OK;
#endif
#if OPENTLV_LLDP
        case GO_FORMAT_LLDP: *format = tlv_format_lldp; return TLV_OK;
#endif
#if OPENTLV_BLUETOOTH
        case GO_FORMAT_BLUETOOTH_LTV: *format = tlv_format_bluetooth_ltv; return TLV_OK;
#endif
#if OPENTLV_DHCP
        case GO_FORMAT_DHCPV4: *format = tlv_format_dhcpv4; return TLV_OK;
#endif
#if OPENTLV_NFC
        case GO_FORMAT_NFC_TYPE2: *format = tlv_format_nfc_type2; return TLV_OK;
#endif
        default: return TLV_ERR_UNSUPPORTED_TYPE;
    }
}

/* Persistent descriptors and their context are entirely C-owned. */
struct go_document {
    tlv_format_t       format;
    tlv_fixed_format_t fixed;
#if OPENTLV_DOCUMENT
    tlv_document_t* document;
#endif
};

go_document* go_document_parse(go_format config, const uint8_t* data, size_t size, size_t depth,
                               size_t elements, int defaults, int* code,
                               tlv_reader_diagnostic_t* diagnostic) {
    tlv_reader_diagnostic_init(diagnostic);
#if OPENTLV_DOCUMENT
    go_document*           d = calloc(1, sizeof(*d));
    tlv_document_options_t options;
    if (!d) {
        *code = TLV_ERR_OUT_OF_MEMORY;
        return NULL;
    }
    *code = resolve(config, &d->format, &d->fixed);
    if (*code == TLV_OK) *code = tlv_document_options_init(&options, &d->format);
    if (*code == TLV_OK) {
        if (!defaults) {
            options.max_depth = depth;
            options.max_elements = elements;
        }
        tlv_tree_reader_t       reader;
        tlv_document_builder_t* builder = NULL;
        size_t                  capacity = options.max_depth < size ? options.max_depth : size;
        tlv_tree_frame_t*       frames = NULL;
        size_t                  error_offset = SIZE_MAX;
        if (capacity > SIZE_MAX / sizeof(*frames)) {
            *code = TLV_ERR_OVERFLOW;
        } else {
            if (capacity) frames = calloc(capacity, sizeof(*frames));
            *code = capacity && !frames
                        ? TLV_ERR_OUT_OF_MEMORY
                        : tlv_tree_reader_init(&reader, data, size, &d->format, frames, capacity,
                                               options.max_depth, options.max_elements);
            if (*code == TLV_OK)
                *code = tlv_document_builder_create(&options, &reader, NULL, &builder);
            if (*code == TLV_OK)
                *code =
                    tlv_document_builder_consume(builder, &d->document, &error_offset, diagnostic);
            if (*code != TLV_OK && !diagnostic->diagnostic.has_offset && error_offset != SIZE_MAX)
                tlv_diagnostic_set_offset(&diagnostic->diagnostic, error_offset);
            tlv_document_builder_free(builder);
            free(frames);
        }
    }
    if (*code != TLV_OK) {
        free(d);
        return NULL;
    }
    return d;
#else
    (void)config;
    (void)data;
    (void)size;
    (void)depth;
    (void)elements;
    (void)defaults;
    *code = TLV_ERR_UNSUPPORTED_TYPE;
    return NULL;
#endif
}

void go_document_free(go_document* d) {
#if OPENTLV_DOCUMENT
    if (d) tlv_document_free(d->document);
#endif
    free(d);
}

size_t go_document_count(go_document* d) {
#if OPENTLV_DOCUMENT
    return tlv_document_count(d->document);
#else
    (void)d;
    return 0;
#endif
}

void* go_document_node(go_document* d, void* n, int operation) {
#if OPENTLV_DOCUMENT
    switch (operation) {
        case 0: return tlv_document_first(d->document);
        case 1: return tlv_node_first_child(n);
        case 2: return tlv_node_next(n);
        case 3: return tlv_node_parent(n);
    }
#else
    (void)d;
    (void)n;
    (void)operation;
#endif
    return NULL;
}

go_read_result go_document_read(void* n) {
    go_read_result r = {0};
#if OPENTLV_DOCUMENT
    r.element.tag = tlv_node_tag(n);
    r.element.value.data = tlv_node_value_data(n);
    r.element.value.size = tlv_node_value_size(n);
    r.consumed = tlv_node_is_constructed(n);
#else
    (void)n;
#endif
    return r;
}

int go_document_edit(go_document* d, void* n, void* before, const uint8_t* tag, size_t tag_size,
                     const uint8_t* value, size_t value_size, int operation, void** result) {
#if OPENTLV_DOCUMENT
    tlv_node_t*  inserted = NULL;
    tlv_result_t code;
    if (operation == 0) return tlv_node_set_value(n, value, value_size);
    if (operation == 1) {
        tlv_node_erase(n);
        return TLV_OK;
    }
    code = tlv_document_insert(d->document, n, before, tlv_tag(tag, tag_size), value, value_size,
                               &inserted);
    *result = inserted;
    return code;
#else
    (void)d;
    (void)n;
    (void)before;
    (void)tag;
    (void)tag_size;
    (void)value;
    (void)value_size;
    (void)operation;
    (void)result;
    return TLV_ERR_UNSUPPORTED_TYPE;
#endif
}

go_write_result go_document_encode(go_document* d, go_format config, uint8_t* data, size_t capacity,
                                   int measure) {
    go_write_result r = {0};
#if OPENTLV_DOCUMENT
    tlv_format_t       format;
    tlv_fixed_format_t fixed;
    r.code = resolve(config, &format, &fixed);
    if (r.code == TLV_OK)
        r.code = measure ? tlv_document_encoded_size_as(d->document, &format, &r.size)
                         : tlv_document_encode_as(d->document, &format, data, capacity, &r.size);
#else
    (void)d;
    (void)config;
    (void)data;
    (void)capacity;
    (void)measure;
    r.code = TLV_ERR_UNSUPPORTED_TYPE;
#endif
    return r;
}

tlv_result_t go_format_check(go_format config) {
    tlv_format_t       format;
    tlv_fixed_format_t fixed;
    return resolve(config, &format, &fixed);
}

/* Reconstruct a single staged parent for this call; all pointers are call-local. */
go_write_result go_tree(go_format config, uint8_t* data, size_t capacity, const uint8_t* tag,
                        size_t tag_size, const uint8_t* value, size_t value_size, uint8_t* scratch,
                        int close) {
    go_write_result         result = {0};
    tlv_format_t            format;
    tlv_fixed_format_t      fixed;
    tlv_tree_writer_t       writer;
    tlv_tree_writer_frame_t frame;
    tlv_writer_diagnostic_init(&result.diagnostic);
    result.code = resolve(config, &format, &fixed);
    if (result.code != TLV_OK) return result;
    result.code = tlv_tree_writer_init(&writer, data, capacity, &format, &frame, 1, scratch,
                                       value_size, SIZE_MAX, SIZE_MAX);
    if (result.code != TLV_OK) return result;
    result.code = tlv_tree_writer_begin_diag(&writer, tlv_tag(tag, tag_size), &result.diagnostic);
    if (result.code != TLV_OK || !close) return result;
    result.code = tlv_writer_copy_encoded(&writer.output, value, value_size);
    if (result.code != TLV_OK) return result;
    result.code = tlv_tree_writer_end_diag(&writer, &result.diagnostic);
    if (result.code == TLV_OK) result.size = tlv_tree_writer_size(&writer);
    return result;
}

go_read_result go_read(go_format config, const uint8_t* data, size_t size, int final_input) {
    go_read_result     result = {0};
    tlv_format_t       format;
    tlv_fixed_format_t fixed;
    tlv_reader_t       reader;
    tlv_reader_diagnostic_init(&result.diagnostic);
    result.code = resolve(config, &format, &fixed);
    if (result.code != TLV_OK) return result;
    result.code = final_input ? tlv_reader_init(&reader, data, size, &format)
                              : tlv_reader_init_incremental(&reader, data, size, &format);
    if (result.code != TLV_OK) return result;
    result.code =
        tlv_reader_next_source_diag(&reader, &result.element, &result.source, &result.diagnostic);
    if (result.code == TLV_OK) result.consumed = tlv_reader_consumed(&reader);
    /* The Go projection keeps ranges, never the temporary descriptor address. */
    result.source.format = NULL;
    return result;
}

go_write_result go_write(go_format config, uint8_t* data, size_t capacity, const uint8_t* tag,
                         size_t tag_size, const uint8_t* value, size_t value_size, int measure) {
    go_write_result    result = {0};
    tlv_format_t       format;
    tlv_fixed_format_t fixed;
    tlv_element_t      element;
    tlv_writer_diagnostic_init(&result.diagnostic);
    result.code = resolve(config, &format, &fixed);
    if (result.code != TLV_OK) return result;
    element.tag = tlv_tag(tag, tag_size);
    element.value.data = value;
    element.value.size = value_size;
    result.code =
        measure ? tlv_element_encoded_size_diag(&element, &format, &result.size, &result.diagnostic)
                : tlv_write_element_diag(data, capacity, &format, &element, &result.size,
                                         &result.diagnostic);
    return result;
}
