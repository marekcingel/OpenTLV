// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#ifndef OPENTLV_GO_BRIDGE_H
#define OPENTLV_GO_BRIDGE_H
#include <tlv/config.h>
#include <tlv/formats/fixed.h>
#include <tlv/reader/reader.h>
#include <tlv/writer/writer.h>
#include <tlv/writer/tree.h>

typedef struct go_document go_document;

enum go_format_kind {
    GO_FORMAT_FIXED,
    GO_FORMAT_BER,
    GO_FORMAT_BER_INDEFINITE,
    GO_FORMAT_DER,
    GO_FORMAT_CER,
    GO_FORMAT_EMV,
    GO_FORMAT_LLDP,
    GO_FORMAT_BLUETOOTH_LTV,
    GO_FORMAT_DHCPV4,
    GO_FORMAT_NFC_TYPE2
};

typedef struct {
    int    kind;
    size_t tag_size, length_size;
    int    byte_order, element_order, length_scope;
} go_format;
typedef struct {
    tlv_result_t            code;
    size_t                  consumed;
    tlv_element_t           element;
    tlv_source_t            source;
    tlv_reader_diagnostic_t diagnostic;
} go_read_result;
typedef struct {
    tlv_result_t            code;
    size_t                  size;
    tlv_writer_diagnostic_t diagnostic;
} go_write_result;

tlv_result_t    go_format_check(go_format config);
go_write_result go_tree(go_format config, uint8_t* data, size_t capacity, const uint8_t* tag,
                        size_t tag_size, const uint8_t* value, size_t value_size, uint8_t* scratch,
                        int close);
go_read_result  go_read(go_format config, const uint8_t* data, size_t size, int final_input);
go_write_result go_write(go_format config, uint8_t* data, size_t capacity, const uint8_t* tag,
                         size_t tag_size, const uint8_t* value, size_t value_size, int measure);
go_document*    go_document_parse(go_format config, const uint8_t* data, size_t size, size_t depth,
                                  size_t elements, int defaults, int* code,
                                  tlv_reader_diagnostic_t* diagnostic);
void            go_document_free(go_document* document);
void*           go_document_node(go_document* document, void* node, int operation);
go_read_result  go_document_read(void* node);
int go_document_edit(go_document* document, void* node, void* before, const uint8_t* tag,
                     size_t tag_size, const uint8_t* value, size_t value_size, int operation,
                     void** result);
go_write_result go_document_encode(go_document* document, go_format config, uint8_t* data,
                                   size_t capacity, int measure);
size_t          go_document_count(go_document* document);
#endif
