// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#ifndef OPENTLV_GO_BRIDGE_H
#define OPENTLV_GO_BRIDGE_H
#include <tlv/config.h>
#include <tlv/formats/fixed.h>
#include <tlv/reader/reader.h>
#include <tlv/writer/writer.h>
#include <tlv/writer/tree.h>
#include <tlv/query/adapters.h>

typedef struct go_document        go_document;
typedef struct go_query_program   go_query_program;
typedef struct go_query_execution go_query_execution;
typedef struct {
    const char*    name;
    const uint8_t* tag;
    size_t         size;
} go_query_name;

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
go_query_program* go_query_compile(go_format config, const uint8_t* text, size_t size,
                                   const tlv_query_compile_options_t* options,
                                   const go_query_name* names, size_t name_count, int image,
                                   tlv_result_t* code, tlv_query_diagnostic_t* diagnostic);
void              go_query_program_free(go_query_program* program);
const tlv_query_program_t*      go_query_native(const go_query_program* program);
const tlv_query_program_info_t* go_query_info(const go_query_program* program);
go_query_execution* go_query_execution_create(go_query_program* program, size_t depth, size_t nodes,
                                              size_t work, int retained, tlv_result_t* code);
void                go_query_execution_free(go_query_execution* execution);
tlv_query_exec_t*   go_query_exec(go_query_execution* execution);
tlv_result_t        go_query_execution_reset(go_query_execution* execution);
tlv_result_t        go_query_input(go_query_execution* execution, const uint8_t* data, size_t size,
                                   size_t discard, int final_input);
tlv_result_t        go_query_visit(go_query_execution* execution, tlv_query_event_visitor_t visitor,
                                   void* context, tlv_query_diagnostic_t* diagnostic);
tlv_result_t        go_query_exists(go_query_execution* execution, int early_return, int* found,
                                    tlv_query_diagnostic_t* diagnostic);
tlv_result_t go_query_bind(go_query_execution* execution, const char* name,
                           tlv_query_result_kind_t type, int64_t integer, const uint8_t* data,
                           size_t size, tlv_query_diagnostic_t* diagnostic);
tlv_result_t go_query_document(go_query_execution* execution, const go_document* document,
                               void* context, size_t capacity, tlv_query_diagnostic_t* diagnostic);
tlv_result_t go_query_document_next(go_query_execution* execution, void** node);
uint64_t     go_query_node_identity(void* node);
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
int  go_document_query(go_document* document, const char* text, void*** nodes, size_t* count,
                       size_t* error_offset);
void go_query_free(void** nodes);
#endif
