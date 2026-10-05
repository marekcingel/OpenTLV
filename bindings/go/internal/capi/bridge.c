// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#include "bridge.h"
#include <stdlib.h>
#include <string.h>
#if OPENTLV_FORMAT_BER
#include <tlv/builtins/asn1/query.h>
#endif
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

#if OPENTLV_DOCUMENT
typedef struct {
    void** nodes;
    size_t count;
} go_query_results;
static tlv_visit_result_t collect_query(tlv_node_t* node, void* context) {
    go_query_results* results = context;
    results->nodes[results->count++] = node;
    return TLV_VISIT_CONTINUE;
}
#endif

int go_document_query(go_document* d, const char* text, void*** nodes, size_t* count,
                      size_t* error_offset) {
#if OPENTLV_DOCUMENT
    tlv_query_t      query;
    tlv_result_t     code = tlv_query_parse(text, &query, error_offset);
    go_query_results results = {NULL, 0};
    size_t           capacity;
    if (code != TLV_OK) return code;
    capacity = tlv_document_count(d->document);
    if (capacity > SIZE_MAX / sizeof(void*)) return TLV_ERR_OVERFLOW;
    if (capacity) {
        results.nodes = malloc(capacity * sizeof(void*));
        if (!results.nodes) return TLV_ERR_OUT_OF_MEMORY;
    }
    code = tlv_document_query_visit(d->document, &query, collect_query, &results);
    if (code != TLV_OK) {
        free(results.nodes);
        return code;
    }
    *nodes = results.nodes;
    *count = results.count;
    return TLV_OK;
#else
    (void)d;
    (void)text;
    (void)nodes;
    (void)count;
    (void)error_offset;
    return TLV_ERR_UNSUPPORTED_TYPE;
#endif
}
void go_query_free(void** nodes) {
    free(nodes);
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

/* Owning language adapter. Core Query calls still receive explicit storage. */
struct go_query_program {
    size_t                     references;
    tlv_format_t               format;
    tlv_fixed_format_t         fixed;
    tlv_query_environment_t    environment;
    tlv_query_hook_t           hooks[4];
    void*                      image;
    const tlv_query_program_t* program;
    tlv_query_program_info_t   info;
};
typedef struct query_buffer {
    struct query_buffer* next;
    uint8_t              data[1];
} query_buffer;
struct go_query_execution {
    go_query_program* program;
    void*             storage;
    void*             storage_allocation;
    size_t            capacity, depth, nodes, work;
    int               retained, has_reader, has_document;
    tlv_query_exec_t* exec;
    tlv_tree_reader_t reader;
    tlv_tree_frame_t* frames;
    query_buffer*     buffers;
    void*             values;
};
typedef struct query_names {
    const go_query_name* names;
    size_t               count;
} query_names;
static tlv_result_t query_resolve(const void* context, const char* space, size_t space_size,
                                  const char* name, size_t name_size, tlv_tag_t* tag) {
    const query_names* names = context;
    for (size_t i = 0; i < names->count; ++i) {
        const go_query_name* entry = &names->names[i];
        size_t               size = strlen(entry->name);
        if (!space_size && size == name_size && !memcmp(entry->name, name, size)) {
            *tag = tlv_tag(entry->tag, entry->size);
            return TLV_OK;
        }
        if (space_size && size > space_size && size - space_size - 1 == name_size &&
            entry->name[space_size] == ':' && !memcmp(entry->name, space, space_size) &&
            !memcmp(entry->name + space_size + 1, name, name_size)) {
            *tag = tlv_tag(entry->tag, entry->size);
            return TLV_OK;
        }
    }
    return TLV_ERR_INVALID_TAG;
}
go_query_program* go_query_compile(go_format format, const uint8_t* text, size_t size,
                                   const tlv_query_compile_options_t* options,
                                   const go_query_name* names, size_t name_count, int image,
                                   tlv_result_t* code, tlv_query_diagnostic_t* diagnostic) {
    memset(diagnostic, 0, sizeof *diagnostic);
    if (!text && !size) text = (const uint8_t*)"";
    go_query_program* p = calloc(1, sizeof *p);
    if (!p) {
        *code = TLV_ERR_OUT_OF_MEMORY;
        return NULL;
    }
    p->references = 1;
    *code = resolve(format, &p->format, &p->fixed);
    p->environment.format = &p->format;
    size_t                  count;
    const tlv_query_hook_t* hooks = tlv_query_builtin_hooks(&count);
    memcpy(p->hooks, hooks, count * sizeof *hooks);
#if OPENTLV_FORMAT_BER
    if (format.kind == GO_FORMAT_BER || format.kind == GO_FORMAT_BER_INDEFINITE ||
        format.kind == GO_FORMAT_DER || format.kind == GO_FORMAT_CER) {
        p->environment.tags = &tlv_asn1_query_tags;
        p->hooks[count++] = tlv_asn1_query_date;
    }
#endif
    p->environment.hooks = p->hooks;
    p->environment.hook_count = count;
    tlv_query_compile_options_t config;
    tlv_query_compile_options_init(&config);
    if (options) config = *options;
    query_names lookup = {names, name_count};
    config.environment = &p->environment;
    config.resolve = query_resolve;
    config.resolve_context = &lookup;
    size_t bytes = 0, alignment = 0;
    p->info.struct_size = sizeof p->info;
    if (*code == TLV_OK)
        *code = image ? tlv_query_program_load_scratch(text, size, &config, &bytes, &alignment,
                                                       diagnostic)
                      : tlv_query_compile_scratch((const char*)text, size, &config, &bytes,
                                                  &alignment, diagnostic);
    void* scratch = *code == TLV_OK ? malloc(bytes ? bytes : 1) : NULL;
    if (*code == TLV_OK && !scratch) *code = TLV_ERR_OUT_OF_MEMORY;
    if (*code == TLV_OK && !image)
        *code = tlv_query_compile((const char*)text, size, &config, scratch, bytes, NULL, 0,
                                  &p->info, diagnostic);
    if (*code == TLV_OK) {
        p->image = malloc(image ? (size ? size : 1) : p->info.program_size);
        if (!p->image) *code = TLV_ERR_OUT_OF_MEMORY;
    }
    if (*code == TLV_OK && image) {
        memcpy(p->image, text, size);
        *code = tlv_query_program_load(p->image, size, &config, scratch, bytes, &p->program,
                                       &p->info, diagnostic);
    } else if (*code == TLV_OK) {
        *code = tlv_query_compile((const char*)text, size, &config, scratch, bytes, p->image,
                                  p->info.program_size, &p->info, diagnostic);
        p->program = p->image;
    }
    free(scratch);
    if (*code != TLV_OK) {
        go_query_program_free(p);
        return NULL;
    }
    return p;
}
void go_query_program_free(go_query_program* p) {
    if (p && --p->references == 0) {
        free(p->image);
        free(p);
    }
}
const tlv_query_program_t* go_query_native(const go_query_program* p) {
    return p->program;
}
const tlv_query_program_info_t* go_query_info(const go_query_program* p) {
    return &p->info;
}
tlv_query_exec_t* go_query_exec(go_query_execution* q) {
    return q->exec;
}
static void query_buffers_free(go_query_execution* q) {
    while (q->buffers) {
        query_buffer* next = q->buffers->next;
        free(q->buffers);
        q->buffers = next;
    }
}
static query_buffer* query_buffer_new(const uint8_t* data, size_t size) {
    if (size > SIZE_MAX - sizeof(query_buffer)) return NULL;
    query_buffer* buffer = malloc(sizeof(query_buffer) + size);
    if (!buffer) return NULL;
    if (size) memcpy(buffer->data, data, size);
    buffer->next = NULL;
    return buffer;
}
tlv_result_t go_query_execution_reset(go_query_execution* q) {
    tlv_result_t rc =
        q->retained ? tlv_query_eval_init(q->program->program, &q->program->environment, q->storage,
                                          q->capacity, q->depth, q->nodes, q->work, &q->exec)
                    : tlv_query_exec_init(q->program->program, q->storage, q->capacity, q->depth,
                                          q->nodes, q->work, &q->exec);
    if (rc == TLV_OK) {
        query_buffers_free(q);
        free(q->values);
        q->values = NULL;
        q->has_reader = q->has_document = 0;
    }
    return rc;
}
go_query_execution* go_query_execution_create(go_query_program* p, size_t depth, size_t nodes,
                                              size_t work, int retained, tlv_result_t* code) {
    size_t bytes, alignment;
    *code = retained ? tlv_query_eval_size(p->program, depth, nodes, &bytes, &alignment)
                     : tlv_query_exec_size(p->program, depth, &bytes, &alignment);
    if (*code != TLV_OK) return NULL;
    if (depth > SIZE_MAX / sizeof(tlv_tree_frame_t)) {
        *code = TLV_ERR_OVERFLOW;
        return NULL;
    }
    go_query_execution* q = calloc(1, sizeof *q);
    if (!q) {
        *code = TLV_ERR_OUT_OF_MEMORY;
        return NULL;
    }
    q->program = p;
    ++p->references;
    q->capacity = bytes;
    q->depth = depth;
    q->nodes = nodes;
    q->work = work;
    q->retained = retained;
    if (bytes > SIZE_MAX - (alignment - 1)) {
        *code = TLV_ERR_OVERFLOW;
        go_query_execution_free(q);
        return NULL;
    }
    q->storage_allocation = malloc(bytes + alignment - 1);
    if (q->storage_allocation)
        q->storage = (void*)(((uintptr_t)q->storage_allocation + alignment - 1) &
                             ~(uintptr_t)(alignment - 1));
    q->frames = calloc(depth ? depth : 1, sizeof *q->frames);
    if (!q->storage || !q->frames)
        *code = TLV_ERR_OUT_OF_MEMORY;
    else
        *code = go_query_execution_reset(q);
    if (*code != TLV_OK) {
        go_query_execution_free(q);
        return NULL;
    }
    return q;
}
void go_query_execution_free(go_query_execution* q) {
    if (!q) return;
    query_buffers_free(q);
    free(q->storage_allocation);
    free(q->frames);
    free(q->values);
    go_query_program_free(q->program);
    free(q);
}
tlv_result_t go_query_input(go_query_execution* q, const uint8_t* data, size_t size, size_t discard,
                            int final_input) {
    if (q->has_document || (!q->has_reader && discard)) return TLV_ERR_INVALID_ARG;
    query_buffer* buffer = query_buffer_new(data, size);
    if (!buffer) return TLV_ERR_OUT_OF_MEMORY;
    tlv_result_t rc;
    if (q->has_reader)
        rc = tlv_tree_reader_set_input(&q->reader, buffer->data, size, discard, final_input);
    else {
        rc = final_input ? tlv_tree_reader_init(&q->reader, buffer->data, size, &q->program->format,
                                                q->frames, q->depth, q->depth, q->nodes)
                         : tlv_tree_reader_init_incremental(&q->reader, buffer->data, size,
                                                            &q->program->format, q->frames,
                                                            q->depth, q->depth, q->nodes);
    }
    if (rc != TLV_OK) {
        free(buffer);
        return rc;
    }
    buffer->next = q->buffers;
    q->buffers = buffer;
    q->has_reader = 1;
    return TLV_OK;
}
tlv_result_t go_query_visit(go_query_execution* q, tlv_query_event_visitor_t visitor, void* context,
                            tlv_query_diagnostic_t* diagnostic) {
    if (!q->has_reader || q->has_document) return TLV_ERR_INVALID_ARG;
    return tlv_query_program_visit(&q->reader, q->exec, visitor, context, diagnostic);
}
tlv_result_t go_query_exists(go_query_execution* q, int early_return, int* found,
                             tlv_query_diagnostic_t* diagnostic) {
    if (!q->has_reader || q->has_document) return TLV_ERR_INVALID_ARG;
    return tlv_query_program_exists(&q->reader, q->exec, early_return, found, diagnostic);
}
tlv_result_t go_query_bind(go_query_execution* q, const char* name, tlv_query_result_kind_t type,
                           int64_t integer, const uint8_t* data, size_t size,
                           tlv_query_diagnostic_t* diagnostic) {
    query_buffer* buffer = query_buffer_new(data, size);
    if (!buffer) return TLV_ERR_OUT_OF_MEMORY;
    tlv_result_t rc =
        tlv_query_exec_bind(q->exec, name, type, integer, buffer->data, size, diagnostic);
    if (rc != TLV_OK) {
        free(buffer);
        return rc;
    }
    buffer->next = q->buffers;
    q->buffers = buffer;
    return TLV_OK;
}
tlv_result_t go_query_document(go_query_execution* q, const go_document* document, void* context,
                               size_t capacity, tlv_query_diagnostic_t* diagnostic) {
#if OPENTLV_DOCUMENT
    if (!q->retained || q->has_reader || q->has_document) return TLV_ERR_INVALID_ARG;
    if (q->depth > SIZE_MAX / sizeof(tlv_tree_writer_frame_t)) return TLV_ERR_OVERFLOW;
    tlv_tree_writer_workspace_t staging = {0};
    if (q->program->info.constructed_values_required) {
        staging.frames = calloc(q->depth ? q->depth : 1, sizeof *staging.frames);
        staging.frame_capacity = q->depth;
        staging.data = malloc(capacity ? capacity : 1);
        staging.data_capacity = capacity;
        staging.scratch = malloc(capacity ? capacity : 1);
        staging.scratch_capacity = capacity;
        q->values = malloc(capacity ? capacity : 1);
        if (!staging.frames || !staging.data || !staging.scratch || !q->values) {
            free(staging.frames);
            free(staging.data);
            free(staging.scratch);
            free(q->values);
            q->values = NULL;
            return TLV_ERR_OUT_OF_MEMORY;
        }
    }
    q->has_document = 1;
    tlv_result_t rc = tlv_document_query_evaluate(
        document->document, q->exec, context, q->values,
        q->program->info.constructed_values_required ? capacity : 0,
        q->program->info.constructed_values_required ? &staging : NULL, diagnostic);
    free(staging.frames);
    free(staging.data);
    free(staging.scratch);
    return rc;
#else
    (void)q;
    (void)document;
    (void)context;
    (void)capacity;
    (void)diagnostic;
    return TLV_ERR_UNSUPPORTED_TYPE;
#endif
}
tlv_result_t go_query_document_next(go_query_execution* q, void** node) {
#if OPENTLV_DOCUMENT
    tlv_node_t*  result;
    tlv_result_t rc = tlv_document_query_next(q->exec, &result);
    if (rc == TLV_OK) *node = result;
    return rc;
#else
    (void)q;
    (void)node;
    return TLV_ERR_UNSUPPORTED_TYPE;
#endif
}
uint64_t go_query_node_identity(void* node) {
#if OPENTLV_DOCUMENT
    return tlv_node_identity(node);
#else
    (void)node;
    return 0;
#endif
}
