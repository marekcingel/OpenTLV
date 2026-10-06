// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "opentlv_wasm.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../common/query_schema.h"

#include "tlv/tlv.h"
#include "tlv/query/adapters.h"
#include "tlv/document/document.h"
#include "tlv/writer/tree.h"
#if OPENTLV_FORMAT_BER
#include "tlv/builtins/asn1/query.h"
#endif

/* Bounded browser output storage; independent of core traversal limits. */
enum { WASM_TREE_CAPACITY = 64 };
#if OPENTLV_NFC
#include "tlv/builtins/nfc/type2.h"
#endif
#if OPENTLV_LLDP
#include "tlv/builtins/lldp/lldp.h"
#endif
#if OPENTLV_BLUETOOTH
#include "tlv/builtins/bluetooth/bluetooth_ltv.h"
#include "tlv/builtins/bluetooth/ad_data.h"
#include "tlv/builtins/bluetooth/ad_types.h"
#endif
#include "tlv/version.h"
#if OPENTLV_FORMAT_CER
#include "tlv/builtins/asn1/cer.h"
#endif

enum {
    /* Bounds the work one browser call can request. */
    WASM_MAX_ELEMENTS = 65536
};

struct opentlv_wasm_result {
    tlv_result_t code;
    size_t       error_offset;
    char*        json;
    size_t       json_size;
};

typedef struct {
    char*  data;
    size_t size;
    size_t capacity;
    int    failed;
} builder_t;

typedef struct {
    builder_t out;
    /* Elements are visited in preorder; `open` counts the elements whose JSON
     * object is still unclosed, `has_children` records which of them opened a
     * "children" array and `count` how many siblings each level already has. */
    size_t open;
    size_t count[WASM_TREE_CAPACITY + 2];
    int    has_children[WASM_TREE_CAPACITY + 2];
    int    ber;
    int    bluetooth;
    /* Start of the parsed input; offsets of values are measured against it. */
    const uint8_t*      input;
    size_t              input_size;
    const tlv_format_t* reader;
#if OPENTLV_EMV
    /* Set when the EMV dictionary annotates elements; `emv_context[d]` is the
     * dictionary context of the elements at depth d. */
    int               emv;
    tlv_emv_context_t emv_context[WASM_TREE_CAPACITY + 2];
#endif
} writer_context_t;

static void builder_reserve(builder_t* b, size_t extra) {
    size_t needed;
    char*  grown;
    if (b->failed) return;
    if (extra > (size_t)-1 - b->size - 1) {
        b->failed = 1;
        return;
    }
    needed = b->size + extra + 1;
    if (needed <= b->capacity) return;
    needed = needed < 256 ? 256 : needed;
    if (needed < b->capacity * 2) needed = b->capacity * 2;
    grown = (char*)realloc(b->data, needed);
    if (!grown) {
        b->failed = 1;
        return;
    }
    b->data = grown;
    b->capacity = needed;
}

static void builder_append(builder_t* b, const char* text, size_t length) {
    builder_reserve(b, length);
    if (b->failed) return;
    memcpy(b->data + b->size, text, length);
    b->size += length;
    b->data[b->size] = '\0';
}

static void builder_text(builder_t* b, const char* text) {
    builder_append(b, text, strlen(text));
}

static void builder_number(builder_t* b, size_t value) {
    char text[32];
    (void)sprintf(text, "%lu", (unsigned long)value);
    builder_text(b, text);
}

static void builder_hex(builder_t* b, const uint8_t* bytes, size_t length) {
    static const char digits[] = "0123456789ABCDEF";
    size_t            i;
    builder_reserve(b, length * 2);
    if (b->failed) return;
    for (i = 0; i < length; ++i) {
        b->data[b->size++] = digits[bytes[i] >> 4];
        b->data[b->size++] = digits[bytes[i] & 0x0F];
    }
    b->data[b->size] = '\0';
}

static void builder_json_string(builder_t* b, const char* text) {
    builder_text(b, "\"");
    for (; *text; ++text) {
        if ((unsigned char)*text < 0x20) {
            /* The caller controls the format name; keep the document valid JSON. */
            char escape[8];
            (void)sprintf(escape, "\\u%04X", (unsigned)(unsigned char)*text);
            builder_text(b, escape);
            continue;
        }
        if (*text == '"' || *text == '\\') builder_append(b, "\\", 1);
        builder_append(b, text, 1);
    }
    builder_text(b, "\"");
}

static void close_elements(writer_context_t* w, size_t depth) {
    while (w->open > depth) {
        --w->open;
        builder_text(&w->out, w->has_children[w->open] ? "]}" : "}");
    }
}

#if OPENTLV_EMV
/* Appends the EMV dictionary entry of the element, if it has one, and derives
 * the dictionary context its children are read in. */
static void emit_emv(writer_context_t* w, const tlv_element_t* element, size_t depth,
                     size_t length) {
    tlv_emv_context_t           context = w->emv_context[depth];
    tlv_emv_context_t           child = tlv_emv_child_context(context, &element->tag);
    const tlv_emv_definition_t* definition = tlv_emv_find(context, &element->tag);

    w->emv_context[depth + 1] = child == TLV_EMV_CONTEXT_COUNT ? context : child;
    if (!definition) return;
    {
        const char* label = definition->definition->name;
        builder_text(&w->out, ",\"symbol\":");
        builder_json_string(&w->out, tlv_emv_symbol(definition));
        if (label) {
            builder_text(&w->out, ",\"name\":");
            builder_json_string(&w->out, label);
        }
        builder_text(&w->out, tlv_emv_validate_length(definition, length) == TLV_OK
                                  ? ",\"lengthValid\":true"
                                  : ",\"lengthValid\":false");
    }
}
#endif

static void emit_range(builder_t* out, const char* name, tlv_range_t range, size_t offset) {
    builder_text(out, name);
    builder_text(out, "{\"offset\":");
    builder_number(out, offset + range.offset);
    builder_text(out, ",\"length\":");
    builder_number(out, range.size);
    builder_text(out, "}");
}

static tlv_visit_result_t emit_element(const tlv_element_t* element, size_t depth, size_t offset,
                                       void* context) {
    writer_context_t* w = (writer_context_t*)context;
    int               constructed = 0;
    size_t            length, header_size;
    tlv_decoded_t     decoded;

    if (tlv_size_to_native(element->value.size, &length) != TLV_OK) return TLV_VISIT_ERROR;
    if (depth > WASM_TREE_CAPACITY) return TLV_VISIT_ERROR;
    /* Obtain authoritative source ranges, including trailers such as BER EOC. */
    if (offset > w->input_size ||
        tlv_format_decode(w->reader, w->input + offset, w->input_size - offset, &decoded, NULL) !=
            TLV_OK)
        return TLV_VISIT_ERROR;
    header_size = decoded.source.header.size;
    if (w->reader->is_constructed)
        constructed = w->reader->is_constructed(w->reader->context, &element->tag) != 0;
    close_elements(w, depth);
    if (w->count[depth]++) builder_text(&w->out, ",");
    w->count[depth + 1] = 0;

    builder_text(&w->out, "{\"offset\":");
    builder_number(&w->out, offset);
    builder_text(&w->out, ",\"depth\":");
    builder_number(&w->out, depth);
    builder_text(&w->out, ",\"tag\":\"");
    builder_hex(&w->out, element->tag.data, element->tag.size);
    builder_text(&w->out, "\",\"length\":");
    builder_number(&w->out, length);
    builder_text(&w->out, ",\"headerSize\":");
    builder_number(&w->out, header_size);
    builder_text(&w->out, ",\"encodedSize\":");
    builder_number(&w->out, decoded.source.size);
    builder_text(&w->out, ",\"source\":{");
    emit_range(&w->out, "\"header\":", decoded.source.header, offset);
    emit_range(&w->out, ",\"tag\":", decoded.source.tag, offset);
    emit_range(&w->out, ",\"length\":", decoded.source.length, offset);
    emit_range(&w->out, ",\"value\":", decoded.source.value, offset);
    emit_range(&w->out, ",\"trailer\":", decoded.source.trailer, offset);
    builder_text(&w->out, "}");
    builder_text(&w->out, constructed ? ",\"constructed\":true" : ",\"constructed\":false");
#if OPENTLV_EMV
    if (w->emv) emit_emv(w, element, depth, length);
#endif
#if OPENTLV_BLUETOOTH
    if (w->bluetooth) {
        const tlv_definition_t* definition =
            tlv_definition_find(&tlv_bluetooth_ad_types, &element->tag);
        if (definition) {
            builder_text(&w->out, ",\"name\":");
            builder_json_string(&w->out, definition->name);
        }
    }
#endif
    if (constructed && length) {
        /* The Tree Reader descends into it next; children close it later. */
        builder_text(&w->out, ",\"children\":[");
        w->has_children[w->open] = 1;
    } else {
        builder_text(&w->out, ",\"value\":\"");
        builder_hex(&w->out, element->value.data, length);
        builder_text(&w->out, "\"");
        w->has_children[w->open] = 0;
    }
    ++w->open;
    return w->out.failed ? TLV_VISIT_ERROR : TLV_VISIT_CONTINUE;
}

static const tlv_format_t* select_format(const char* name, int* ber, int* der,
                                         size_t fixed_tag_size, size_t fixed_length_size,
                                         int fixed_big_endian, int fixed_length_first,
                                         int fixed_counts_tag, tlv_fixed_format_t* fixed_config,
                                         tlv_format_t* fixed_format) {
    *ber = 0;
    *der = 0;
    if (!name) return NULL;
    // Configured by the caller's fixed_tag_size/fixed_length_size/fixed_big_endian.
    // fixed_config/fixed_format are storage owned by the caller (opentlv_wasm_parse),
    // which outlives this call, since a `static` here would make the module
    // non-reentrant (see docs/guides/memory.md#format-context-ownership-and-lifetime).
    if (!strcmp(name, "fixed")) {
        fixed_config->tag_size = fixed_tag_size;
        fixed_config->length_size = fixed_length_size;
        fixed_config->length_order =
            fixed_big_endian ? TLV_BYTE_ORDER_BIG_ENDIAN : TLV_BYTE_ORDER_LITTLE_ENDIAN;
        fixed_config->element_order =
            fixed_length_first ? TLV_ELEMENT_ORDER_LTV : TLV_ELEMENT_ORDER_TLV;
        fixed_config->length_scope =
            fixed_counts_tag ? TLV_LENGTH_SCOPE_TAG_AND_VALUE : TLV_LENGTH_SCOPE_VALUE;
        if (tlv_fixed_format_init(fixed_format, fixed_config) != TLV_OK) return NULL;
        return fixed_format;
    }
#if OPENTLV_EMV
    if (!strcmp(name, "emv")) return &tlv_format_emv;
#endif
#if OPENTLV_NFC
    if (!strcmp(name, "nfc-type2")) return &tlv_format_nfc_type2;
#endif
#if OPENTLV_LLDP
    if (!strcmp(name, "lldp")) return &tlv_format_lldp;
#endif
#if OPENTLV_BLUETOOTH
    if (!strcmp(name, "bluetooth-ltv") || !strcmp(name, "bluetooth-ad"))
        return &tlv_format_bluetooth_ltv;
#endif
#if OPENTLV_FORMAT_BER
    if (!strcmp(name, "ber")) {
        *ber = 1;
        return &tlv_format_ber;
    }
#endif
#if OPENTLV_FORMAT_DER
    if (!strcmp(name, "der")) {
        *ber = 1;
        *der = 1;
        return &tlv_format_der;
    }
#endif
#if OPENTLV_FORMAT_CER
    if (!strcmp(name, "cer")) {
        *ber = 1;
        return &tlv_format_cer;
    }
#endif
    return NULL;
}

static void append_error(builder_t* b, tlv_result_t code, size_t offset) {
    builder_text(b, ",\"error\":{\"code\":");
    builder_number(b, (size_t)code);
    builder_text(b, ",\"message\":");
    builder_json_string(b, tlv_strerror(code));
    builder_text(b, ",\"offset\":");
    builder_number(b, offset);
    builder_text(b, "}");
}

opentlv_wasm_result_t* opentlv_wasm_parse(const uint8_t* data, size_t size, const char* format,
                                          const char* module, size_t fixed_tag_size,
                                          size_t fixed_length_size, int fixed_big_endian,
                                          int fixed_length_first, int fixed_counts_tag) {
    opentlv_wasm_result_t* result = (opentlv_wasm_result_t*)calloc(1, sizeof *result);
    const tlv_format_t*    reader;
    writer_context_t*      w;
    int                    ber, der;
    size_t                 error_offset = 0;
    size_t                 padding_offset = size;
    /* Storage for select_format()'s "fixed" case; must outlive its use below. */
    tlv_fixed_format_t fixed_config;
    tlv_format_t       fixed_format;

    if (!result) return NULL;
    w = (writer_context_t*)calloc(1, sizeof *w);
    if (!w) {
        free(result);
        return NULL;
    }
    reader = select_format(format, &ber, &der, fixed_tag_size, fixed_length_size, fixed_big_endian,
                           fixed_length_first, fixed_counts_tag, &fixed_config, &fixed_format);
    w->ber = ber;
    w->input = data;
    w->input_size = size;
    w->reader = reader;
    w->bluetooth = format && (!strcmp(format, "bluetooth-ltv") || !strcmp(format, "bluetooth-ad"));

    builder_text(&w->out, "{\"format\":");
    builder_json_string(&w->out, format ? format : "");

    if (module && *module && strcmp(module, "none")) {
        /* The EMV dictionary names BER-TLV tags; it does not apply to other formats. */
#if OPENTLV_EMV
        if (!strcmp(module, "emv") && format &&
            (!strcmp(format, "ber") || !strcmp(format, "emv")) && reader) {
            w->emv = 1;
            w->emv_context[0] = TLV_EMV_CONTEXT_BASE;
            builder_text(&w->out, ",\"module\":\"emv\"");
        } else
#endif
            reader = NULL;
    }
    builder_text(&w->out, ",\"elements\":[");

    if (!reader) {
        result->code = TLV_ERR_INVALID_ARG;
    } else if (!data && size) {
        result->code = TLV_ERR_NULL_ARG;
    } else {
#if OPENTLV_BLUETOOTH
        if (!strcmp(format, "bluetooth-ad")) {
            tlv_reader_t ad_reader;
            size_t       count = 0;
            result->code = tlv_reader_init(&ad_reader, data, size, reader);
            while (result->code == TLV_OK && !tlv_reader_at_end(&ad_reader)) {
                size_t                  offset = ad_reader.pos;
                tlv_element_t           element;
                tlv_reader_diagnostic_t diagnostic;
                if (data[offset] == 0) {
                    size_t significant_size, relative_error = 0;
                    result->code = tlv_bluetooth_ad_data_validate(
                        data + offset, size - offset, &significant_size, &relative_error);
                    if (result->code == TLV_OK)
                        padding_offset = offset;
                    else
                        error_offset = offset + relative_error;
                    break;
                }
                if (count++ == WASM_MAX_ELEMENTS) {
                    result->code = TLV_ERR_LIMIT;
                    error_offset = offset;
                    break;
                }
                result->code = tlv_reader_next_diag(&ad_reader, &element, &diagnostic);
                if (result->code != TLV_OK) {
                    error_offset =
                        diagnostic.diagnostic.has_offset ? diagnostic.diagnostic.offset : offset;
                    break;
                }
                if (emit_element(&element, 0, offset, w) != TLV_VISIT_CONTINUE) {
                    result->code = TLV_ERR_VISITOR;
                    error_offset = offset;
                }
            }
        } else
#endif
#if OPENTLV_FORMAT_DER
            if (der) {
            result->code = tlv_der_visit(data, size, NULL, emit_element, w, &error_offset);
        } else
#endif
        {
            tlv_tree_reader_t cursor;
            tlv_tree_frame_t  frames[WASM_TREE_CAPACITY];
            result->code =
                tlv_tree_reader_init(&cursor, data, size, reader, frames, WASM_TREE_CAPACITY,
                                     WASM_TREE_CAPACITY, WASM_MAX_ELEMENTS);
            if (result->code == TLV_OK)
                result->code = tlv_tree_reader_visit(&cursor, emit_element, w, &error_offset);
        }
    }
    if (w->out.failed) result->code = TLV_ERR_OUT_OF_MEMORY;
    result->error_offset = error_offset;

    close_elements(w, 0);
    builder_text(&w->out, "]");
    if (padding_offset < size) {
        builder_text(&w->out, ",\"padding\":{\"offset\":");
        builder_number(&w->out, padding_offset);
        builder_text(&w->out, ",\"length\":");
        builder_number(&w->out, size - padding_offset);
        builder_text(&w->out, "}");
    }
    if (result->code != TLV_OK) append_error(&w->out, result->code, error_offset);
    builder_text(&w->out, "}");

    if (w->out.failed) {
        free(w->out.data);
        free(w);
        free(result);
        return NULL;
    }
    result->json = w->out.data;
    result->json_size = w->out.size;
    free(w);
    return result;
}

int opentlv_wasm_result_code(const opentlv_wasm_result_t* result) {
    return result ? (int)result->code : (int)TLV_ERR_NULL_ARG;
}

size_t opentlv_wasm_result_error_offset(const opentlv_wasm_result_t* result) {
    return result ? result->error_offset : 0;
}

const char* opentlv_wasm_result_json(const opentlv_wasm_result_t* result) {
    return result ? result->json : NULL;
}

size_t opentlv_wasm_result_json_size(const opentlv_wasm_result_t* result) {
    return result ? result->json_size : 0;
}

void opentlv_wasm_result_free(opentlv_wasm_result_t* result) {
    if (!result) return;
    free(result->json);
    free(result);
}

uint8_t* opentlv_wasm_alloc(size_t size) {
    return (uint8_t*)malloc(size ? size : 1);
}

void opentlv_wasm_free(void* pointer) {
    free(pointer);
}

const char* opentlv_wasm_version(void) {
    return tlv_version_string();
}

/* Owning boundary storage is deliberately outside the allocation-free core. */
enum { QUERY_DECLARATIONS = 64 };
typedef struct {
    char*    name;
    uint8_t* bytes;
    size_t   size;
} wasm_name_t;
typedef struct wasm_pin {
    struct wasm_pin* next;
    uint8_t          data[1];
} wasm_pin_t;
struct opentlv_wasm_program {
    size_t                      references;
    tlv_query_compile_options_t options;
    tlv_query_variable_t        variables[QUERY_DECLARATIONS];
    wasm_name_t                 names[QUERY_DECLARATIONS];
    size_t                      name_count;
    tlv_query_environment_t     environment;
    tlv_query_hook_t            hooks[4];
    const tlv_query_program_t*  program;
    void*                       image;
    tlv_query_program_info_t    info;
    builder_t                   reply;
};
struct opentlv_wasm_document {
    size_t                  references;
    opentlv_wasm_program_t* program;
    tlv_document_t*         document;
};
struct opentlv_wasm_execution {
    opentlv_wasm_program_t*  program;
    opentlv_wasm_document_t* document;
    tlv_query_exec_t*        exec;
    void*                    allocation;
    void*                    storage;
    void*                    values;
    size_t                   capacity, depth, nodes, work;
    int                      retained, has_reader, fed;
    tlv_tree_reader_t        reader;
    tlv_tree_frame_t*        frames;
    wasm_pin_t*              pins;
    builder_t                reply;
};
static char* query_copy_name(const char* name) {
    if (!name) return NULL;
    size_t n = strlen(name);
    char*  copy = malloc(n + 1);
    if (copy) memcpy(copy, name, n + 1);
    return copy;
}
static tlv_result_t wasm_resolve(const void* context, const char* scope, size_t scope_size,
                                 const char* name, size_t name_size, tlv_tag_t* tag) {
    const opentlv_wasm_program_t* p = context;
    for (size_t i = 0; i < p->name_count; ++i) {
        const wasm_name_t* n = p->names + i;
        size_t             prefix = scope_size ? scope_size + 1 : 0;
        if (strlen(n->name) != prefix + name_size) continue;
        if (scope_size && (memcmp(n->name, scope, scope_size) || n->name[scope_size] != ':'))
            continue;
        if (!memcmp(n->name + prefix, name, name_size)) {
            *tag = tlv_tag(n->bytes, n->size);
            return TLV_OK;
        }
    }
    return TLV_ERR_INVALID_TAG;
}
static void query_integer(builder_t* b, int64_t value) {
    char text[32];
    (void)snprintf(text, sizeof text, "%lld", (long long)value);
    builder_json_string(b, text);
}
static void query_status(builder_t* b, tlv_result_t code, const tlv_query_diagnostic_t* d) {
    b->size = 0;
    b->failed = 0;
    builder_text(b, "{\"code\":");
    builder_number(b, code);
    builder_text(b, ",\"query\":{\"kind\":");
    builder_number(b, d ? d->kind : 0);
    builder_text(b, ",\"begin\":");
    builder_number(b, d ? d->begin : 0);
    builder_text(b, ",\"end\":");
    builder_number(b, d ? d->end : 0);
    if (d) {
        builder_text(b, ",\"configured\":");
        builder_number(b, d->configured);
        builder_text(b, ",\"codec\":");
        builder_number(b, d->codec);
        if (d->limit) {
            builder_text(b, ",\"limit\":");
            builder_json_string(b, d->limit);
        }
        if (d->expected) {
            builder_text(b, ",\"expected\":");
            builder_json_string(b, d->expected);
        }
        if (d->has_source_offset) {
            builder_text(b, ",\"source_offset\":");
            builder_number(b, d->source_offset);
        }
    }
    builder_text(b, "}");
}
static const char* query_reply(builder_t* b) {
    builder_text(b, "}");
    return b->failed ? "{\"code\":4}" : b->data;
}
static void query_field(builder_t* b, const char* name, size_t value) {
    builder_text(b, ",");
    builder_json_string(b, name);
    builder_text(b, ":");
    builder_number(b, value);
}
opentlv_wasm_program_t* opentlv_wasm_program_new(const char* name) {
    if (!name) return NULL;
    const tlv_format_t* format = NULL;
#if OPENTLV_FORMAT_BER
    if (!strcmp(name, "ber")) format = &tlv_format_ber;
#endif
#if OPENTLV_FORMAT_DER
    if (!strcmp(name, "der")) format = &tlv_format_der;
#endif
#if OPENTLV_FORMAT_CER
    if (!strcmp(name, "cer")) format = &tlv_format_cer;
#endif
    if (!format) return NULL;
    opentlv_wasm_program_t* p = calloc(1, sizeof *p);
    if (!p) return NULL;
    p->references = 1;
    tlv_query_compile_options_init(&p->options);
    p->options.variables = p->variables;
    p->options.resolve = wasm_resolve;
    p->options.resolve_context = p;
    p->options.environment = &p->environment;
    p->environment.format = format;
    size_t                  count;
    const tlv_query_hook_t* hooks = tlv_query_builtin_hooks(&count);
    memcpy(p->hooks, hooks, count * sizeof *hooks);
#if OPENTLV_FORMAT_BER
    p->environment.tags = &tlv_asn1_query_tags;
    p->hooks[count++] = tlv_asn1_query_date;
#endif
    p->environment.hooks = p->hooks;
    p->environment.hook_count = count;
    return p;
}
void opentlv_wasm_program_free(opentlv_wasm_program_t* p) {
    if (!p || --p->references) return;
    for (size_t i = 0; i < p->options.variable_count; ++i) free((void*)p->variables[i].name);
    for (size_t i = 0; i < p->name_count; ++i) {
        free(p->names[i].name);
        free(p->names[i].bytes);
    }
    free(p->image);
    free(p->reply.data);
    free(p);
}
void opentlv_wasm_program_retain(opentlv_wasm_program_t* p) {
    ++p->references;
}
const char* opentlv_wasm_schema_validate(opentlv_wasm_program_t* owner, const uint32_t* programs,
                                         const uint32_t* names, size_t count,
                                         opentlv_wasm_document_t* document, const uint8_t* data,
                                         size_t size, size_t depth, size_t nodes, size_t work,
                                         size_t contexts, size_t value_capacity,
                                         int measure_values) {
    tlv_result_t rc =
        count > SIZE_MAX / sizeof(tlv_schema_query_rule_t) ? TLV_ERR_OVERFLOW : TLV_OK;
    tlv_schema_query_rule_t* rules = rc == TLV_OK && count ? calloc(count, sizeof *rules) : NULL;
    if (rc == TLV_OK && count && !rules) rc = TLV_ERR_OUT_OF_MEMORY;
    tlv_schema_query_diagnostic_t diagnostic = {0};
    if (rc == TLV_OK) {
        for (size_t i = 0; i < count; ++i) {
            opentlv_wasm_program_t* context = (opentlv_wasm_program_t*)(uintptr_t)programs[2 * i];
            opentlv_wasm_program_t* assertion =
                (opentlv_wasm_program_t*)(uintptr_t)programs[2 * i + 1];
            rules[i] = (tlv_schema_query_rule_t){context->program, assertion->program,
                                                 &assertion->environment,
                                                 (const char*)(uintptr_t)names[i]};
        }
        rc = opentlv_binding_schema_run(data, size, document ? document->document : NULL,
                                        owner->environment.format, rules, count, depth, nodes, work,
                                        contexts, value_capacity, measure_values, &diagnostic);
    }
    free(rules);
    query_status(&owner->reply, rc, &diagnostic.query);
    query_field(&owner->reply, "rule", diagnostic.rule);
    builder_text(&owner->reply, ",\"schema\":{\"tag\":\"");
    builder_hex(&owner->reply, diagnostic.schema.tag.data, diagnostic.schema.tag.size);
    builder_text(&owner->reply, "\",\"field\":");
    builder_json_string(&owner->reply, diagnostic.schema.field ? diagnostic.schema.field : "");
    query_field(&owner->reply, "kind", diagnostic.schema.kind);
    builder_text(&owner->reply, ",\"kind_name\":");
    builder_json_string(&owner->reply, tlv_schema_issue_kind_string(diagnostic.schema.kind));
    query_field(&owner->reply, "code", diagnostic.schema.diagnostic.code);
    query_field(&owner->reply, "severity", diagnostic.schema.diagnostic.severity);
    builder_text(&owner->reply, ",\"offset\":");
    if (diagnostic.schema.diagnostic.has_offset)
        builder_number(&owner->reply, diagnostic.schema.diagnostic.offset);
    else
        builder_text(&owner->reply, "null");
    builder_text(&owner->reply, ",\"expected\":");
    if (diagnostic.schema.diagnostic.expected)
        builder_json_string(&owner->reply, diagnostic.schema.diagnostic.expected);
    else
        builder_text(&owner->reply, "null");
    builder_text(&owner->reply, ",\"actual\":");
    if (diagnostic.schema.diagnostic.actual)
        builder_json_string(&owner->reply, diagnostic.schema.diagnostic.actual);
    else
        builder_text(&owner->reply, "null");
    builder_text(&owner->reply, ",\"path\":[");
    for (size_t i = 0; i < diagnostic.schema.path.length; ++i) {
        if (i) builder_text(&owner->reply, ",");
        builder_text(&owner->reply, "\"");
        builder_hex(&owner->reply, diagnostic.schema.path.tags[i].data,
                    diagnostic.schema.path.tags[i].size);
        builder_text(&owner->reply, "\"");
    }
    builder_text(&owner->reply, "]");
    builder_text(&owner->reply, "}");
    return query_reply(&owner->reply);
}
int opentlv_wasm_program_variable(opentlv_wasm_program_t* p, const char* name, int type) {
    if (!p || p->program || !name) return TLV_ERR_INVALID_ARG;
    if (p->options.variable_count == QUERY_DECLARATIONS) return TLV_ERR_LIMIT;
    char* copy = query_copy_name(name);
    if (!copy) return TLV_ERR_OUT_OF_MEMORY;
    tlv_query_variable_t* v = p->variables + p->options.variable_count++;
    v->name = copy;
    v->type = (tlv_query_result_kind_t)type;
    return TLV_OK;
}
int opentlv_wasm_program_name(opentlv_wasm_program_t* p, const char* name, const uint8_t* data,
                              size_t size) {
    if (!p || p->program || !name || (!data && size)) return TLV_ERR_INVALID_ARG;
    if (p->name_count == QUERY_DECLARATIONS) return TLV_ERR_LIMIT;
    wasm_name_t n = {query_copy_name(name), malloc(size ? size : 1), size};
    if (!n.name || !n.bytes) {
        free(n.name);
        free(n.bytes);
        return TLV_ERR_OUT_OF_MEMORY;
    }
    if (size) memcpy(n.bytes, data, size);
    p->names[p->name_count++] = n;
    return TLV_OK;
}
int opentlv_wasm_program_option(opentlv_wasm_program_t* p, int key, size_t value) {
    if (!p || p->program) return TLV_ERR_INVALID_ARG;
    switch (key) {
        case 0: p->options.optimize = value != 0; break;
        case 1: p->options.max_text = value; break;
        case 2: p->options.max_tokens = value; break;
        case 3: p->options.max_nesting = value; break;
        case 4: p->options.max_states = value; break;
        case 5: p->options.max_pattern = value; break;
        case 6: p->options.max_resolved_tag = value; break;
        default: return TLV_ERR_INVALID_ARG;
    }
    return TLV_OK;
}
int opentlv_wasm_program_provider(opentlv_wasm_program_t* p, int function, uint32_t id,
                                  size_t capacity, tlv_query_decode_t decode) {
    if (!p || p->program || function < 0 || function > TLV_QUERY_DATE || !id || !decode)
        return TLV_ERR_INVALID_ARG;
    size_t slot = 0;
    while (slot < p->environment.hook_count &&
           p->hooks[slot].function != (tlv_query_conversion_t)function)
        ++slot;
    if (slot == p->environment.hook_count) ++p->environment.hook_count;
    p->hooks[slot] =
        (tlv_query_hook_t){id, (tlv_query_conversion_t)function, capacity, 1, NULL, decode};
    return TLV_OK;
}
void opentlv_wasm_provider_integer(tlv_query_result_t* result, uint32_t low, uint32_t high) {
    memset(result, 0, sizeof *result);
    result->kind = TLV_QUERY_RESULT_INTEGER;
    uint64_t bits = ((uint64_t)high << 32) | low;
    memcpy(&result->integer, &bits, sizeof bits);
}
void opentlv_wasm_provider_text(tlv_query_result_t* result, const uint8_t* data, size_t size) {
    memset(result, 0, sizeof *result);
    result->kind = TLV_QUERY_RESULT_STRING;
    result->data = data;
    result->size = size;
}
size_t opentlv_wasm_provider_event(const tlv_tree_event_t* event, int field) {
    if (!event) return 0;
    switch (field) {
        case 0: return (size_t)event->kind;
        case 1: return event->depth;
        case 2: return event->offset;
        case 3: return (size_t)(uintptr_t)event->element.tag.data;
        case 4: return event->element.tag.size;
        case 5: return (size_t)(uintptr_t)event->element.value.data;
        case 6: return event->element.value.size;
        default: return 0;
    }
}
const char* opentlv_wasm_program_compile(opentlv_wasm_program_t* p, const uint8_t* text,
                                         size_t size, int image) {
    tlv_query_diagnostic_t d = {0};
    size_t                 bytes = 0, alignment;
    tlv_result_t           rc =
        p->program ? TLV_ERR_INVALID_ARG
        : image    ? tlv_query_program_load_scratch(text, size, &p->options, &bytes, &alignment, &d)
                   : tlv_query_compile_scratch((const char*)text, size, &p->options, &bytes,
                                               &alignment, &d);
    void* scratch = rc == TLV_OK ? malloc(bytes ? bytes : 1) : NULL;
    if (rc == TLV_OK && !scratch) rc = TLV_ERR_OUT_OF_MEMORY;
    p->info.struct_size = sizeof p->info;
    if (rc == TLV_OK && !image)
        rc = tlv_query_compile((const char*)text, size, &p->options, scratch, bytes, NULL, 0,
                               &p->info, &d);
    if (rc == TLV_OK) {
        p->image = malloc(image ? (size ? size : 1) : p->info.program_size);
        if (!p->image) rc = TLV_ERR_OUT_OF_MEMORY;
    }
    if (rc == TLV_OK && image) {
        memcpy(p->image, text, size);
        rc = tlv_query_program_load(p->image, size, &p->options, scratch, bytes, &p->program,
                                    &p->info, &d);
    } else if (rc == TLV_OK) {
        rc = tlv_query_compile((const char*)text, size, &p->options, scratch, bytes, p->image,
                               p->info.program_size, &p->info, &d);
        if (rc == TLV_OK) p->program = p->image;
    }
    free(scratch);
    if (rc != TLV_OK) {
        free(p->image);
        p->image = NULL;
    }
    query_status(&p->reply, rc, &d);
    if (rc == TLV_OK) {
        builder_text(&p->reply, ",\"info\":{\"language_version\":1");
#define FIELD(n) query_field(&p->reply, #n, p->info.n)
        FIELD(program_size);
        FIELD(program_alignment);
        FIELD(scratch_size);
        FIELD(scratch_alignment);
        FIELD(states);
        FIELD(level);
        FIELD(result_kind);
        FIELD(expression_values);
        FIELD(instructions);
        FIELD(variable_slots);
        FIELD(codec_scratch);
        FIELD(pattern_bytes);
        FIELD(optimized_states);
        FIELD(expression_stack);
        FIELD(candidate_size);
        FIELD(candidate_alignment);
        FIELD(frame_states);
        FIELD(decision_timing);
        FIELD(stable_input_required);
        FIELD(constructed_values_required);
#undef FIELD
        builder_text(&p->reply, "}");
    }
    return query_reply(&p->reply);
}
const uint8_t* opentlv_wasm_program_image(opentlv_wasm_program_t* p) {
    return p->image;
}
size_t opentlv_wasm_program_image_size(opentlv_wasm_program_t* p) {
    return p->info.program_size;
}
const char* opentlv_wasm_program_render(opentlv_wasm_program_t* p, int explain) {
    if (explain == -1) return p->reply.data;
    size_t       size;
    tlv_result_t rc = explain ? tlv_query_program_explain(p->program, NULL, 0, &size)
                              : tlv_query_program_format(p->program, NULL, 0, &size);
    char*        text = rc == TLV_OK ? malloc(size) : NULL;
    if (rc == TLV_OK && !text) rc = TLV_ERR_OUT_OF_MEMORY;
    if (rc == TLV_OK)
        rc = explain ? tlv_query_program_explain(p->program, text, size, &size)
                     : tlv_query_program_format(p->program, text, size, &size);
    query_status(&p->reply, rc, NULL);
    if (rc == TLV_OK) {
        builder_text(&p->reply, ",\"value\":");
        builder_json_string(&p->reply, text);
    }
    free(text);
    return query_reply(&p->reply);
}
static void wasm_unpin(opentlv_wasm_execution_t* q) {
    while (q->pins) {
        wasm_pin_t* pin = q->pins;
        q->pins = pin->next;
        free(pin);
    }
}
static wasm_pin_t* wasm_pin(opentlv_wasm_execution_t* q, const uint8_t* data, size_t size) {
    if ((!data && size) || size > SIZE_MAX - sizeof(wasm_pin_t)) return NULL;
    wasm_pin_t* pin = malloc(sizeof *pin + size);
    if (!pin) return NULL;
    if (size) memcpy(pin->data, data, size);
    pin->next = q->pins;
    q->pins = pin;
    return pin;
}
static tlv_result_t wasm_execution_reset(opentlv_wasm_execution_t* q) {
    tlv_result_t rc =
        q->retained ? tlv_query_eval_init(q->program->program, &q->program->environment, q->storage,
                                          q->capacity, q->depth, q->nodes, q->work, &q->exec)
                    : tlv_query_exec_init(q->program->program, q->storage, q->capacity, q->depth,
                                          q->nodes, q->work, &q->exec);
    if (rc == TLV_OK) {
        wasm_unpin(q);
        free(q->values);
        q->values = NULL;
        opentlv_wasm_document_free(q->document);
        q->document = NULL;
        q->has_reader = 0;
        q->fed = 0;
    }
    return rc;
}
opentlv_wasm_execution_t* opentlv_wasm_execution_new(opentlv_wasm_program_t* p, size_t depth,
                                                     size_t nodes, size_t work, int retained) {
    size_t       bytes = 0, alignment = 0;
    tlv_result_t rc = retained ? tlv_query_eval_size(p->program, depth, nodes, &bytes, &alignment)
                               : tlv_query_exec_size(p->program, depth, &bytes, &alignment);
    opentlv_wasm_execution_t* q = NULL;
    if (rc == TLV_OK &&
        (bytes > SIZE_MAX - alignment + 1 || depth > SIZE_MAX / sizeof(tlv_tree_frame_t)))
        rc = TLV_ERR_OVERFLOW;
    if (rc == TLV_OK) {
        q = calloc(1, sizeof *q);
        if (!q) rc = TLV_ERR_OUT_OF_MEMORY;
    }
    if (rc == TLV_OK) {
        q->program = p;
        ++p->references;
        q->depth = depth;
        q->nodes = nodes;
        q->work = work;
        q->retained = retained;
        q->capacity = bytes;
        q->allocation = malloc(bytes + alignment - 1);
        q->frames = calloc(depth ? depth : 1, sizeof *q->frames);
        if (!q->allocation || !q->frames)
            rc = TLV_ERR_OUT_OF_MEMORY;
        else {
            q->storage =
                (void*)(((uintptr_t)q->allocation + alignment - 1) & ~(uintptr_t)(alignment - 1));
            rc = wasm_execution_reset(q);
        }
    }
    query_status(&p->reply, rc, NULL);
    query_reply(&p->reply);
    if (rc != TLV_OK) {
        opentlv_wasm_execution_free(q);
        return NULL;
    }
    return q;
}
void opentlv_wasm_execution_free(opentlv_wasm_execution_t* q) {
    if (!q) return;
    wasm_unpin(q);
    free(q->allocation);
    free(q->frames);
    free(q->values);
    free(q->reply.data);
    opentlv_wasm_document_free(q->document);
    opentlv_wasm_program_free(q->program);
    free(q);
}
const char* opentlv_wasm_execution_input(opentlv_wasm_execution_t* q, const uint8_t* data,
                                         size_t size, size_t discard, int final) {
    tlv_result_t rc =
        q->document || q->fed || (!q->has_reader && discard) ? TLV_ERR_INVALID_ARG : TLV_OK;
    wasm_pin_t* pin = rc == TLV_OK ? wasm_pin(q, data, size) : NULL;
    if (rc == TLV_OK && !pin) rc = TLV_ERR_OUT_OF_MEMORY;
    if (rc == TLV_OK)
        rc = q->has_reader ? tlv_tree_reader_set_input(&q->reader, pin->data, size, discard, final)
             : final
                 ? tlv_tree_reader_init(&q->reader, pin->data, size, q->program->environment.format,
                                        q->frames, q->depth, q->depth, q->nodes)
                 : tlv_tree_reader_init_incremental(&q->reader, pin->data, size,
                                                    q->program->environment.format, q->frames,
                                                    q->depth, q->depth, q->nodes);
    if (rc == TLV_OK) q->has_reader = 1;
    query_status(&q->reply, rc, NULL);
    return query_reply(&q->reply);
}
const char* opentlv_wasm_execution_bind(opentlv_wasm_execution_t* q, const char* name, int type,
                                        const char* integer, const uint8_t* data, size_t size) {
    tlv_query_diagnostic_t d = {0};
    wasm_pin_t*            pin = wasm_pin(q, data, size);
    int64_t                value = 0;
    tlv_result_t           rc = pin ? TLV_OK : TLV_ERR_OUT_OF_MEMORY;
    if (rc == TLV_OK && type == TLV_QUERY_RESULT_INTEGER) {
        char* end;
        value = strtoll(integer, &end, 10);
        if (*end) rc = TLV_ERR_INVALID_ARG;
    }
    if (rc == TLV_OK)
        rc = tlv_query_exec_bind(q->exec, name, (tlv_query_result_kind_t)type, value, pin->data,
                                 size, &d);
    query_status(&q->reply, rc, &d);
    return query_reply(&q->reply);
}
static tlv_visit_result_t wasm_pull(const tlv_tree_event_t* event, void* context) {
    *(tlv_tree_event_t*)context = *event;
    return TLV_VISIT_STOP;
}
static tlv_visit_result_t wasm_drain(const tlv_tree_event_t* event, void* context) {
    (void)event;
    (void)context;
    return TLV_VISIT_CONTINUE;
}
static void wasm_event(builder_t* b, const tlv_tree_event_t* event) {
    builder_text(b, ",\"value\":{\"offset\":");
    builder_number(b, event->offset);
    query_field(b, "depth", event->depth);
    query_field(b, "kind", event->kind);
    builder_text(b, ",\"tag\":\"");
    builder_hex(b, event->element.tag.data, event->element.tag.size);
    builder_text(b, "\",\"bytes\":\"");
    builder_hex(b, event->element.value.data, event->element.value.size);
    builder_text(b, "\"}");
}
const char* opentlv_wasm_execution_feed(opentlv_wasm_execution_t* q, int kind, const uint8_t* tag,
                                        size_t tag_size, const uint8_t* value, size_t value_size,
                                        size_t depth, size_t offset, int skipped) {
    tlv_query_diagnostic_t diagnostic = {0};
    tlv_result_t           rc = q->has_reader || q->document ? TLV_ERR_INVALID_ARG : TLV_OK;
    tlv_tree_event_t       event = {0};
    int                    matched = 0;
    if (rc == TLV_OK) {
        wasm_pin_t* tag_pin = wasm_pin(q, tag, tag_size);
        wasm_pin_t* value_pin = wasm_pin(q, value, value_size);
        if (!tag_pin || !value_pin)
            rc = TLV_ERR_OUT_OF_MEMORY;
        else {
            event.kind = (tlv_tree_event_kind_t)kind;
            event.element.tag = tlv_tag(tag_pin->data, tag_size);
            event.element.value.data = value_pin->data;
            event.element.value.size = value_size;
            event.depth = depth;
            event.offset = offset;
            event.skipped = skipped;
            q->fed = 1;
            rc = tlv_query_exec_feed(q->exec, &event, &matched, &diagnostic);
            if (rc == TLV_OK && matched && q->program->info.level == TLV_QUERY_S1)
                rc = tlv_query_exec_selected(q->exec, &event);
        }
    }
    query_status(&q->reply, rc, &diagnostic);
    if (rc == TLV_OK && matched)
        wasm_event(&q->reply, &event);
    else if (rc == TLV_OK)
        builder_text(&q->reply, ",\"value\":null");
    return query_reply(&q->reply);
}
const char* opentlv_wasm_execution_operation(opentlv_wasm_execution_t* q, int operation,
                                             size_t argument) {
    tlv_query_diagnostic_t d = {0};
    tlv_result_t           rc = TLV_OK;
    tlv_tree_event_t       event = {0};
    tlv_query_result_t     result = {0};
    tlv_query_exec_info_t  info = {0};
    info.struct_size = sizeof info;
    int         found = 0;
    tlv_node_t* node = NULL;
    switch (operation) {
        case 0: rc = wasm_execution_reset(q); break;
        case 1:
            if (q->document) {
#if OPENTLV_DOCUMENT
                rc = tlv_document_query_next(q->exec, &node);
#else
                rc = TLV_ERR_UNSUPPORTED_TYPE;
#endif
            } else if (q->fed && q->retained)
                rc = tlv_query_result_next(q->exec, &event);
            else if (!q->has_reader || q->program->info.result_kind != TLV_QUERY_RESULT_NODES)
                rc = TLV_ERR_INVALID_ARG;
            else {
                event.kind = (tlv_tree_event_kind_t)-1;
                rc = tlv_query_program_visit(&q->reader, q->exec, wasm_pull, &event, &d);
                if (rc == TLV_OK && (int)event.kind == -1) rc = TLV_ERR_END_OF_BUFFER;
            }
            break;
        case 2: rc = tlv_query_exec_result(q->exec, &result); break;
        case 3: rc = tlv_query_exec_info(q->exec, &info); break;
        case 4:
            rc = q->has_reader
                     ? tlv_query_program_exists(&q->reader, q->exec, argument != 0, &found, &d)
                     : TLV_ERR_INVALID_ARG;
            break;
        case 5: rc = tlv_query_exec_context(q->exec, argument); break;
        case 6: rc = tlv_query_exec_pruning(q->exec, argument != 0); break;
        case 7:
            rc = q->has_reader ? tlv_query_program_visit(&q->reader, q->exec, wasm_drain, NULL, &d)
                               : tlv_query_exec_finish(q->exec, &d);
            break;
        default: rc = TLV_ERR_INVALID_ARG; break;
    }
    query_status(&q->reply, rc, &d);
    if (rc == TLV_OK && operation == 1) {
        if (!q->document) wasm_event(&q->reply, &event);
#if OPENTLV_DOCUMENT
        else {
            builder_text(&q->reply, ",\"value\":{\"node\":");
            builder_number(&q->reply, (size_t)(uintptr_t)node);
            builder_text(&q->reply, ",\"identity\":");
            query_integer(&q->reply, (int64_t)tlv_node_identity(node));
            builder_text(&q->reply, "}");
        }
#endif
    } else if (rc == TLV_OK && operation == 2) {
        query_field(&q->reply, "kind", result.kind);
        builder_text(&q->reply, ",\"value\":");
        if (result.kind == TLV_QUERY_RESULT_BOOL)
            builder_text(&q->reply, result.boolean ? "true" : "false");
        else if (result.kind == TLV_QUERY_RESULT_INTEGER)
            query_integer(&q->reply, result.integer);
        else if (result.kind == TLV_QUERY_RESULT_BYTES || result.kind == TLV_QUERY_RESULT_STRING) {
            builder_text(&q->reply, "\"");
            builder_hex(&q->reply, result.data, result.size);
            builder_text(&q->reply, "\"");
        } else
            builder_text(&q->reply, "null");
    } else if (rc == TLV_OK && operation == 3) {
        builder_text(&q->reply, ",\"value\":{\"elements\":");
        builder_number(&q->reply, info.elements);
        query_field(&q->reply, "work", info.work);
        query_field(&q->reply, "finished", info.finished);
        query_field(&q->reply, "full_validation", info.full_validation);
        query_field(&q->reply, "invalid", info.invalid);
        query_field(&q->reply, "skipped_subtrees", info.skipped_subtrees);
        builder_text(&q->reply, "}");
    } else if (rc == TLV_OK && operation == 4)
        builder_text(&q->reply, found ? ",\"value\":true" : ",\"value\":false");
    return query_reply(&q->reply);
}
opentlv_wasm_document_t* opentlv_wasm_document_new(opentlv_wasm_program_t* p, const uint8_t* data,
                                                   size_t size) {
    tlv_result_t             rc = TLV_ERR_UNSUPPORTED_TYPE;
    opentlv_wasm_document_t* doc = NULL;
#if OPENTLV_DOCUMENT
    doc = calloc(1, sizeof *doc);
    rc = doc ? TLV_OK : TLV_ERR_OUT_OF_MEMORY;
    if (doc) {
        doc->references = 1;
        doc->program = p;
        ++p->references;
        tlv_document_options_t options;
        rc = tlv_document_options_init(&options, p->environment.format);
        if (rc == TLV_OK) rc = tlv_document_parse(data, size, &options, &doc->document, NULL);
    }
#else
    (void)data;
    (void)size;
#endif
    query_status(&p->reply, rc, NULL);
    query_reply(&p->reply);
    if (rc != TLV_OK) {
        opentlv_wasm_document_free(doc);
        return NULL;
    }
    return doc;
}
void opentlv_wasm_document_free(opentlv_wasm_document_t* doc) {
    if (!doc || --doc->references) return;
#if OPENTLV_DOCUMENT
    tlv_document_free(doc->document);
#endif
    opentlv_wasm_program_free(doc->program);
    free(doc);
}
const char* opentlv_wasm_execution_document(opentlv_wasm_execution_t* q,
                                            opentlv_wasm_document_t* doc, size_t capacity) {
    tlv_query_diagnostic_t d = {0};
    tlv_result_t           rc = TLV_ERR_UNSUPPORTED_TYPE;
#if OPENTLV_DOCUMENT
    rc = !q->retained || q->has_reader || q->document ? TLV_ERR_INVALID_ARG : TLV_OK;
    tlv_tree_writer_workspace_t staging = {0};
    if (rc == TLV_OK && q->program->info.constructed_values_required) {
        if (q->depth == SIZE_MAX || q->depth + 1 > SIZE_MAX / sizeof *staging.frames)
            rc = TLV_ERR_OVERFLOW;
        else {
            staging.frames = calloc(q->depth + 1, sizeof *staging.frames);
            staging.frame_capacity = q->depth + 1;
            staging.data = malloc(capacity ? capacity : 1);
            staging.data_capacity = capacity;
            staging.scratch = malloc(capacity ? capacity : 1);
            staging.scratch_capacity = capacity;
            q->values = malloc(capacity ? capacity : 1);
            if (!staging.frames || !staging.data || !staging.scratch || !q->values)
                rc = TLV_ERR_OUT_OF_MEMORY;
        }
    }
    if (rc == TLV_OK) {
        q->document = doc;
        ++doc->references;
        rc = tlv_document_query_evaluate(
            doc->document, q->exec, NULL, q->values,
            q->program->info.constructed_values_required ? capacity : 0,
            q->program->info.constructed_values_required ? &staging : NULL, &d);
    }
    free(staging.frames);
    free(staging.data);
    free(staging.scratch);
#else
    (void)doc;
    (void)capacity;
#endif
    query_status(&q->reply, rc, &d);
    return query_reply(&q->reply);
}
const char* opentlv_wasm_execution_edit(opentlv_wasm_execution_t* q, int kind, const uint8_t* tag,
                                        size_t tag_size, const uint8_t* value, size_t value_size,
                                        size_t capacity) {
    tlv_result_t rc = TLV_ERR_UNSUPPORTED_TYPE;
    size_t       applied = 0;
#if OPENTLV_DOCUMENT
    rc = q->document ? TLV_OK : TLV_ERR_INVALID_ARG;
    if (rc == TLV_OK && capacity > SIZE_MAX / sizeof(tlv_node_t*)) rc = TLV_ERR_OVERFLOW;
    tlv_node_t** targets = rc == TLV_OK && capacity ? calloc(capacity, sizeof *targets) : NULL;
    if (rc == TLV_OK && capacity && !targets) rc = TLV_ERR_OUT_OF_MEMORY;
    if (rc == TLV_OK)
        rc = tlv_document_query_edit(q->document->document, q->exec,
                                     (tlv_document_query_edit_kind_t)kind, tlv_tag(tag, tag_size),
                                     value, value_size, targets, capacity, &applied);
    free(targets);
#else
    (void)q;
    (void)kind;
    (void)tag;
    (void)tag_size;
    (void)value;
    (void)value_size;
    (void)capacity;
#endif
    query_status(&q->reply, rc, NULL);
    query_field(&q->reply, "applied", applied);
    return query_reply(&q->reply);
}
const char* opentlv_wasm_document_node(opentlv_wasm_document_t* doc, size_t address,
                                       const char* identity, int operation, const uint8_t* data,
                                       size_t size) {
    builder_t*   b = &doc->program->reply;
    tlv_result_t rc = TLV_ERR_UNSUPPORTED_TYPE;
#if OPENTLV_DOCUMENT
    tlv_node_t* node = (tlv_node_t*)(uintptr_t)address;
    rc = TLV_OK;
    if (node && (!identity ||
                 tlv_document_node_identity(doc->document, node) != strtoull(identity, NULL, 10)))
        rc = TLV_ERR_INVALID_ARG;
    if (rc == TLV_OK) {
        switch (operation) {
            case 0: node = tlv_document_first(doc->document); break;
            case 1: node = tlv_node_first_child(node); break;
            case 2: node = tlv_node_next(node); break;
            case 3: node = tlv_node_parent(node); break;
            case 4: rc = node ? tlv_node_set_value(node, data, size) : TLV_ERR_INVALID_ARG; break;
            case 5:
                if (node)
                    tlv_node_erase(node);
                else
                    rc = TLV_ERR_INVALID_ARG;
                node = NULL;
                break;
            case 6: break;
            default: rc = TLV_ERR_INVALID_ARG;
        }
    }
    query_status(b, rc, NULL);
    if (rc == TLV_OK) {
        builder_text(b, ",\"value\":");
        if (!node)
            builder_text(b, "null");
        else {
            builder_text(b, "{\"node\":");
            builder_number(b, (size_t)(uintptr_t)node);
            builder_text(b, ",\"identity\":");
            query_integer(b, (int64_t)tlv_node_identity(node));
            tlv_tag_t tag = tlv_node_tag(node);
            builder_text(b, ",\"tag\":\"");
            builder_hex(b, tag.data, tag.size);
            builder_text(b, "\",\"bytes\":\"");
            if (!tlv_node_is_constructed(node))
                builder_hex(b, tlv_node_value_data(node), tlv_node_value_size(node));
            builder_text(b, "\"");
            query_field(b, "constructed", tlv_node_is_constructed(node));
            builder_text(b, "}");
        }
    }
#else
    (void)address;
    (void)identity;
    (void)operation;
    (void)data;
    (void)size;
    query_status(b, rc, NULL);
#endif
    return query_reply(b);
}
