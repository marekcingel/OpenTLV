#include "opentlv_wasm.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tlv/tlv.h"
#if OPENTLV_FORMAT_BLUETOOTH_LTV
#include "tlv/builtins/bluetooth/bluetooth_ltv.h"
#endif
#include "tlv/version.h"

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
    size_t count[TLV_WALK_MAX_DEPTH + 2];
    int    has_children[TLV_WALK_MAX_DEPTH + 2];
    int    ber;
    /* Start of the parsed input; offsets of values are measured against it. */
    const uint8_t* input;
#if OPENTLV_PROFILE_EMV
    /* Set when the EMV dictionary annotates elements; `emv_context[d]` is the
     * dictionary context of the elements at depth d. */
    int               emv;
    tlv_emv_context_t emv_context[TLV_WALK_MAX_DEPTH + 2];
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

#if OPENTLV_PROFILE_EMV
/* Appends the EMV dictionary entry of the element, if it has one, and derives
 * the dictionary context its children are read in. */
static void emit_emv(writer_context_t* w, const tlv_view_t* view, size_t depth, size_t length) {
    tlv_emv_context_t           context = w->emv_context[depth];
    tlv_emv_context_t           child = tlv_emv_child_context(context, &view->tag);
    const tlv_emv_definition_t* definition = tlv_emv_find(context, &view->tag);

    w->emv_context[depth + 1] = child == TLV_EMV_CONTEXT_COUNT ? context : child;
    if (!definition) return;
    {
        char        title[128];
        const char* label = tlv_emv_display_label(definition->name);
        if (!label && tlv_emv_titlecase_name(definition->name, title, sizeof title) == TLV_OK)
            label = title;
        builder_text(&w->out, ",\"symbol\":");
        builder_json_string(&w->out, definition->name);
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

static tlv_visit_result_t emit_element(const tlv_view_t* view, size_t depth, size_t offset,
                                       void* context) {
    writer_context_t* w = (writer_context_t*)context;
    int               constructed = 0;
    size_t            length, header_size;

    if (tlv_length_to_size(view->value.length, &length) != TLV_OK) return TLV_VISIT_ERROR;
    if (depth > TLV_WALK_MAX_DEPTH) return TLV_VISIT_ERROR;
    /* The value directly follows the encoded tag and length. */
    header_size = (size_t)(view->value.data - w->input) - offset;
#if OPENTLV_FORMAT_BER
    if (w->ber) constructed = tlv_ber_is_constructed(NULL, &view->tag) != 0;
#endif
    close_elements(w, depth);
    if (w->count[depth]++) builder_text(&w->out, ",");
    w->count[depth + 1] = 0;

    builder_text(&w->out, "{\"offset\":");
    builder_number(&w->out, offset);
    builder_text(&w->out, ",\"depth\":");
    builder_number(&w->out, depth);
    builder_text(&w->out, ",\"tag\":\"");
    builder_hex(&w->out, view->tag.data, view->tag.size);
    builder_text(&w->out, "\",\"length\":");
    builder_number(&w->out, length);
    builder_text(&w->out, ",\"headerSize\":");
    builder_number(&w->out, header_size);
    builder_text(&w->out, constructed ? ",\"constructed\":true" : ",\"constructed\":false");
#if OPENTLV_PROFILE_EMV
    if (w->emv) emit_emv(w, view, depth, length);
#endif
    if (constructed && length) {
        /* The walker descends into it next; children close it later. */
        builder_text(&w->out, ",\"children\":[");
        w->has_children[w->open] = 1;
    } else {
        builder_text(&w->out, ",\"value\":\"");
        builder_hex(&w->out, view->value.data, length);
        builder_text(&w->out, "\"");
        w->has_children[w->open] = 0;
    }
    ++w->open;
    return w->out.failed ? TLV_VISIT_ERROR : TLV_VISIT_CONTINUE;
}

static const tlv_reader_format_t* select_format(const char* name, int* ber, int* der,
                                                size_t fixed_tag_size, size_t fixed_length_size,
                                                int fixed_big_endian) {
    *ber = 0;
    *der = 0;
    if (!name) return NULL;
#if OPENTLV_FORMAT_DEFAULT
    if (!strcmp(name, "default")) return &tlv_reader_format_default;
#endif
#if OPENTLV_FORMAT_FIXED
    // Configured by the caller's fixed_tag_size/fixed_length_size/fixed_big_endian.
    if (!strcmp(name, "fixed")) {
        static tlv_fixed_config_t  config;
        static tlv_reader_format_t format;
        config.tag_size = fixed_tag_size;
        config.length_size = fixed_length_size;
        config.order = fixed_big_endian ? TLV_BYTE_ORDER_BIG_ENDIAN : TLV_BYTE_ORDER_LITTLE_ENDIAN;
        if (tlv_fixed_reader_format_init(&format, &config) != TLV_OK) return NULL;
        return &format;
    }
#endif
#if OPENTLV_FORMAT_BLUETOOTH_LTV
    if (!strcmp(name, "bluetooth-ltv")) return &tlv_reader_format_bluetooth_ltv;
#endif
#if OPENTLV_FORMAT_BER
    if (!strcmp(name, "ber")) {
        *ber = 1;
        return &tlv_reader_format_ber;
    }
#endif
#if OPENTLV_FORMAT_DER
    if (!strcmp(name, "der")) {
        *ber = 1;
        *der = 1;
        return &tlv_reader_format_der;
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
                                          const char* profile, size_t fixed_tag_size,
                                          size_t fixed_length_size, int fixed_big_endian) {
    opentlv_wasm_result_t*     result = (opentlv_wasm_result_t*)calloc(1, sizeof *result);
    const tlv_reader_format_t* reader;
    writer_context_t*          w;
    int                        ber, der;
    size_t                     error_offset = 0;

    if (!result) return NULL;
    w = (writer_context_t*)calloc(1, sizeof *w);
    if (!w) {
        free(result);
        return NULL;
    }
    reader = select_format(format, &ber, &der, fixed_tag_size, fixed_length_size, fixed_big_endian);
    w->ber = ber;
    w->input = data;

    builder_text(&w->out, "{\"format\":");
    builder_json_string(&w->out, format ? format : "");

    if (profile && *profile && strcmp(profile, "none")) {
        /* The EMV dictionary names BER-TLV tags; it does not apply to other formats. */
#if OPENTLV_PROFILE_EMV
        if (!strcmp(profile, "emv") && ber && !der) {
            w->emv = 1;
            w->emv_context[0] = TLV_EMV_CONTEXT_BASE;
            builder_text(&w->out, ",\"profile\":\"emv\"");
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
#if OPENTLV_FORMAT_DER
        if (der) {
            result->code = tlv_der_walk(data, size, NULL, emit_element, w, &error_offset);
        } else
#endif
        {
            tlv_is_constructed_fn constructed = NULL;
#if OPENTLV_FORMAT_BER
            if (ber) constructed = tlv_ber_is_constructed;
#endif
            result->code = tlv_walk_tree(data, size, reader, constructed, TLV_WALK_MAX_DEPTH,
                                         WASM_MAX_ELEMENTS, emit_element, w, &error_offset);
        }
    }
    if (w->out.failed) result->code = TLV_ERR_OUT_OF_MEMORY;
    result->error_offset = error_offset;

    close_elements(w, 0);
    builder_text(&w->out, "]");
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
