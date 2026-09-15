#include <ctype.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif
#include "tlv/config.h"
#include "tlv/version.h"
#include "tlv/reader/walker.h"
#include "diagnostics.hpp"
#include "options.hpp"
#include "presentation.hpp"
#include "tlv++/walker.hpp"
#include <memory>
#if OPENTLV_FORMAT_DEFAULT
#include "tlv/formats/default/default.h"
#endif
#if OPENTLV_FORMAT_FIXED_1BYTE
#include "tlv/formats/fixed/fixed_1byte.h"
#endif
#if OPENTLV_FORMAT_BER
#include "tlv/formats/asn1/ber.h"
#endif
#if OPENTLV_FORMAT_DER
#include "tlv/profiles/der.h"
#endif

using cli::fail;

static const tlv_reader_format_t* select_format(const char* name) {
#if OPENTLV_FORMAT_DEFAULT
    if (!strcmp(name, "default")) return &tlv_reader_format_default;
#endif
#if OPENTLV_FORMAT_FIXED_1BYTE
    if (!strcmp(name, "fixed-1byte")) return &tlv_reader_format_fixed_1byte;
#endif
#if OPENTLV_FORMAT_BER
    if (!strcmp(name, "ber")) return &tlv_reader_format_ber;
#endif
#if OPENTLV_FORMAT_DER
    if (!strcmp(name, "der")) return &tlv_reader_format_der;
#endif
    (void)name;
    return NULL;
}

static void formats(void) {
#if OPENTLV_FORMAT_DEFAULT
    puts("default");
#endif
#if OPENTLV_FORMAT_FIXED_1BYTE
    puts("fixed-1byte");
#endif
#if OPENTLV_FORMAT_BER
    puts("ber");
#endif
#if OPENTLV_FORMAT_DER
    puts("der");
#endif
}

static int nibble(unsigned char ch) {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

/* Grow only the CLI-owned input buffer; the library keeps borrowing it. */
static int append(uint8_t** data, size_t* size, size_t* capacity, size_t limit, uint8_t byte) {
    if (*size == limit) return fail(3, "input-size limit exceeded");
    if (*size == *capacity) {
        size_t next = *capacity ? (*capacity > SIZE_MAX / 2 ? SIZE_MAX : *capacity * 2) : 4096;
        uint8_t* grown;
        if (next > limit) next = limit;
        grown = (uint8_t*)realloc(*data, next);
        if (!grown) return fail(3, "cannot allocate input buffer");
        *data = grown;
        *capacity = next;
    }
    (*data)[(*size)++] = byte;
    return 0;
}

static int read_input(const cli::options* o, uint8_t** data, size_t* size) {
    size_t capacity = 0;
    int rc = 0;
    if (o->hex) {
        const unsigned char* p = (const unsigned char*)o->hex;
        while (*p) {
            int hi, lo;
            if (isspace(*p)) { ++p; continue; }
            hi = nibble(*p++);
            if (hi < 0 || !*p || (lo = nibble(*p++)) < 0)
                return fail(2, "hex input requires complete hexadecimal byte pairs");
            rc = append(data, size, &capacity, o->max_input, (uint8_t)(hi * 16 + lo));
            if (rc) return rc;
        }
    } else {
        FILE* stream = stdin;
        int ch, high = -1;
        if (strcmp(o->input, "-")) {
#ifdef _WIN32
            if (fopen_s(&stream, o->input, "rb")) stream = NULL;
#else
            stream = fopen(o->input, "rb");
#endif
            if (!stream) return fail(3, "cannot open input file");
        }
#ifdef _WIN32
        else if (_setmode(_fileno(stdin), _O_BINARY) == -1)
            return fail(3, "cannot set binary stdin mode");
#endif
        while ((ch = fgetc(stream)) != EOF) {
            if (o->hex_input) {
                int digit;
                if (high < 0 && isspace((unsigned char)ch)) continue;
                digit = nibble((unsigned char)ch);
                if (digit < 0) { rc = fail(2, "hex input requires complete hexadecimal byte pairs"); break; }
                if (high < 0) { high = digit; continue; }
                ch = high * 16 + digit;
                high = -1;
            }
            rc = append(data, size, &capacity, o->max_input, (uint8_t)ch);
            if (rc) break;
        }
        if (!rc && ferror(stream)) rc = fail(3, "cannot read input");
        if (!rc && high >= 0) rc = fail(2, "hex input requires complete hexadecimal byte pairs");
        if (stream != stdin && fclose(stream) && !rc) rc = fail(3, "cannot close input");
    }
    return rc;
}

typedef struct output_context {
    const cli::options* options;
    const uint8_t* data;
    int ber;
    cli_presentation_t presentation;
} output_context_t;

static tlv_visit_result_t print_element(const tlv_view_t* view, size_t depth,
                                        size_t offset, void* context) {
    output_context_t* out = (output_context_t*)context;
    size_t i;
    int indefinite = out->ber && out->data[offset + view->tag.size] == 0x80;
    cli_presentation_visit(&out->presentation, view, depth, indefinite);
    if (!out->options->tree && depth) return TLV_VISIT_CONTINUE;
    if (out->options->pretty) cli_presentation_prefix(&out->presentation, depth);
    else for (i = 0; i < depth; ++i) fputs("  ", stdout);
    printf("offset=%zu tag=", offset);
    if (out->presentation.color) fputs("\033[36m", stdout);
    for (i = 0; i < view->tag.size; ++i) printf("%02X", (unsigned)view->tag.data[i]);
    if (out->presentation.color) fputs("\033[0m", stdout);
    printf(" length=%" PRIu64, view->value.length);
    if (indefinite)
        fputs(" encoding=indefinite", stdout);
    fputs(" value=", stdout);
    for (i = 0; i < (size_t)view->value.length; ++i) printf("%02X", (unsigned)view->value.data[i]);
    if (out->options->profile) cli_presentation_emv(&out->presentation, view, depth, out->options->describe);
    putchar('\n');
    return ferror(stdout) ? TLV_VISIT_ERROR : TLV_VISIT_CONTINUE;
}

static const char* error_name(tlv_result_t rc) {
    switch (rc) {
#define ERROR_NAME(e) case e: return #e
        ERROR_NAME(TLV_OK);
        ERROR_NAME(TLV_ERR_BUFFER_TOO_SHORT);
        ERROR_NAME(TLV_ERR_INVALID_LENGTH);
        ERROR_NAME(TLV_ERR_NULL_ARG);
        ERROR_NAME(TLV_ERR_OUT_OF_MEMORY);
        ERROR_NAME(TLV_ERR_END_OF_BUFFER);
        ERROR_NAME(TLV_ERR_INVALID_TAG);
        ERROR_NAME(TLV_ERR_VISITOR);
        ERROR_NAME(TLV_ERR_LIMIT);
        ERROR_NAME(TLV_ERR_SCHEMA);
        ERROR_NAME(TLV_ERR_INVALID_ARG);
        ERROR_NAME(TLV_ERR_INVALID_TAG_SIZE);
        ERROR_NAME(TLV_ERR_INVALID_BYTE_ORDER);
        ERROR_NAME(TLV_ERR_OVERFLOW);
#undef ERROR_NAME
        default: return "TLV_ERR_UNKNOWN";
    }
}

/* A DOL length is a single unsigned byte, not a BER length field. No value
 * bytes follow it. Reuse the public BER tag reader without fabricating TLVs. */
static tlv_result_t walk_pdol(const uint8_t* data, size_t size,
                              const tlv_reader_format_t* format,
                              output_context_t* output, size_t* error_offset) {
    size_t pos = 0, count = 0;
    while (pos < size) {
        tlv_view_t entry;
        size_t used, start = pos, i;
        unsigned requested;
        tlv_result_t rc;
        *error_offset = pos;
        if (count == output->options->max_elements) return TLV_ERR_LIMIT;
        rc = format->read_tag(format->context, data + pos, size - pos, &entry.tag, &used);
        if (rc != TLV_OK) return rc;
        if (entry.tag.size > 2) return TLV_ERR_INVALID_TAG_SIZE;
        pos += used;
        *error_offset = pos;
        if (pos == size) return TLV_ERR_BUFFER_TOO_SHORT;
        requested = data[pos++];
        ++count;
        if (strcmp(output->options->command, "dump")) continue;
        printf("offset=%zu tag=", start);
        if (output->presentation.color) fputs("\033[36m", stdout);
        for (i = 0; i < entry.tag.size; ++i) printf("%02X", (unsigned)entry.tag.data[i]);
        if (output->presentation.color) fputs("\033[0m", stdout);
        printf(" requested-length=%u", requested);
        /* Annotation uses only the tag, never a requested length as a value view. */
        entry.value.data = NULL;
        entry.value.length = 0;
        if (output->options->profile)
            cli_presentation_emv(&output->presentation, &entry, 0, output->options->describe);
        putchar('\n');
        if (ferror(stdout)) return TLV_ERR_VISITOR;
    }
    return TLV_OK;
}

static int run(int argc, char** argv) {
    cli::options o;
    const tlv_reader_format_t* format;
    tlv_is_constructed_fn predicate = NULL;
    uint8_t* data = NULL;
    size_t size = 0, error_offset = 0;
    tlv_result_t result;
    tlv_tree_visitor_t visitor;
    output_context_t output;
    // Own the buffer across wrapper errors, which may allocate error strings.
    std::unique_ptr<uint8_t, decltype(&std::free)> input(nullptr, &std::free);
    int rc, structured;
    if (argc == 2 && !strcmp(argv[1], "--help")) { cli::options::usage(); goto flushed; }
    if (argc == 2 && !strcmp(argv[1], "--version")) {
        printf("opentlv %s\n", tlv_version_string()); goto flushed;
    }
    if (argc == 2 && !strcmp(argv[1], "formats")) { formats(); goto flushed; }
    if (argc < 2) return fail(2, "missing command; use --help");
    rc = o.parse(argc, argv);
    if (rc) return rc;
    format = select_format(o.format);
    if (!format) return fail(2, "unknown or disabled format; use opentlv formats");
    structured = !strcmp(o.format, "ber") || !strcmp(o.format, "der");
    if (o.tree && !structured) return fail(2, "--tree supports only BER and DER");
    rc = read_input(&o, &data, &size);
    input.reset(data);
    if (rc) return rc;
    output.options = &o;
    output.data = data;
    output.ber = !strcmp(o.format, "ber");
    cli_presentation_init(&output.presentation, data, size, o.color, o.pretty);
    visitor = !strcmp(o.command, "dump") ? print_element : NULL;
#if OPENTLV_FORMAT_BER
    if (structured) predicate = tlv_ber_is_constructed;
#endif
    if (o.pdol) result = walk_pdol(data, size, format, &output, &error_offset);
    else
#if OPENTLV_FORMAT_DER
    if (!strcmp(o.format, "der")) {
        tlv_der_limits_t limits = {o.max_depth, o.max_input, o.max_input, o.max_elements};
        result = tlv_der_walk(data, size, &limits, visitor, &output, &error_offset);
    } else
#endif
    {
        // The C++ walker owns the callback adapter and exposes borrowed entries.
        const auto walked = tlv::walk_tree(
            tlv::bytes(reinterpret_cast<const tlv::byte*>(data), size),
            *format, predicate, o.max_depth, o.max_elements,
            [&output, visitor](const tlv::entry& entry, size_t depth, size_t offset) {
                if (!visitor) return TLV_VISIT_CONTINUE;
                // Presentation shares this view adapter with the unwrapped DER API.
                const tlv_view_t raw = {entry.tag,
                    {reinterpret_cast<const uint8_t*>(entry.value.data()),
                     static_cast<tlv_length_t>(entry.value.size())}};
                return visitor(&raw, depth, offset, &output);
            }, &error_offset);
        result = walked ? TLV_OK : walked.error().code;
    }
    cli_presentation_restore(&output.presentation);
    if (fflush(stdout) || ferror(stdout)) return fail(3, "cannot write output");
    if (result != TLV_OK) {
        fprintf(stderr, "opentlv: %s at byte %zu: %s\n", error_name(result),
                error_offset, tlv_strerror(result));
        return result == TLV_ERR_LIMIT || result == TLV_ERR_OUT_OF_MEMORY ? 3 : 1;
    }
    return 0;
flushed:
    return fflush(stdout) || ferror(stdout) ? fail(3, "cannot write output") : 0;
}

int main(int argc, char** argv) {
    try {
        return run(argc, argv);
    } catch (const std::bad_alloc&) {
        return fail(3, "cannot allocate CLI memory");
    }
}
