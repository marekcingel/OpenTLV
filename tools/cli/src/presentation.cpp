#include "presentation.hpp"
#include "tlv/config.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <unistd.h>
#endif
#if OPENTLV_PROFILE_EMV
#include "tlv/profiles/emv.h"
#endif

static int environment_excludes_color(void) {
#ifdef _WIN32
    char value[32];
    DWORD length;
    SetLastError(ERROR_SUCCESS);
    length = GetEnvironmentVariableA("NO_COLOR", value, sizeof(value));
    if (length || GetLastError() != ERROR_ENVVAR_NOT_FOUND) return 1;
    length = GetEnvironmentVariableA("TERM", value, sizeof(value));
    return length && length < sizeof(value) && !strcmp(value, "dumb");
#else
    const char* term = getenv("TERM");
    return getenv("NO_COLOR") != NULL || (term && !strcmp(term, "dumb"));
#endif
}

void cli_presentation_init(cli_presentation_t* p, const uint8_t* data,
                           size_t size, int color, int pretty) {
    int terminal;
    memset(p, 0, sizeof(*p));
    p->data = data;
    p->ends[0] = size;
#ifdef _WIN32
    terminal = GetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), &p->console_mode) != 0;
#else
    terminal = isatty(STDOUT_FILENO);
    (void)pretty;
#endif
    p->color = color > 0 || (color == 0 && terminal && !environment_excludes_color());
#ifdef _WIN32
    if (terminal && p->color) {
        p->restore_mode = SetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE),
            p->console_mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0;
        if (!p->restore_mode && color == 0) p->color = 0;
    }
    if (terminal && pretty) {
        p->console_codepage = GetConsoleOutputCP();
        p->restore_codepage = SetConsoleOutputCP(CP_UTF8) != 0;
    }
#endif
}

void cli_presentation_restore(cli_presentation_t* p) {
#ifdef _WIN32
    /* Flush UTF-8 bytes before restoring the console's original encoding. */
    (void)fflush(stdout);
    if (p->restore_mode) SetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), p->console_mode);
    if (p->restore_codepage) SetConsoleOutputCP(p->console_codepage);
#else
    (void)p;
#endif
}

#if OPENTLV_PROFILE_EMV
static int child_context(int context, const tlv_tag_t* tag) {
    unsigned value = tag->data[0];
    if (tag->size == 2) value = (value << 8) | tag->data[1];
    else if (tag->size != 1) return TLV_EMV_CONTEXT_COUNT;
    if (context == TLV_EMV_CONTEXT_BASE || context == TLV_EMV_CONTEXT_BIT_GROUP) {
        if (value == 0x7F60) return TLV_EMV_CONTEXT_BIT;
    }
    if (context == TLV_EMV_CONTEXT_BASE) {
        switch (value) {
            case 0xBF4A: case 0xBF4B: return TLV_EMV_CONTEXT_BIT_GROUP;
            case 0xBF4C: return TLV_EMV_CONTEXT_BIOMETRIC_COUNTERS;
            case 0xBF4D: return TLV_EMV_CONTEXT_BIOMETRIC_ATTEMPTS;
            case 0xBF4E: return TLV_EMV_CONTEXT_BIOMETRIC_VERIFICATION;
            default: break;
        }
        /* Only known templates inherit BASE, avoiding guesses in proprietary containers. */
        if (tlv_emv_find(TLV_EMV_CONTEXT_BASE, tag)) return TLV_EMV_CONTEXT_BASE;
    }
    if (context == TLV_EMV_CONTEXT_BIT && value == 0xA1) return TLV_EMV_CONTEXT_BHT;
    if (context == TLV_EMV_CONTEXT_BHT && (value == 0xA1 || value == 0xA2))
        return TLV_EMV_CONTEXT_BHT_FORMAT;
    return TLV_EMV_CONTEXT_COUNT;
}
#endif

void cli_presentation_visit(cli_presentation_t* p, const tlv_view_t* view,
                            size_t depth, int indefinite) {
    size_t end = (size_t)(view->value.data - p->data) + (size_t)view->value.length;
    p->more[depth] = end + (indefinite ? 2u : 0u) < p->ends[depth];
    if (depth < TLV_WALK_MAX_DEPTH) {
        p->ends[depth + 1] = end;
#if OPENTLV_PROFILE_EMV
        p->contexts[depth + 1] = child_context(p->contexts[depth], &view->tag);
#endif
    }
}

void cli_presentation_prefix(const cli_presentation_t* p, size_t depth) {
    size_t i;
    for (i = 1; i < depth; ++i)
        fputs(p->more[i] ? "\xE2\x94\x82   " : "    ", stdout);
    if (depth) fputs(p->more[depth] ? "\xE2\x94\x9C\xE2\x94\x80\xE2\x94\x80 " :
                                    "\xE2\x94\x94\xE2\x94\x80\xE2\x94\x80 ", stdout);
}

#if OPENTLV_PROFILE_EMV
/* Presentation labels only; tag matching, value types and bounds come from tlv. */
static void display_name(const char* name) {
    static const struct { const char *symbol, *label; } labels[] = {
        {"pan", "Primary Account Number (PAN)"},
        {"aip", "Application Interchange Profile (AIP)"},
        {"afl", "Application File Locator (AFL)"},
        {"tvr", "Terminal Verification Results (TVR)"},
        {"tsi", "Transaction Status Information (TSI)"},
        {"atc", "Application Transaction Counter (ATC)"},
        {"df_name", "Dedicated File (DF) Name"},
        {"adf_name", "Application Dedicated File (ADF) Name"},
        {"fci_template", "File Control Information (FCI) Template"},
        {"fci_proprietary_template", "File Control Information (FCI) Proprietary Template"},
        {"iin", "Issuer Identification Number (IIN)"},
        {"sfi", "Short File Identifier (SFI)"}
    };
    size_t i;
    int initial = 1;
    for (i = 0; i < sizeof(labels) / sizeof(labels[0]); ++i)
        if (!strcmp(name, labels[i].symbol)) { fputs(labels[i].label, stdout); return; }
    for (; *name; ++name) {
        if (*name == '_') { putchar(' '); initial = 1; }
        else { putchar(initial ? toupper((unsigned char)*name) : *name); initial = 0; }
    }
}

static const char* value_description(tlv_emv_value_kind_t kind) {
    switch (kind) {
        case TLV_EMV_VALUE_BYTES: return "Raw bytes";
        case TLV_EMV_VALUE_TEXT: return "Text bytes (not necessarily UTF-8)";
        case TLV_EMV_VALUE_TEMPLATE: return "Template containing encoded data elements";
        case TLV_EMV_VALUE_NUMBER: return "Numeric value (binary or decimal BCD, tag-dependent)";
        case TLV_EMV_VALUE_FLAGS: return "Bit flags";
        case TLV_EMV_VALUE_DIGITS: return "Decimal digits";
        case TLV_EMV_VALUE_DATE: return "Date (YYMMDD)";
        case TLV_EMV_VALUE_TIME: return "Time (hhmmss)";
        case TLV_EMV_VALUE_ACCOUNT: return "Account type";
        case TLV_EMV_VALUE_CRYPTOGRAM: return "Cryptogram information";
        case TLV_EMV_VALUE_BIOMETRIC: return "Biometric type";
        case TLV_EMV_VALUE_NUMBER_LIST: return "List of numeric values";
        default: return "Unspecified representation";
    }
}
#endif

void cli_presentation_emv(const cli_presentation_t* p, const tlv_view_t* view,
                          size_t depth, int describe) {
#if OPENTLV_PROFILE_EMV
    const tlv_emv_definition_t* definition = tlv_emv_find(
        (tlv_emv_context_t)p->contexts[depth], &view->tag);
    fputs(" name=\"", stdout);
    if (definition) display_name(definition->name);
    else fputs("Unknown EMV tag in this context", stdout);
    putchar('"');
    if (describe && definition) {
        printf(" description=\"%s; dictionary length: %zu", value_description(definition->value_kind),
               definition->schema->min_length);
        if (definition->schema->max_length == SIZE_MAX) fputs("..unbounded", stdout);
        else if (definition->schema->max_length != definition->schema->min_length)
            printf("..%zu", definition->schema->max_length);
        printf(" bytes; step: %zu\"", definition->length_step);
    }
#else
    (void)p; (void)view; (void)depth; (void)describe;
#endif
}
