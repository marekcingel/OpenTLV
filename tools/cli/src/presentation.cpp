#include "presentation.hpp"
#include "tlv/config.h"
#include <iostream>
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
    char  value[32];
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

void cli_presentation_init(cli_presentation_t* p, const uint8_t* data, size_t size, int color,
                           int pretty) {
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
    std::cout.flush();
    if (p->restore_mode) SetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), p->console_mode);
    if (p->restore_codepage) SetConsoleOutputCP(p->console_codepage);
#else
    (void)p;
#endif
}

void cli_presentation_visit(cli_presentation_t* p, const tlv_view_t* view, size_t depth,
                            int indefinite) {
    size_t end = (size_t)(view->value.data - p->data) + (size_t)view->value.length;
    p->more[depth] = end + (indefinite ? 2u : 0u) < p->ends[depth];
    if (depth < TLV_WALK_MAX_DEPTH) {
        p->ends[depth + 1] = end;
#if OPENTLV_PROFILE_EMV
        p->contexts[depth + 1] =
            tlv_emv_child_context((tlv_emv_context_t)p->contexts[depth], &view->tag);
#endif
    }
}

void cli_presentation_prefix(const cli_presentation_t* p, size_t depth) {
    size_t i;
    for (i = 1; i < depth; ++i) std::cout << (p->more[i] ? "\xE2\x94\x82   " : "    ");
    if (depth)
        std::cout << (p->more[depth] ? "\xE2\x94\x9C\xE2\x94\x80\xE2\x94\x80 "
                                     : "\xE2\x94\x94\xE2\x94\x80\xE2\x94\x80 ");
}

#if OPENTLV_PROFILE_EMV
/* Presentation-only wrapper: falls back to a generic title-cased label when
 * the symbol has no curated one. Tag matching, value types and bounds come
 * from tlv itself (tlv_emv_display_label/tlv_emv_titlecase_name). */
static void display_name(const char* name) {
    char        titlecased[128];
    const char* label = tlv_emv_display_label(name);
    if (label) {
        std::cout << label;
        return;
    }
    if (tlv_emv_titlecase_name(name, titlecased, sizeof(titlecased)) == TLV_OK)
        std::cout << titlecased;
    else
        std::cout << name;
}
#endif

void cli_presentation_emv(const cli_presentation_t* p, const tlv_view_t* view, size_t depth,
                          int describe) {
#if OPENTLV_PROFILE_EMV
    const tlv_emv_definition_t* definition =
        tlv_emv_find((tlv_emv_context_t)p->contexts[depth], &view->tag);
    std::cout << " name=\"";
    if (definition)
        display_name(definition->name);
    else
        std::cout << "Unknown EMV tag in this context";
    std::cout << '"';
    if (describe && definition) {
        std::cout << " description=\"" << tlv_emv_value_kind_description(definition->value_kind)
                  << "; dictionary length: " << definition->schema->min_length;
        if (definition->schema->max_length == SIZE_MAX)
            std::cout << "..unbounded";
        else if (definition->schema->max_length != definition->schema->min_length)
            std::cout << ".." << definition->schema->max_length;
        std::cout << " bytes; step: " << definition->length_step << '"';
    }
#else
    (void)p;
    (void)view;
    (void)depth;
    (void)describe;
#endif
}
