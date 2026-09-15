#ifndef OPENTLV_CLI_PRESENTATION_H
#define OPENTLV_CLI_PRESENTATION_H
#include "tlv/reader/walker.h"

typedef struct cli_presentation {
    const uint8_t* data;
    size_t ends[TLV_WALK_MAX_DEPTH + 1];
    int more[TLV_WALK_MAX_DEPTH + 1];
    int contexts[TLV_WALK_MAX_DEPTH + 1];
    int color;
    unsigned long console_mode;
    unsigned int console_codepage;
    int restore_mode, restore_codepage;
} cli_presentation_t;

void cli_presentation_init(cli_presentation_t* p, const uint8_t* data,
                           size_t size, int color, int pretty);
void cli_presentation_restore(cli_presentation_t* p);
void cli_presentation_visit(cli_presentation_t* p, const tlv_view_t* view,
                            size_t depth, int indefinite);
void cli_presentation_prefix(const cli_presentation_t* p, size_t depth);
void cli_presentation_emv(const cli_presentation_t* p, const tlv_view_t* view,
                          size_t depth, int describe);
#endif
