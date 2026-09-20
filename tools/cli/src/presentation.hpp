#ifndef OPENTLV_CLI_PRESENTATION_H
#define OPENTLV_CLI_PRESENTATION_H
#include <string>
#include "tlv/reader/walker.h"

// Structured EMV dictionary metadata for one element, shared by the text
// renderer (cli_presentation_emv, below) and the CLI's JSON output so both
// present the same lookup without duplicating it. `known` is false for a tag
// with no dictionary entry in the element's context, in which case `name`
// and `description` are unset.
struct cli_emv_info {
    bool        known = false;
    std::string name;
    bool        has_description = false;
    std::string description;
};

// Human-readable label for an EMV dictionary symbol (curated when available,
// otherwise title-cased). Shared by dump annotations and the tag command.
// Available only when the EMV profile is enabled.
std::string cli_emv_display_name(const char* name);

typedef struct cli_presentation {
    const uint8_t* data;
    size_t         ends[TLV_WALK_MAX_DEPTH + 1];
    int            more[TLV_WALK_MAX_DEPTH + 1];
    int            contexts[TLV_WALK_MAX_DEPTH + 1];
    int            color;
    unsigned long  console_mode;
    unsigned int   console_codepage;
    int            restore_mode, restore_codepage;
} cli_presentation_t;

void cli_presentation_init(cli_presentation_t* p, const uint8_t* data, size_t size, int color,
                           int pretty);
void cli_presentation_restore(cli_presentation_t* p);
void cli_presentation_visit(cli_presentation_t* p, const tlv_view_t* view, size_t depth,
                            int indefinite);
void cli_presentation_prefix(const cli_presentation_t* p, size_t depth);
void cli_presentation_emv(const cli_presentation_t* p, const tlv_view_t* view, size_t depth,
                          int describe);
cli_emv_info cli_presentation_emv_info(const cli_presentation_t* p, const tlv_view_t* view,
                                       size_t depth, int describe);
#endif
