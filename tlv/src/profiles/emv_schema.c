#include "tlv/profiles/emv_schema.h"
#include <stdint.h>

/* Tag bytes and length bounds mirror tlv/profiles/emv_tags.def; kept as
 * literals here because tlv_structure_rule_t embeds a tlv_schema_entry_t by
 * value in an immutable static table, which the dictionary's extern
 * tlv_emv_tag_* objects (ordinary runtime-linked constants) cannot initialize.
 */

/* FCI Proprietary Template (A5) children (Book 3 Table 12, non-exhaustive):
 * issuer- and kernel-specific proprietary tags are common and accepted
 * unchecked. Fields the base dictionary defines as templates recurse with an
 * unrestricted child scope (FCI Issuer Discretionary Data holds arbitrary
 * issuer-defined tags). */
static const tlv_structure_rule_t fci_proprietary_rules[] = {
    {{{{0x50}, 1}, 1, 16, 0}, 0, 1, TLV_SCHEMA_PRIMITIVE, NULL}, /* application_label */
    {{{{0x87}, 1}, 1, 1, 0}, 0, 1, TLV_SCHEMA_PRIMITIVE, NULL}, /* application_priority_indicator */
#if TLV_TAG_CAPACITY >= 2
    {{{{0x9F, 0x38}, 2}, 0, SIZE_MAX, 0}, 0, 1, TLV_SCHEMA_PRIMITIVE, NULL}, /* pdol */
    {{{{0x5F, 0x2D}, 2}, 2, 8, 0}, 0, 1, TLV_SCHEMA_PRIMITIVE, NULL}, /* language_preference */
    {{{{0x9F, 0x11}, 2}, 1, 1, 0}, 0, 1, TLV_SCHEMA_PRIMITIVE, NULL}, /* issuer_code_table_index */
    {{{{0xBF, 0x0C}, 2}, 0, 222, 0},
     0,
     1,
     TLV_SCHEMA_CONSTRUCTED,
     NULL}, /* fci_issuer_discretionary_data */
#endif
};
static const tlv_structure_schema_t fci_proprietary_schema = {
    fci_proprietary_rules, sizeof(fci_proprietary_rules) / sizeof(fci_proprietary_rules[0]),
    1 /* allow_unknown: proprietary/kernel-specific data elements */
};

/* FCI Template (6F) children (Book 3 section 11.3.4 Table 12): DF Name is
 * mandatory, FCI Proprietary Template is optional, and no other tag belongs
 * directly under 6F. */
static const tlv_structure_rule_t fci_rules[] = {
    {{{{0x84}, 1}, 5, 16, 0}, 1, 1, TLV_SCHEMA_PRIMITIVE, NULL}, /* df_name */
    {{{{0xA5}, 1}, 0, 252, 0},
     0,
     1,
     TLV_SCHEMA_CONSTRUCTED,
     &fci_proprietary_schema}, /* fci_proprietary_template */
};
static const tlv_structure_schema_t fci_schema = {fci_rules,
                                                  sizeof(fci_rules) / sizeof(fci_rules[0]), 0};

/* Application Template (61) children (Book 1 Table 8): ADF Name is
 * mandatory, Application Label and Application Priority Indicator are
 * optional. Kernel-specific discretionary data commonly follows, so unlike
 * the FCI and GPO response templates below, unknown children are accepted. */
static const tlv_structure_rule_t application_rules[] = {
    {{{{0x4F}, 1}, 5, 16, 0}, 1, 1, TLV_SCHEMA_PRIMITIVE, NULL}, /* adf_name */
    {{{{0x50}, 1}, 1, 16, 0}, 0, 1, TLV_SCHEMA_PRIMITIVE, NULL}, /* application_label */
    {{{{0x87}, 1}, 1, 1, 0}, 0, 1, TLV_SCHEMA_PRIMITIVE, NULL}, /* application_priority_indicator */
};
static const tlv_structure_schema_t application_schema = {
    application_rules, sizeof(application_rules) / sizeof(application_rules[0]), 1};

/* GPO Response Message Template Format 2 (77) children (Book 3 Table 3):
 * exactly one AIP and one AFL, nothing else. */
static const tlv_structure_rule_t gpo_response2_rules[] = {
    {{{{0x82}, 1}, 2, 2, 0}, 1, 1, TLV_SCHEMA_PRIMITIVE, NULL},   /* aip */
    {{{{0x94}, 1}, 4, 252, 0}, 1, 1, TLV_SCHEMA_PRIMITIVE, NULL}, /* afl */
};
static const tlv_structure_schema_t gpo_response2_schema = {
    gpo_response2_rules, sizeof(gpo_response2_rules) / sizeof(gpo_response2_rules[0]), 0};

/* Root: any of the modeled top-level templates may repeat (a captured trace
 * or file may hold several messages); everything else, including the
 * unmodeled Read Record Template (70), Response Message Template Format 1
 * (80), and issuer script templates, is accepted unchecked. */
static const tlv_structure_rule_t root_rules[] = {
    {{{{0x6F}, 1}, 0, 252, 0}, 0, SIZE_MAX, TLV_SCHEMA_CONSTRUCTED, &fci_schema}, /* fci_template */
    {{{{0x61}, 1}, 0, 252, 0},
     0,
     SIZE_MAX,
     TLV_SCHEMA_CONSTRUCTED,
     &application_schema}, /* application_template */
    {{{{0x77}, 1}, 0, SIZE_MAX, 0},
     0,
     SIZE_MAX,
     TLV_SCHEMA_CONSTRUCTED,
     &gpo_response2_schema}, /* response_template2 */
};
const tlv_structure_schema_t tlv_emv_structure_schema = {
    root_rules, sizeof(root_rules) / sizeof(root_rules[0]), 1};
