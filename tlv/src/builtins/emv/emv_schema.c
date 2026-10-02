// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/builtins/emv/emv_schema.h"
#include <stdint.h>

#include "dictionary_internal.h"

/* Structural contexts reference the dictionary's authoritative field Schema. */

/* FCI Proprietary Template (A5) children (Book 3 Table 12, non-exhaustive):
 * issuer- and kernel-specific proprietary tags are common and accepted
 * unchecked. Fields the base dictionary defines as templates recurse with an
 * unrestricted child scope (FCI Issuer Discretionary Data holds arbitrary
 * issuer-defined tags). */
static const tlv_structure_rule_t fci_proprietary_rules[] = {
    {&emv_base_fields[index_application_label], 0, 1, TLV_SCHEMA_PRIMITIVE, NULL, 0},
    {&emv_base_fields[index_application_priority_indicator], 0, 1, TLV_SCHEMA_PRIMITIVE, NULL, 0},
    {&emv_base_fields[index_pdol], 0, 1, TLV_SCHEMA_PRIMITIVE, NULL, 0},
    {&emv_base_fields[index_language_preference], 0, 1, TLV_SCHEMA_PRIMITIVE, NULL, 0},
    {&emv_base_fields[index_issuer_code_table_index], 0, 1, TLV_SCHEMA_PRIMITIVE, NULL, 0},
    {&emv_base_fields[index_fci_issuer_discretionary_data], 0, 1, TLV_SCHEMA_CONSTRUCTED, NULL, 0}};
static const tlv_structure_schema_t fci_proprietary_schema = {
    fci_proprietary_rules,
    sizeof(fci_proprietary_rules) / sizeof(fci_proprietary_rules[0]),
    1, /* allow_unknown: proprietary/kernel-specific data elements */
    NULL,
    0,
    TLV_SCHEMA_ORDER_ANY};

/* FCI Template (6F) children (Book 3 section 11.3.4 Table 12): DF Name is
 * mandatory, FCI Proprietary Template is optional, and no other tag belongs
 * directly under 6F. */
static const tlv_structure_rule_t fci_rules[] = {
    {&emv_base_fields[index_df_name], 1, 1, TLV_SCHEMA_PRIMITIVE, NULL, 0},
    {&emv_base_fields[index_fci_proprietary_template], 0, 1, TLV_SCHEMA_CONSTRUCTED,
     &fci_proprietary_schema, 0}};
static const tlv_structure_schema_t fci_schema = {
    fci_rules, sizeof(fci_rules) / sizeof(fci_rules[0]), 0, NULL, 0, TLV_SCHEMA_ORDER_ANY};

/* Application Template (61) children (Book 1 Table 8): ADF Name is
 * mandatory, Application Label and Application Priority Indicator are
 * optional. Kernel-specific discretionary data commonly follows, so unlike
 * the FCI and GPO response templates below, unknown children are accepted. */
static const tlv_structure_rule_t application_rules[] = {
    {&emv_base_fields[index_adf_name], 1, 1, TLV_SCHEMA_PRIMITIVE, NULL, 0},
    {&emv_base_fields[index_application_label], 0, 1, TLV_SCHEMA_PRIMITIVE, NULL, 0},
    {&emv_base_fields[index_application_priority_indicator], 0, 1, TLV_SCHEMA_PRIMITIVE, NULL, 0}};
static const tlv_structure_schema_t application_schema = {
    application_rules,   sizeof(application_rules) / sizeof(application_rules[0]), 1, NULL, 0,
    TLV_SCHEMA_ORDER_ANY};

/* GPO Response Message Template Format 2 (77) children (Book 3 Table 3):
 * exactly one AIP and one AFL, nothing else. */
static const tlv_structure_rule_t gpo_response2_rules[] = {
    {&emv_base_fields[index_aip], 1, 1, TLV_SCHEMA_PRIMITIVE, NULL, 0},
    {&emv_base_fields[index_afl], 1, 1, TLV_SCHEMA_PRIMITIVE, NULL, 0}};
static const tlv_structure_schema_t gpo_response2_schema = {
    gpo_response2_rules, sizeof(gpo_response2_rules) / sizeof(gpo_response2_rules[0]), 0, NULL, 0,
    TLV_SCHEMA_ORDER_ANY};

/* Root: any of the modeled top-level templates may repeat (a captured trace
 * or file may hold several messages); everything else, including the
 * unmodeled Read Record Template (70), Response Message Template Format 1
 * (80), and issuer script templates, is accepted unchecked. */
static const tlv_structure_rule_t root_rules[] = {
    {&emv_base_fields[index_fci_template], 0, SIZE_MAX, TLV_SCHEMA_CONSTRUCTED, &fci_schema, 0},
    {&emv_base_fields[index_application_template], 0, SIZE_MAX, TLV_SCHEMA_CONSTRUCTED,
     &application_schema, 0},
    {&emv_base_fields[index_response_template2], 0, SIZE_MAX, TLV_SCHEMA_CONSTRUCTED,
     &gpo_response2_schema, 0}};
const tlv_structure_schema_t tlv_emv_structure_schema = {
    root_rules, sizeof(root_rules) / sizeof(root_rules[0]), 1, NULL, 0, TLV_SCHEMA_ORDER_ANY};
