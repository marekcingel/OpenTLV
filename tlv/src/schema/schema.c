// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/schema/schema.h"
#include <string.h>

const tlv_schema_entry_t* tlv_schema_find(const tlv_schema_t* schema, const tlv_tag_t* tag) {
    size_t i;
    if (!schema || !tag || (!schema->entries && schema->count != 0)) return NULL;
    if (tag->size && !tag->data) return NULL;
    for (i = 0; i < schema->count; ++i) {
        const tlv_schema_entry_t* entry = &schema->entries[i];
        if (entry->tag.size && !entry->tag.data) continue;
        if (tlv_tag_equal(entry->tag, *tag)) return entry;
    }
    return NULL;
}

tlv_result_t tlv_schema_validate_length(const tlv_schema_entry_t* entry, size_t length) {
    if (!entry) return TLV_ERR_NULL_ARG;
    if (entry->min_length > entry->max_length) return TLV_ERR_INVALID_SCHEMA;
    if (length < entry->min_length || length > entry->max_length ||
        ((entry->flags & TLV_SCHEMA_LENGTH_ENDPOINTS) && length != entry->min_length &&
         length != entry->max_length) ||
        (entry->length_multiple && length % entry->length_multiple != 0))
        return TLV_ERR_SCHEMA;
    return TLV_OK;
}

void tlv_schema_diagnostic_init(tlv_schema_diagnostic_t* diagnostic) {
    if (!diagnostic) return;
    memset(diagnostic, 0, sizeof(*diagnostic));
}

static int group_index(const tlv_structure_schema_t* schema, uint32_t id) {
    for (size_t g = 0; g < schema->group_count; ++g)
        if (schema->groups[g].id == id) return (int)g;
    return -1;
}

static tlv_result_t check_table(const tlv_structure_schema_t* schema,
                                tlv_schema_definition_location_t* location) {
    if (location)
        *location = (tlv_schema_definition_location_t){TLV_SCHEMA_DEFINITION_TABLE, schema, 0};
    if (!schema->rules && schema->count) return TLV_ERR_INVALID_SCHEMA;
    if (!schema->groups && schema->group_count) return TLV_ERR_INVALID_SCHEMA;
    if (schema->order != TLV_SCHEMA_ORDER_ANY && schema->order != TLV_SCHEMA_ORDER_SEQUENCE)
        return TLV_ERR_INVALID_SCHEMA;
    for (size_t g = 0; g < schema->group_count; ++g) {
        const tlv_structure_group_t* group = &schema->groups[g];
        if (location)
            *location = (tlv_schema_definition_location_t){TLV_SCHEMA_DEFINITION_GROUP, schema, g};
        int has_member = 0;
        if (!group->id || group->min_occurs > group->max_occurs) return TLV_ERR_INVALID_SCHEMA;
        for (size_t h = 0; h < g; ++h)
            if (schema->groups[h].id == group->id) return TLV_ERR_INVALID_SCHEMA;
        for (size_t i = 0; i < schema->count; ++i)
            if (schema->rules[i].group == group->id) has_member = 1;
        if (!has_member) return TLV_ERR_INVALID_SCHEMA;
    }
    for (size_t i = 0; i < schema->count; ++i) {
        const tlv_structure_rule_t* rule = &schema->rules[i];
        if (location)
            *location = (tlv_schema_definition_location_t){TLV_SCHEMA_DEFINITION_RULE, schema, i};
        if (!rule->entry || !rule->entry->tag.size || !rule->entry->tag.data ||
            rule->entry->min_length > rule->entry->max_length ||
            rule->min_occurs > rule->max_occurs || rule->kind < TLV_SCHEMA_ANY ||
            rule->kind > TLV_SCHEMA_CONSTRUCTED ||
            (rule->children && rule->kind != TLV_SCHEMA_CONSTRUCTED) ||
            (rule->group && group_index(schema, rule->group) < 0) ||
            (rule->group && rule->min_occurs != 0))
            return TLV_ERR_INVALID_SCHEMA;
        for (size_t j = 0; j < i; ++j)
            if (tlv_tag_equal(rule->entry->tag, schema->rules[j].entry->tag))
                return TLV_ERR_INVALID_SCHEMA;
    }
    return TLV_OK;
}

tlv_result_t tlv_schema_check(const tlv_structure_schema_t* schema,
                              tlv_schema_diagnostic_t* diagnostic) {
    const tlv_structure_schema_t* tables[TLV_SCHEMA_MAX_TABLES];
    size_t count = 1;
    tlv_result_t rc;
    if (diagnostic) tlv_schema_diagnostic_init(diagnostic);
    if (!schema) {
        rc = TLV_ERR_NULL_ARG;
        goto done;
    }
    tables[0] = schema;
    /* Enqueue each identity once. Every queued table is checked before success,
     * including tables reached through cycles or absent optional fields. */
    for (size_t next = 0; next < count; ++next) {
        const tlv_structure_schema_t* current = tables[next];
        rc = check_table(current, diagnostic ? &diagnostic->definition : NULL);
        if (rc != TLV_OK) goto done;
        for (size_t rule = 0; rule < current->count; ++rule) {
            const tlv_structure_schema_t* child = current->rules[rule].children;
            size_t i;
            if (!child) continue;
            for (i = 0; i < count; ++i)
                if (tables[i] == child) break;
            if (i < count) continue;
            if (count == TLV_SCHEMA_MAX_TABLES) {
                rc = TLV_ERR_UNSUPPORTED;
                goto done;
            }
            tables[count++] = child;
        }
    }
    rc = TLV_OK;
done:
    if (diagnostic && rc == TLV_OK)
        memset(&diagnostic->definition, 0, sizeof diagnostic->definition);
    if (diagnostic && rc != TLV_OK) {
        diagnostic->diagnostic.code = rc;
        diagnostic->diagnostic.severity = TLV_DIAGNOSTIC_SEVERITY_ERROR;
        if (rc == TLV_ERR_INVALID_SCHEMA) diagnostic->kind = TLV_SCHEMA_ISSUE_DEFINITION;
    }
    return rc;
}

tlv_result_t tlv_schema_prepare(tlv_schema_checked_t* checked, const tlv_structure_schema_t* schema,
                                tlv_schema_diagnostic_t* diagnostic) {
    tlv_result_t rc;
    if (!checked) {
        if (diagnostic) {
            tlv_schema_diagnostic_init(diagnostic);
            diagnostic->diagnostic.code = TLV_ERR_NULL_ARG;
            diagnostic->diagnostic.severity = TLV_DIAGNOSTIC_SEVERITY_ERROR;
        }
        /* diagnostic-return: the initialized base code is set above. */
        return TLV_ERR_NULL_ARG;
    }
    checked->schema = NULL;
    rc = tlv_schema_check(schema, diagnostic);
    if (rc == TLV_OK) checked->schema = schema;
    return rc;
}
