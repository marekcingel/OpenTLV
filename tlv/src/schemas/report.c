#include "tlv/schemas/schema.h"
#include "tlv/reader/reader.h"
#include "tlv/reader/walker.h"
#include "tlv/length.h"
#include <string.h>

static int same_tag(const tlv_tag_t* a, const tlv_tag_t* b) {
    return a->size == b->size && memcmp(a->data, b->data, a->size) == 0;
}

typedef struct frame {
    const tlv_structure_schema_t* schema;
    size_t start, end, pos;
    tlv_tag_t tag; /* Tag of the enclosing element; unused for the root frame. */
    size_t offset; /* Offset of the enclosing element; unused for the root frame. */
    int checked;
} frame_t;

typedef struct collector {
    tlv_schema_report_t* report;
    const frame_t* frames;
    size_t depth;
} collector_t;

/* Records one violation. The path is the enclosing frames' tags followed by
 * `tag`; a NULL `offset` means none is available. */
static void add_issue(collector_t* c, tlv_schema_issue_kind_t kind, const tlv_tag_t* tag,
                      const size_t* offset) {
    tlv_schema_report_t* report = c->report;
    tlv_schema_issue_t* issue;
    if (report->count++ >= report->capacity) return;
    issue = &report->issues[report->count - 1];
    memset(issue, 0, sizeof(*issue));
    issue->kind = kind;
    for (size_t i = 1; i <= c->depth; ++i) issue->path[issue->path_length++] = c->frames[i].tag;
    issue->path[issue->path_length++] = *tag;
    if (offset) {
        issue->has_offset = 1;
        issue->offset = *offset;
    }
}

static tlv_result_t check_table(const tlv_structure_schema_t* schema) {
    if (!schema->rules && schema->count) return TLV_ERR_INVALID_ARG;
    for (size_t i = 0; i < schema->count; ++i) {
        const tlv_structure_rule_t* rule = &schema->rules[i];
        if (!rule->entry.tag.size || rule->entry.tag.size > TLV_TAG_CAPACITY ||
            rule->entry.min_length > rule->entry.max_length ||
            rule->min_occurs > rule->max_occurs || rule->kind < TLV_SCHEMA_ANY ||
            rule->kind > TLV_SCHEMA_CONSTRUCTED ||
            (rule->children && rule->kind != TLV_SCHEMA_CONSTRUCTED))
            return TLV_ERR_INVALID_ARG;
        for (size_t j = 0; j < i; ++j)
            if (same_tag(&rule->entry.tag, &schema->rules[j].entry.tag)) return TLV_ERR_INVALID_ARG;
    }
    return TLV_OK;
}

/* Checks the rule table of a scope and its occurrence counts. */
static tlv_result_t check_scope(const uint8_t* data, const tlv_reader_format_t* format,
                                collector_t* c, const frame_t* frame) {
    tlv_result_t rc = check_table(frame->schema);
    if (rc != TLV_OK) return rc;
    for (size_t i = 0; i < frame->schema->count; ++i) {
        const tlv_structure_rule_t* rule = &frame->schema->rules[i];
        size_t count = 0, pos = frame->start;
        while (pos < frame->end) {
            tlv_view_t view;
            size_t used;
            rc = tlv_read(data + pos, frame->end - pos, format, &view, &used);
            if (rc != TLV_OK) return rc;
            if (same_tag(&rule->entry.tag, &view.tag) && ++count > rule->max_occurs)
                add_issue(c, TLV_SCHEMA_ISSUE_DUPLICATE, &view.tag, &pos);
            pos += used;
        }
        if (count < rule->min_occurs)
            add_issue(c, TLV_SCHEMA_ISSUE_MISSING, &rule->entry.tag,
                      c->depth ? &frame->offset : NULL);
    }
    return TLV_OK;
}

static tlv_result_t validate_all(const uint8_t* data, size_t size,
                                 const tlv_reader_format_t* format,
                                 tlv_is_constructed_fn is_constructed,
                                 const tlv_structure_schema_t* schema, size_t max_depth,
                                 size_t max_elements, tlv_schema_unknown_policy_t unknown,
                                 tlv_schema_report_t* report, size_t* error_offset) {
    frame_t stack[TLV_SCHEMA_PATH_MAX];
    collector_t c = {report, stack, 0};
    tlv_result_t rc = tlv_walk_tree(data, size, format, is_constructed, max_depth, max_elements,
                                    NULL, NULL, error_offset);
    if (rc != TLV_OK) return rc;
    memset(stack, 0, sizeof(stack));
    stack[0].schema = schema;
    stack[0].end = size;
    for (;;) {
        frame_t* frame = &stack[c.depth];
        const tlv_structure_schema_t* current = frame->schema;
        if (!frame->checked) {
            rc = check_scope(data, format, &c, frame);
            if (rc != TLV_OK) return rc;
            frame->checked = 1;
        }
        if (frame->pos == frame->end) {
            if (!c.depth) break;
            --c.depth;
            continue;
        }
        {
            tlv_view_t view;
            size_t used, pos = frame->pos, value_length;
            const tlv_structure_rule_t* rule = NULL;
            int constructed, kind_ok;
            rc = tlv_read(data + pos, frame->end - pos, format, &view, &used);
            if (rc != TLV_OK) return rc;
            frame->pos += used;
            for (size_t i = 0; i < current->count; ++i)
                if (same_tag(&current->rules[i].entry.tag, &view.tag)) {
                    rule = &current->rules[i];
                    break;
                }
            if (!rule) {
                if (unknown == TLV_SCHEMA_UNKNOWN_REJECT ||
                    (unknown == TLV_SCHEMA_UNKNOWN_BY_SCHEMA && !current->allow_unknown))
                    add_issue(&c, TLV_SCHEMA_ISSUE_UNEXPECTED, &view.tag, &pos);
                continue;
            }
            rc = tlv_length_to_size(view.value.length, &value_length);
            if (rc != TLV_OK) return rc;
            if (tlv_schema_validate_length(&rule->entry, value_length) != TLV_OK)
                add_issue(&c, TLV_SCHEMA_ISSUE_LENGTH, &view.tag, &pos);
            constructed = is_constructed && is_constructed(format->context, &view.tag);
            kind_ok = !((rule->kind == TLV_SCHEMA_PRIMITIVE && constructed) ||
                        (rule->kind == TLV_SCHEMA_CONSTRUCTED && !constructed));
            if (!kind_ok) add_issue(&c, TLV_SCHEMA_ISSUE_KIND, &view.tag, &pos);
            if (kind_ok && rule->children) {
                size_t start = (size_t)(view.value.data - data);
                if (c.depth + 1 >= TLV_SCHEMA_PATH_MAX) {
                    if (error_offset) *error_offset = pos;
                    return TLV_ERR_LIMIT;
                }
                ++c.depth;
                stack[c.depth] =
                    (frame_t){rule->children, start, start + value_length, start, view.tag, pos, 0};
            }
        }
    }
    return report->count ? TLV_ERR_SCHEMA : TLV_OK;
}

tlv_result_t tlv_schema_validate_all(const uint8_t* data, size_t size,
                                     const tlv_reader_format_t* format,
                                     tlv_is_constructed_fn is_constructed,
                                     const tlv_structure_schema_t* schema, size_t max_depth,
                                     size_t max_elements, tlv_schema_unknown_policy_t unknown,
                                     tlv_schema_report_t* report, size_t* error_offset) {
    tlv_result_t rc;
    if (!report) return TLV_ERR_NULL_ARG;
    report->count = 0;
    if (!schema || (!report->issues && report->capacity)) return TLV_ERR_NULL_ARG;
    if (unknown < TLV_SCHEMA_UNKNOWN_BY_SCHEMA || unknown > TLV_SCHEMA_UNKNOWN_REJECT)
        return TLV_ERR_INVALID_ARG;
    rc = validate_all(data, size, format, is_constructed, schema, max_depth, max_elements, unknown,
                      report, error_offset);
    if (rc != TLV_OK && rc != TLV_ERR_SCHEMA) report->count = 0;
    return rc;
}

const char* tlv_schema_issue_kind_string(tlv_schema_issue_kind_t kind) {
    switch (kind) {
        case TLV_SCHEMA_ISSUE_MISSING: return "missing";
        case TLV_SCHEMA_ISSUE_DUPLICATE: return "duplicate";
        case TLV_SCHEMA_ISSUE_UNEXPECTED: return "unexpected";
        case TLV_SCHEMA_ISSUE_KIND: return "kind";
        case TLV_SCHEMA_ISSUE_LENGTH: return "length";
    }
    return "unknown";
}

tlv_result_t tlv_schema_issue_path_string(const tlv_schema_issue_t* issue, char* out,
                                          size_t capacity, size_t* length) {
    static const char hex[] = "0123456789ABCDEF";
    size_t needed = 0;
    if (!issue || (!out && capacity)) return TLV_ERR_NULL_ARG;
    if (!issue->path_length || issue->path_length > TLV_SCHEMA_PATH_MAX) return TLV_ERR_INVALID_ARG;
    for (size_t i = 0; i < issue->path_length; ++i) {
        const tlv_tag_t* tag = &issue->path[i];
        if (!tag->size || tag->size > TLV_TAG_CAPACITY) return TLV_ERR_INVALID_ARG;
        for (size_t j = 0; j < tag->size; ++j) {
            if (needed + 2 < capacity) {
                out[needed] = hex[tag->data[j] >> 4];
                out[needed + 1] = hex[tag->data[j] & 0x0F];
            }
            needed += 2;
        }
        if (i + 1 < issue->path_length) {
            if (needed + 1 < capacity) out[needed] = '/';
            ++needed;
        }
    }
    if (length) *length = needed;
    if (needed + 1 > capacity) {
        if (capacity) out[0] = '\0';
        return TLV_ERR_BUFFER_TOO_SHORT;
    }
    out[needed] = '\0';
    return TLV_OK;
}
