// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#include "tlv/schema/query.h"
#include "../query/program_internal.h"
#include <string.h>

static tlv_result_t schema_query_requirements(const tlv_schema_query_rule_t* rules, size_t count,
                                              size_t depth, size_t nodes, size_t* selector,
                                              size_t* assertion, size_t* alignment,
                                              tlv_schema_query_diagnostic_t* diagnostic);

/* A false assertion is a Schema finding: the common part carries SCHEMA and the
 * ASSERTION detail is the only cause; location and path are added by the caller. */
static void assertion_failure(tlv_query_diagnostic_t* d, tlv_tag_t tag, const char* name) {
    query_diag_init(d);
    tlv_diagnostic_init(&d->diagnostic, TLV_ERR_SCHEMA, TLV_DIAGNOSTIC_SEVERITY_ERROR);
    d->diagnostic.expected = "contextual Query assertion true";
    d->diagnostic.has_path = 1;
    d->kind = TLV_QUERY_ERROR_SCHEMA;
    d->cause = TLV_QUERY_CAUSE_SCHEMA;
    d->detail.schema.kind = TLV_SCHEMA_ISSUE_ASSERTION;
    d->detail.schema.tag = tag;
    d->detail.schema.field = name;
}

#if OPENTLV_DOCUMENT && OPENTLV_READER && OPENTLV_WRITER
tlv_result_t tlv_schema_query_validate_document(const tlv_document_t* document,
                                                const tlv_schema_query_rule_t* rules, size_t count,
                                                size_t depth, size_t nodes, size_t work,
                                                tlv_schema_query_workspace_t* w, uint8_t* values,
                                                size_t capacity,
                                                tlv_tree_writer_workspace_t* staging,
                                                tlv_schema_query_diagnostic_t* diagnostic) {
    if (!count) return TLV_OK;
    if (!document || !w || (!w->contexts && w->context_capacity)) return TLV_ERR_NULL_ARG;
    size_t a, b, alignment;
    tlv_result_t rc =
        schema_query_requirements(rules, count, depth, nodes, &a, &b, &alignment, diagnostic);
    if (rc != TLV_OK) return rc;
    if (w->selector_size < a || w->assertion_size < b) return TLV_ERR_BUFFER_TOO_SHORT;
    if (diagnostic) memset(diagnostic, 0, sizeof *diagnostic);
    for (size_t i = 0; i < count; ++i) {
        if (diagnostic) diagnostic->rule = i;
        tlv_query_diagnostic_t* detail = diagnostic ? &diagnostic->query : NULL;
        tlv_query_exec_t* exec;
        rc = tlv_query_eval_init(rules[i].context, rules[i].environment, w->selector,
                                 w->selector_size, depth, nodes, work, &exec);
        if (rc != TLV_OK)
            return query_failure(detail, rc, TLV_QUERY_ERROR_EVENTS,
                                 "valid Schema Query execution");
        rc = tlv_document_query_evaluate(document, exec, NULL, values, capacity, staging, detail);
        if (rc != TLV_OK)
            return query_failure(detail, rc, TLV_QUERY_ERROR_EVENTS,
                                 "valid Schema Query execution");
        size_t contexts = 0;
        for (;;) {
            tlv_node_t* node;
            rc = tlv_document_query_next(exec, &node);
            if (rc == TLV_END) break;
            if (rc != TLV_OK)
                return query_failure(detail, rc, TLV_QUERY_ERROR_EVENTS,
                                     "valid Schema Query execution");
            if (contexts == w->context_capacity)
                return query_limit(detail, "schema-contexts", w->context_capacity, 0, 0);
            w->contexts[contexts++].node = node;
        }
        for (size_t j = 0; j < contexts; ++j) {
            rc = tlv_query_eval_init(rules[i].assertion, rules[i].environment, w->assertion,
                                     w->assertion_size, depth, nodes, work, &exec);
            if (rc != TLV_OK)
                return query_failure(detail, rc, TLV_QUERY_ERROR_EVENTS,
                                     "valid Schema Query execution");
            rc = tlv_document_query_evaluate(document, exec, w->contexts[j].node, values, capacity,
                                             staging, detail);
            if (rc != TLV_OK)
                return query_failure(detail, rc, TLV_QUERY_ERROR_EVENTS,
                                     "valid Schema Query execution");
            tlv_query_result_t result;
            rc = tlv_query_exec_result(exec, &result);
            if (rc != TLV_OK)
                return query_failure(detail, rc, TLV_QUERY_ERROR_EVENTS,
                                     "valid Schema Query execution");
            if (!result.boolean) {
                if (diagnostic) {
                    assertion_failure(&diagnostic->query, tlv_node_tag(w->contexts[j].node),
                                      rules[i].name);
                    /* Count the complete ancestry, then fill the retained root
                     * prefix in reverse as parent links walk inward to outward. */
                    tlv_diagnostic_path_t* path = &diagnostic->query.diagnostic.path;
                    size_t parents = 0;
                    for (tlv_node_t* p = tlv_node_parent(w->contexts[j].node); p;
                         p = tlv_node_parent(p))
                        ++parents;
                    path->length =
                        parents < TLV_DIAGNOSTIC_PATH_MAX ? parents : TLV_DIAGNOSTIC_PATH_MAX;
                    path->omitted = parents - path->length;
                    for (tlv_node_t* p = tlv_node_parent(w->contexts[j].node); p;
                         p = tlv_node_parent(p)) {
                        if (--parents < path->length) path->tags[parents] = tlv_node_tag(p);
                    }
                }
                /* diagnostic-return: query.diagnostic.code is set for the failed assertion above.
                 */
                return TLV_ERR_SCHEMA;
            }
        }
    }
    return TLV_OK;
}
#endif

static tlv_result_t schema_query_requirements(const tlv_schema_query_rule_t* rules, size_t count,
                                              size_t depth, size_t nodes, size_t* selector,
                                              size_t* assertion, size_t* alignment,
                                              tlv_schema_query_diagnostic_t* diagnostic) {
    if ((!rules && count) || !selector || !assertion || !alignment) return TLV_ERR_NULL_ARG;
    size_t selected = 0, asserted = 0, aligned = 1;
    for (size_t i = 0; i < count; ++i) {
        if (!rules[i].context || !rules[i].assertion) return TLV_ERR_NULL_ARG;
        if ((uintptr_t)rules[i].context % sizeof(uint32_t) ||
            (uintptr_t)rules[i].assertion % sizeof(uint32_t))
            return TLV_ERR_INVALID_ARG;
        tlv_query_error_kind_t kind = TLV_QUERY_ERROR_NONE;
        const char* expected = NULL;
        if (!query_program_valid(rules[i].context) || !query_program_valid(rules[i].assertion)) {
            kind = TLV_QUERY_ERROR_IMAGE;
            expected = "valid Schema Query program image";
        } else if (query_public_type(query_nodes(rules[i].context)[rules[i].context->root].type) !=
                       TLV_QUERY_RESULT_NODES ||
                   query_public_type(
                       query_nodes(rules[i].assertion)[rules[i].assertion->root].type) !=
                       TLV_QUERY_RESULT_BOOL) {
            kind = TLV_QUERY_ERROR_TYPE;
            expected = "node context selector and boolean assertion";
        }
        if (kind != TLV_QUERY_ERROR_NONE) {
            if (diagnostic) {
                memset(diagnostic, 0, sizeof *diagnostic);
                diagnostic->rule = i;
            }
            return query_error_unlocated(diagnostic ? &diagnostic->query : NULL,
                                         TLV_ERR_INVALID_VALUE, kind, expected);
        }
        size_t bytes, align;
        tlv_result_t rc = tlv_query_eval_size(rules[i].context, depth, nodes, &bytes, &align);
        if (rc != TLV_OK) return rc;
        if (bytes > selected) selected = bytes;
        if (align > aligned) aligned = align;
        rc = tlv_query_eval_size(rules[i].assertion, depth, nodes, &bytes, &align);
        if (rc != TLV_OK) return rc;
        if (bytes > asserted) asserted = bytes;
        if (align > aligned) aligned = align;
    }
    *selector = selected;
    *assertion = asserted;
    *alignment = aligned;
    return TLV_OK;
}
tlv_result_t tlv_schema_query_size(const tlv_schema_query_rule_t* rules, size_t count, size_t depth,
                                   size_t nodes, size_t* selector, size_t* assertion,
                                   size_t* alignment) {
    return schema_query_requirements(rules, count, depth, nodes, selector, assertion, alignment,
                                     NULL);
}
static tlv_result_t buffer_evaluate(const uint8_t* data, size_t size, const tlv_format_t* format,
                                    tlv_query_exec_t* exec, size_t depth, size_t nodes,
                                    tlv_schema_query_workspace_t* workspace,
                                    tlv_query_diagnostic_t* diagnostic) {
    tlv_tree_reader_t reader;
    tlv_result_t rc = tlv_tree_reader_init(&reader, data, size, format, workspace->frames,
                                           workspace->frame_capacity, depth, nodes);
    if (rc != TLV_OK) {
        if (diagnostic) {
            tlv_reader_diagnostic_t failed;
            tlv_reader_diagnostic_init(&failed);
            tlv_diagnostic_init(&failed.diagnostic, rc, TLV_DIAGNOSTIC_SEVERITY_ERROR);
            query_diag_init(diagnostic);
            query_reader_failure(diagnostic, rc, &failed);
        }
        return rc;
    }
    tlv_reader_diagnostic_t original;
    for (;;) {
        tlv_tree_event_t event;
        /* Tree preflight failures leave detail untouched. Reset only the marker;
         * materialize missing detail on failure, never on the successful event path. */
        if (diagnostic) original.diagnostic.code = TLV_OK;
        rc = tlv_tree_reader_next_event_diag(&reader, &event, diagnostic ? &original : NULL);
        if (rc == TLV_END) return tlv_query_exec_finish(exec, diagnostic);
        if (rc != TLV_OK) {
            if (diagnostic) {
                if (original.diagnostic.code == TLV_OK) {
                    tlv_reader_diagnostic_init(&original);
                    tlv_diagnostic_init(&original.diagnostic, rc, TLV_DIAGNOSTIC_SEVERITY_ERROR);
                }
                query_diag_init(diagnostic);
                query_reader_failure(diagnostic, rc, &original);
            }
            return rc;
        }
        int matched;
        rc = tlv_query_exec_feed(exec, &event, &matched, diagnostic);
        if (rc != TLV_OK) return rc;
    }
}

static void context_path(const uint8_t* data, size_t size, const tlv_format_t* format, size_t depth,
                         size_t nodes, tlv_schema_query_workspace_t* workspace, size_t wanted,
                         tlv_diagnostic_path_t* path) {
    tlv_tree_reader_t reader;
    if (tlv_tree_reader_init(&reader, data, size, format, workspace->frames,
                             workspace->frame_capacity, depth, nodes) != TLV_OK)
        return;
    tlv_tag_t ancestors[TLV_DIAGNOSTIC_PATH_MAX];
    size_t ordinal = 0;
    for (;;) {
        tlv_tree_event_t event;
        if (tlv_tree_reader_next_event(&reader, &event) != TLV_OK) return;
        if (event.kind == TLV_TREE_END) continue;
        if (ordinal++ == wanted) {
            size_t count =
                event.depth < TLV_DIAGNOSTIC_PATH_MAX ? event.depth : TLV_DIAGNOSTIC_PATH_MAX;
            memcpy(path->tags, ancestors, count * sizeof(*ancestors));
            path->length = count;
            path->omitted = event.depth - count;
            return;
        }
        if (event.depth < TLV_DIAGNOSTIC_PATH_MAX) ancestors[event.depth] = event.element.tag;
    }
}
tlv_result_t tlv_schema_query_validate_buffer(const uint8_t* data, size_t size,
                                              const tlv_format_t* format,
                                              const tlv_schema_query_rule_t* rules, size_t count,
                                              size_t depth, size_t nodes, size_t work,
                                              tlv_schema_query_workspace_t* w,
                                              tlv_schema_query_diagnostic_t* diagnostic) {
    if (!count) return TLV_OK;
    if ((!data && size) || !format || !w || (!w->contexts && w->context_capacity))
        return TLV_ERR_NULL_ARG;
    size_t selector_size, assertion_size, alignment;
    tlv_result_t rc = schema_query_requirements(rules, count, depth, nodes, &selector_size,
                                                &assertion_size, &alignment, diagnostic);
    if (rc != TLV_OK) return rc;
    if (!w->selector || !w->assertion || (uintptr_t)w->selector % alignment ||
        (uintptr_t)w->assertion % alignment)
        return TLV_ERR_INVALID_ARG;
    if (w->selector_size < selector_size || w->assertion_size < assertion_size)
        return TLV_ERR_BUFFER_TOO_SHORT;
    for (size_t i = 0; i < count; ++i)
        if (rules[i].context->level == TLV_QUERY_D || rules[i].assertion->level == TLV_QUERY_D)
            return TLV_ERR_UNSUPPORTED;
    if (diagnostic) memset(diagnostic, 0, sizeof *diagnostic);
    for (size_t i = 0; i < count; ++i) {
        if (diagnostic) diagnostic->rule = i;
        tlv_query_diagnostic_t* detail = diagnostic ? &diagnostic->query : NULL;
        tlv_query_exec_t* exec;
        rc = tlv_query_eval_init(rules[i].context, rules[i].environment, w->selector,
                                 w->selector_size, depth, nodes, work, &exec);
        if (rc != TLV_OK)
            return query_failure(detail, rc, TLV_QUERY_ERROR_EVENTS,
                                 "valid Schema Query execution");
        rc = buffer_evaluate(data, size, format, exec, depth, nodes, w, detail);
        if (rc != TLV_OK)
            return query_failure(detail, rc, TLV_QUERY_ERROR_EVENTS,
                                 "valid Schema Query execution");
        size_t contexts = 0;
        for (;;) {
            tlv_tree_event_t event;
            size_t ordinal;
            rc = tlv_query_result_next_ordinal(exec, &event, &ordinal);
            if (rc == TLV_END) break;
            if (rc != TLV_OK)
                return query_failure(detail, rc, TLV_QUERY_ERROR_EVENTS,
                                     "valid Schema Query execution");
            if (contexts == w->context_capacity)
                return query_limit(detail, "schema-contexts", w->context_capacity, 0, 0);
            w->contexts[contexts].ordinal = ordinal;
            w->contexts[contexts++].event = event;
        }
        for (size_t j = 0; j < contexts; ++j) {
            rc = tlv_query_eval_init(rules[i].assertion, rules[i].environment, w->assertion,
                                     w->assertion_size, depth, nodes, work, &exec);
            if (rc != TLV_OK)
                return query_failure(detail, rc, TLV_QUERY_ERROR_EVENTS,
                                     "valid Schema Query execution");
            rc = tlv_query_exec_context(exec, w->contexts[j].ordinal);
            if (rc != TLV_OK)
                return query_failure(detail, rc, TLV_QUERY_ERROR_EVENTS,
                                     "valid Schema Query execution");
            rc = buffer_evaluate(data, size, format, exec, depth, nodes, w, detail);
            if (rc != TLV_OK)
                return query_failure(detail, rc, TLV_QUERY_ERROR_EVENTS,
                                     "valid Schema Query execution");
            tlv_query_result_t result;
            rc = tlv_query_exec_result(exec, &result);
            if (rc != TLV_OK)
                return query_failure(detail, rc, TLV_QUERY_ERROR_EVENTS,
                                     "valid Schema Query execution");
            if (!result.boolean) {
                if (diagnostic) {
                    assertion_failure(&diagnostic->query, w->contexts[j].event.element.tag,
                                      rules[i].name);
                    if (w->contexts[j].event.source.data)
                        tlv_diagnostic_set_location(
                            &diagnostic->query.diagnostic, TLV_LOCATION_INPUT, TLV_LOCATION_POINT,
                            w->contexts[j].event.offset, w->contexts[j].event.offset);
                    context_path(data, size, format, depth, nodes, w, w->contexts[j].ordinal,
                                 &diagnostic->query.diagnostic.path);
                }
                /* diagnostic-return: query.diagnostic.code is set for the failed assertion above.
                 */
                return TLV_ERR_SCHEMA;
            }
        }
    }
    return TLV_OK;
}
