// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "../../callback_internal.h"
#include "tlv/builtins/asn1/der_schema.h"
#include "der_validation_internal.h"
#include "asn1_values_internal.h"
#include "tlv/builtins/asn1/asn1_codec.h"
#include "tlv/size.h"
#include <string.h>

const tlv_der_schema_limits_t tlv_der_schema_default_limits = {
    {32, (size_t)16 * 1024 * 1024, (size_t)16 * 1024 * 1024, 100000}, 10000};

static tlv_result_t fail(tlv_result_t rc, size_t offset, tlv_diagnostic_t* location) {
    if (location) {
        location->code = rc;
        tlv_location_kind_t kind = location->location.kind;
        if (kind != TLV_LOCATION_SCOPE_END && kind != TLV_LOCATION_INSERTION)
            kind = TLV_LOCATION_POINT;
        tlv_diagnostic_set_location(location, TLV_LOCATION_INPUT, kind, offset, offset);
    }
    return rc;
}

static tlv_result_t missing(size_t offset, tlv_diagnostic_t* location,
                            tlv_schema_diagnostic_t* diagnostic, tlv_location_kind_t anchor) {
    if (diagnostic) {
        diagnostic->kind = TLV_SCHEMA_ISSUE_MISSING;
        diagnostic->diagnostic.location.kind = anchor;
    }
    return fail(TLV_ERR_SCHEMA, offset, location);
}

static tlv_result_t publish(tlv_result_t rc, tlv_location_domain_t domain,
                            tlv_schema_diagnostic_t* diagnostic) {
    if (diagnostic) {
        diagnostic->diagnostic.code = rc;
        if (rc != TLV_OK && diagnostic->diagnostic.location.kind != TLV_LOCATION_UNKNOWN) {
            diagnostic->diagnostic.location.domain = domain;
        }
    }
    return rc;
}

/* ITU-T X.690 identifier rule shared with builtins/asn1/der.c and
 * asn1_internal.c: EXTERNAL (8), EMBEDDED PDV (11), SEQUENCE (16), SET (17)
 * and CHARACTER STRING (29) are the only assigned universal numbers (<=36)
 * that must be constructed; DER requires every other one to stay primitive. */
static int universal_is_constructed(uint64_t number) {
    return number == 8 || number == 11 || number == 16 || number == 17 || number == 29;
}

/* A tag that owns its bytes, so it can be built, copied and sorted locally;
 * tlv_tag_t itself only borrows. */
typedef struct {
    uint8_t bytes[TLV_ASN1_TAG_MAX_SIZE];
    size_t size;
} owned_tag_t;

static tlv_tag_t owned_view(const owned_tag_t* owned) {
    return tlv_tag(owned->bytes, owned->size);
}

static tlv_result_t owned_make(tlv_asn1_class_t tag_class, int constructed, uint64_t number,
                               owned_tag_t* owned) {
    tlv_tag_t tag;
    tlv_result_t rc = tlv_der_tag_make(tag_class, constructed, number, owned->bytes, &tag);
    if (rc == TLV_OK) owned->size = tag.size;
    return rc;
}

static int tags_equal(const owned_tag_t* a, const tlv_tag_t* b) {
    return tlv_tag_equal(owned_view(a), *b);
}

/* The fixed wire identifier a SEQUENCE/SEQUENCE-OF/SET/SET-OF/UNIVERSAL type
 * carries when untagged. CHOICE and ANY have no single fixed identifier and
 * are rejected. */
static tlv_result_t kind_identifier(const tlv_der_schema_type_t* type, owned_tag_t* tag) {
    switch (type->kind) {
        case TLV_DER_SCHEMA_SEQUENCE:
        case TLV_DER_SCHEMA_SEQUENCE_OF: return owned_make(TLV_ASN1_UNIVERSAL, 1, 16, tag);
        case TLV_DER_SCHEMA_SET:
        case TLV_DER_SCHEMA_SET_OF: return owned_make(TLV_ASN1_UNIVERSAL, 1, 17, tag);
        case TLV_DER_SCHEMA_UNIVERSAL:
            return owned_make(TLV_ASN1_UNIVERSAL, universal_is_constructed(type->universal_number),
                              type->universal_number, tag);
        default: return TLV_ERR_SCHEMA;
    }
}

/* Whether an untagged instance of type is constructed on the wire. Only
 * meaningful for SEQUENCE/SEQUENCE_OF/SET/SET_OF/UNIVERSAL; CHOICE has no
 * single answer (resolved per alternative) and ANY is never implicitly
 * tagged. */
static int type_is_constructed(const tlv_der_schema_type_t* type) {
    switch (type->kind) {
        case TLV_DER_SCHEMA_SEQUENCE:
        case TLV_DER_SCHEMA_SEQUENCE_OF:
        case TLV_DER_SCHEMA_SET:
        case TLV_DER_SCHEMA_SET_OF: return 1;
        case TLV_DER_SCHEMA_UNIVERSAL: return universal_is_constructed(type->universal_number);
        default: return 0;
    }
}

/* Resolves the concrete component a wire tag matches at component's
 * position: itself, when tagged or of a kind with a fixed identifier, or one
 * of its CHOICE alternatives (recursively, depth-bounded). Returns NULL if
 * nothing matches or the bound is exceeded. The returned component always
 * has tagging != TLV_DER_TAG_NONE, or an untagged type with a fixed kind
 * (UNIVERSAL/SEQUENCE/SET/SET_OF) or is untagged ANY. */
static const tlv_der_schema_component_t* resolve_tag(const tlv_der_schema_component_t* component,
                                                     const tlv_tag_t* wire_tag, size_t depth,
                                                     const tlv_der_schema_type_t** failed,
                                                     size_t* failed_count) {
    owned_tag_t expected;
    if (depth > TLV_DER_SCHEMA_MAX_TYPE_DEPTH) return NULL;
    if (component->tagging != TLV_DER_TAG_NONE) {
        int constructed =
            component->tagging == TLV_DER_TAG_EXPLICIT ? 1 : type_is_constructed(component->type);
        if (owned_make(component->tag_class, constructed, component->tag_number, &expected) !=
            TLV_OK)
            return NULL;
        return tags_equal(&expected, wire_tag) ? component : NULL;
    }
    if (component->type->kind == TLV_DER_SCHEMA_ANY) return component;
    if (component->type->kind == TLV_DER_SCHEMA_CHOICE) {
        size_t i;
        for (i = 0; i < *failed_count; ++i)
            if (failed[i] == component->type) return NULL;
        for (i = 0; i < component->type->component_count; ++i) {
            const tlv_der_schema_component_t* resolved = resolve_tag(
                &component->type->components[i], wire_tag, depth + 1, failed, failed_count);
            if (resolved) return resolved;
        }
        if (*failed_count < TLV_DER_SCHEMA_MAX_TYPES) failed[(*failed_count)++] = component->type;
        return NULL;
    }
    if (kind_identifier(component->type, &expected) != TLV_OK) return NULL;
    return tags_equal(&expected, wire_tag) ? component : NULL;
}

/* Cache only failed untagged CHOICE resolutions. A shared type has the same
 * answer for this wire tag, regardless of the path used to reach it. */
static const tlv_der_schema_component_t* resolve_at(const tlv_der_schema_component_t* component,
                                                    const tlv_tag_t* wire_tag, size_t depth) {
    const tlv_der_schema_type_t* failed[TLV_DER_SCHEMA_MAX_TYPES];
    size_t failed_count = 0;
    return resolve_tag(component, wire_tag, depth, failed, &failed_count);
}

static int is_default_equal(const uint8_t* data, size_t elem_base, size_t elem_used,
                            const tlv_der_schema_component_t* component) {
    return component->presence == TLV_DER_DEFAULT && component->default_encoding &&
           elem_used == component->default_encoding_length &&
           memcmp(data + elem_base, component->default_encoding, elem_used) == 0;
}

/* Checks a UNIVERSAL leaf's raw content against its own optional SIZE/
 * value-range constraint, beyond tlv_asn1_validate_universal_value()'s
 * canonical DER rules. INTEGER and ENUMERATED share an identical minimal
 * two's complement wire representation (X.690 section 11.2), so
 * tlv_asn1_codec_integer's decode logic applies to either; tlv_der_schema_check()
 * (or, for a schema that skips it, the schema author) is responsible for only
 * setting value_constraint on one of those two universal numbers. */
static tlv_result_t validate_leaf_constraint(const tlv_der_schema_type_t* type, const uint8_t* data,
                                             size_t length) {
    const tlv_der_schema_leaf_constraint_t* constraint = type->constraint;
    if (!constraint) return TLV_OK;
    if (length < constraint->min_length || length > constraint->max_length) return TLV_ERR_SCHEMA;
    if (constraint->value_constraint) {
        int64_t value = 0;
        if (tlv_codec_decode(&tlv_asn1_codec_integer, data, length, &value, sizeof(value)) !=
            TLV_CODEC_OK)
            return TLV_ERR_INVALID_VALUE;
        return tlv_value_constraint_validate(constraint->value_constraint, value);
    }
    return TLV_OK;
}

/* ---- Schema self-check ---------------------------------------------- */

static tlv_result_t check_component(const tlv_der_schema_component_t* component, int in_choice) {
    if (!component || !component->type) return TLV_ERR_INVALID_SCHEMA;
    if (component->presence < TLV_DER_REQUIRED || component->presence > TLV_DER_DEFAULT ||
        component->tagging < TLV_DER_TAG_NONE || component->tagging > TLV_DER_TAG_EXPLICIT ||
        component->tag_class < TLV_ASN1_UNIVERSAL || component->tag_class > TLV_ASN1_PRIVATE)
        return TLV_ERR_INVALID_SCHEMA;
    if (in_choice && (component->presence != TLV_DER_REQUIRED || component->default_encoding))
        return TLV_ERR_INVALID_SCHEMA;
    if (component->presence == TLV_DER_DEFAULT &&
        (!component->default_encoding || !component->default_encoding_length))
        return TLV_ERR_INVALID_SCHEMA;
    if (component->tagging == TLV_DER_TAG_IMPLICIT &&
        (component->type->kind == TLV_DER_SCHEMA_CHOICE ||
         component->type->kind == TLV_DER_SCHEMA_ANY))
        return TLV_ERR_INVALID_SCHEMA;
    return TLV_OK;
}

/* Check local descriptors only. Graph identity and transparent CHOICE paths
 * are handled separately so sharing and productive recursion need no recursion
 * over the complete definition graph. */
static tlv_result_t check_type(const tlv_der_schema_type_t* type,
                               tlv_schema_definition_location_t* location) {
    if (location)
        *location = (tlv_schema_definition_location_t){TLV_SCHEMA_DEFINITION_TYPE, type, 0};
    size_t count = 0;
    const tlv_der_schema_component_t* components = NULL;
    tlv_result_t rc;
    switch (type->kind) {
        case TLV_DER_SCHEMA_UNIVERSAL:
            if (type->constraint) {
                if (type->constraint->min_length > type->constraint->max_length)
                    return TLV_ERR_INVALID_SCHEMA;
                if (type->constraint->value_constraint) {
                    if (type->universal_number != 2 && type->universal_number != 10)
                        return TLV_ERR_INVALID_SCHEMA;
                    return tlv_value_constraint_check(type->constraint->value_constraint);
                }
            }
            return TLV_OK;
        case TLV_DER_SCHEMA_ANY: return TLV_OK;
        case TLV_DER_SCHEMA_SEQUENCE:
        case TLV_DER_SCHEMA_SET:
        case TLV_DER_SCHEMA_CHOICE:
            if (type->component_count && !type->components) return TLV_ERR_INVALID_SCHEMA;
            if (type->component_count > TLV_DER_SCHEMA_MAX_COMPONENTS) return TLV_ERR_UNSUPPORTED;
            components = type->components;
            count = type->component_count;
            break;
        case TLV_DER_SCHEMA_SET_OF:
        case TLV_DER_SCHEMA_SEQUENCE_OF:
            if (!type->element || type->min_elements > type->max_elements ||
                type->element->presence != TLV_DER_REQUIRED)
                return TLV_ERR_INVALID_SCHEMA;
            components = type->element;
            count = 1;
            break;
        default: return TLV_ERR_INVALID_SCHEMA;
    }
    for (size_t i = 0; i < count; ++i) {
        const tlv_der_schema_component_t* c = &components[i];
        if (location)
            *location =
                (tlv_schema_definition_location_t){TLV_SCHEMA_DEFINITION_COMPONENT, type, i};
        rc = check_component(c, type->kind == TLV_DER_SCHEMA_CHOICE);
        if (rc != TLV_OK) return rc;
        if ((type->kind == TLV_DER_SCHEMA_SET || type->kind == TLV_DER_SCHEMA_CHOICE) &&
            c->tagging == TLV_DER_TAG_NONE && c->type->kind == TLV_DER_SCHEMA_ANY)
            return TLV_ERR_INVALID_SCHEMA;
    }
    return TLV_OK;
}

typedef struct schema_graph {
    const tlv_der_schema_type_t* types[TLV_DER_SCHEMA_MAX_TYPES];
    size_t count;
    unsigned char state[TLV_DER_SCHEMA_MAX_TYPES]; /* 0 unseen, 1 active, 2 complete */
    size_t choice_height[TLV_DER_SCHEMA_MAX_TYPES];
} schema_graph_t;

static size_t type_index(const schema_graph_t* graph, const tlv_der_schema_type_t* type) {
    size_t i;
    for (i = 0; i < graph->count; ++i)
        if (graph->types[i] == type) break;
    return i;
}

/* Only an untagged CHOICE-to-CHOICE edge remains at the same wire position.
 * Containers and explicit wrappers consume an identifier before descending.
 * Memoized heights also check longer paths to a previously completed node. */
static tlv_result_t check_choice_path(schema_graph_t* graph, size_t node, size_t depth,
                                      tlv_schema_definition_location_t* location) {
    if (location)
        *location =
            (tlv_schema_definition_location_t){TLV_SCHEMA_DEFINITION_TYPE, graph->types[node], 0};
    const tlv_der_schema_type_t* type = graph->types[node];
    size_t height = 1;
    if (graph->state[node] == 1) return TLV_ERR_INVALID_SCHEMA;
    if (graph->state[node] == 2) return TLV_OK;
    if (depth >= TLV_DER_SCHEMA_MAX_TYPE_DEPTH) return TLV_ERR_UNSUPPORTED;
    graph->state[node] = 1;
    for (size_t i = 0; i < type->component_count; ++i) {
        const tlv_der_schema_component_t* c = &type->components[i];
        if (c->tagging == TLV_DER_TAG_NONE && c->type->kind == TLV_DER_SCHEMA_CHOICE) {
            size_t child = type_index(graph, c->type);
            tlv_result_t rc = check_choice_path(graph, child, depth + 1, location);
            if (rc != TLV_OK) return rc;
            if (height < 1 + graph->choice_height[child]) height = 1 + graph->choice_height[child];
        }
    }
    if (height > TLV_DER_SCHEMA_MAX_TYPE_DEPTH) return TLV_ERR_UNSUPPORTED;
    graph->choice_height[node] = height;
    graph->state[node] = 2;
    return TLV_OK;
}

static tlv_result_t check_identifiers(const tlv_der_schema_type_t* type,
                                      tlv_schema_definition_location_t* location) {
    size_t i, j;
    if (type->kind != TLV_DER_SCHEMA_SET && type->kind != TLV_DER_SCHEMA_CHOICE) return TLV_OK;
    /* Direct components must have pairwise-distinct effective identifiers
     * (X.680 §26 for SET, §29 for CHOICE): for every component with a
     * single fixed identifier (tagged, or untagged UNIVERSAL/SEQUENCE/
     * SET/SET-OF), no other sibling may resolve that same wire tag.
     * A sibling with an untagged nested CHOICE is still checked from the
     * fixed side (as the "other" component j below) via resolve_at's own
     * CHOICE expansion, but this does not enumerate the alternatives of
     * an untagged CHOICE used as the probing component i itself against
     * its siblings -- a documented limitation of this convenience check;
     * the CHOICE's own alternatives are still checked for mutual
     * distinctness when its type is checked separately. */
    for (i = 0; i < type->component_count; ++i) {
        const tlv_der_schema_component_t* ci = &type->components[i];
        if (location)
            *location =
                (tlv_schema_definition_location_t){TLV_SCHEMA_DEFINITION_COMPONENT, type, i};
        owned_tag_t probe;
        tlv_tag_t probe_view;
        if (ci->tagging != TLV_DER_TAG_NONE) {
            int constructed =
                ci->tagging == TLV_DER_TAG_EXPLICIT ? 1 : type_is_constructed(ci->type);
            if (owned_make(ci->tag_class, constructed, ci->tag_number, &probe) != TLV_OK)
                return TLV_ERR_INVALID_SCHEMA;
        } else if (ci->type->kind == TLV_DER_SCHEMA_CHOICE) {
            continue;
        } else if (kind_identifier(ci->type, &probe) != TLV_OK) {
            return TLV_ERR_INVALID_SCHEMA;
        }
        probe_view = owned_view(&probe);
        for (j = 0; j < type->component_count; ++j) {
            if (j != i && resolve_at(&type->components[j], &probe_view, 0) != NULL)
                return TLV_ERR_INVALID_SCHEMA;
        }
    }
    return TLV_OK;
}

static tlv_result_t check_graph(const tlv_der_schema_type_t* root,
                                tlv_schema_definition_location_t* location) {
    schema_graph_t graph;
    tlv_result_t rc;
    graph.count = 1;
    graph.types[0] = root;
    memset(graph.state, 0, sizeof(graph.state));
    for (size_t node = 0; node < graph.count; ++node) {
        const tlv_der_schema_type_t* type = graph.types[node];
        const tlv_der_schema_component_t* components = NULL;
        size_t count = 0;
        rc = check_type(type, location);
        if (rc != TLV_OK) return rc;
        if (type->kind == TLV_DER_SCHEMA_SEQUENCE || type->kind == TLV_DER_SCHEMA_SET ||
            type->kind == TLV_DER_SCHEMA_CHOICE) {
            components = type->components;
            count = type->component_count;
        } else if (type->kind == TLV_DER_SCHEMA_SEQUENCE_OF ||
                   type->kind == TLV_DER_SCHEMA_SET_OF) {
            components = type->element;
            count = 1;
        }
        for (size_t i = 0; i < count; ++i) {
            const tlv_der_schema_type_t* child = components[i].type;
            if (type_index(&graph, child) < graph.count) continue;
            if (graph.count == TLV_DER_SCHEMA_MAX_TYPES) return TLV_ERR_UNSUPPORTED;
            graph.types[graph.count++] = child;
        }
    }
    /* Run before identifier resolution, which relies on finite CHOICE paths. */
    for (size_t node = 0; node < graph.count; ++node) {
        if (graph.types[node]->kind != TLV_DER_SCHEMA_CHOICE) continue;
        rc = check_choice_path(&graph, node, 0, location);
        if (rc != TLV_OK) return rc;
    }
    for (size_t node = 0; node < graph.count; ++node) {
        rc = check_identifiers(graph.types[node], location);
        if (rc != TLV_OK) return rc;
    }
    return TLV_OK;
}

tlv_result_t tlv_der_schema_check(const tlv_der_schema_type_t* root,
                                  tlv_schema_diagnostic_t* diagnostic) {
    if (diagnostic) tlv_schema_diagnostic_init(diagnostic);
    tlv_result_t rc =
        root ? check_graph(root, diagnostic ? &diagnostic->definition : NULL) : TLV_ERR_NULL_ARG;
    if (diagnostic) {
        if (rc == TLV_OK) memset(&diagnostic->definition, 0, sizeof diagnostic->definition);
        diagnostic->diagnostic.code = rc;
        if (rc == TLV_ERR_INVALID_SCHEMA) diagnostic->kind = TLV_SCHEMA_ISSUE_DEFINITION;
    }
    return rc;
}

/* ---- Schema-aware DER reader ----------------------------------------- */

/* Shared traversal state: data is the original input's base pointer, so
 * every offset threaded through the engine is absolute against it, and
 * element_count is the single running total tlv_der_read_element-style reads
 * are charged against, matching tlv_der_visit's convention. */
typedef struct der_schema_ctx {
    const uint8_t* data;
    const tlv_der_schema_limits_t* limits;
    size_t element_count;
    tlv_diagnostic_t* location;
    tlv_schema_diagnostic_t* diagnostic;
} der_schema_ctx_t;

typedef struct der_schema_frame {
    const tlv_der_schema_type_t* type;
    size_t start, end, pos;
    size_t depth;                    /* Wire depth, including EXPLICIT wrappers. */
    size_t next_component;           /* SEQUENCE */
    uint64_t seen;                   /* SET: bitmap over type->components */
    int has_prev;                    /* SET/SET_OF */
    tlv_tag_t prev_tag;              /* SET: previous element's tag */
    size_t prev_offset, prev_length; /* SET_OF: previous element's complete encoding */
    size_t element_count;            /* SET_OF/SEQUENCE_OF: elements matched so far */
} der_schema_frame_t;

static tlv_result_t read_one(der_schema_ctx_t* ctx, size_t offset, size_t size, size_t depth,
                             tlv_element_t* element, size_t* used) {
    tlv_result_t rc;
    if (depth > ctx->limits->base.max_depth || ctx->element_count == ctx->limits->base.max_elements)
        return fail(TLV_ERR_LIMIT, offset, ctx->location);
    rc = tlv_der_read_element(ctx->data + offset, size, offset, &ctx->limits->base, element, used,
                              ctx->location);
    if (rc != TLV_OK) return rc;
    ++ctx->element_count;
    return TLV_OK;
}

static tlv_visit_result_t der_schema_count_visitor(const tlv_element_t* element, size_t depth,
                                                   size_t offset, void* context) {
    (void)element;
    (void)depth;
    (void)offset;
    ++(*(size_t*)context);
    return TLV_VISIT_CONTINUE;
}

/* ANY accepts exactly one well-formed DER-TLV element without ASN.1
 * semantics; a constructed one must still have well-formed generic DER-TLV
 * children, checked with the ordinary (non-strict) generic Tree Reader under a
 * limits budget reduced by what this validation has already spent, with the
 * elements it visits folded back into the running total. */
static tlv_result_t dispatch_any(der_schema_ctx_t* ctx, size_t value_offset, size_t value_length,
                                 int constructed, size_t depth) {
    tlv_der_limits_t sub_limits;
    size_t visited = 0;
    tlv_result_t rc;
    if (!constructed) return TLV_OK;
    sub_limits.max_depth =
        depth < ctx->limits->base.max_depth ? ctx->limits->base.max_depth - depth : 0;
    sub_limits.max_input_size = ctx->limits->base.max_input_size;
    sub_limits.max_value_size = ctx->limits->base.max_value_size;
    sub_limits.max_elements = ctx->element_count < ctx->limits->base.max_elements
                                  ? ctx->limits->base.max_elements - ctx->element_count
                                  : 0;
    rc = tlv_der_visit(ctx->data + value_offset, value_length, &sub_limits,
                       der_schema_count_visitor, &visited, ctx->location);
    ctx->element_count += visited;
    if (rc != TLV_OK) {
        if (ctx->location) tlv_location_translate(&ctx->location->location, value_offset);
        return rc;
    }
    return TLV_OK;
}

static tlv_result_t handle_matched_element(der_schema_ctx_t* ctx, tlv_element_t element,
                                           size_t used, size_t elem_base,
                                           const tlv_der_schema_component_t* component,
                                           size_t depth, der_schema_frame_t* stack, int* level) {
    size_t value_length, value_offset;
    tlv_result_t rc;
    rc = tlv_size_to_native(element.value.size, &value_length);
    if (rc != TLV_OK) return fail(rc, elem_base, ctx->location);
    value_offset = elem_base + used - value_length;

    if (component->tagging == TLV_DER_TAG_EXPLICIT) {
        tlv_element_t inner = {0};
        size_t inner_used = 0;
        rc = read_one(ctx, value_offset, value_length, depth + 1, &inner, &inner_used);
        if (rc != TLV_OK) return rc;
        if (inner_used != value_length)
            return fail(TLV_ERR_INVALID_VALUE, value_offset + inner_used, ctx->location);
        if (component->type->kind == TLV_DER_SCHEMA_ANY)
            return dispatch_any(ctx, value_offset, inner_used,
                                tlv_asn1_tag_is_constructed(&inner.tag), depth + 1);
        {
            tlv_der_schema_component_t synthetic;
            const tlv_der_schema_component_t* resolved;
            synthetic.type = component->type;
            synthetic.tagging = TLV_DER_TAG_NONE;
            synthetic.tag_class = TLV_ASN1_UNIVERSAL;
            synthetic.tag_number = 0;
            synthetic.presence = TLV_DER_REQUIRED;
            synthetic.default_encoding = NULL;
            synthetic.default_encoding_length = 0;
            resolved = resolve_at(&synthetic, &inner.tag, 0);
            if (!resolved) return fail(TLV_ERR_INVALID_TAG, value_offset, ctx->location);
            return handle_matched_element(ctx, inner, inner_used, value_offset, resolved, depth + 1,
                                          stack, level);
        }
    }

    switch (component->type->kind) {
        case TLV_DER_SCHEMA_UNIVERSAL:
            rc = tlv_asn1_validate_universal_value(component->type->universal_number,
                                                   element.value.data, value_length);
            if (rc != TLV_OK) return fail(rc, value_offset, ctx->location);
            rc = validate_leaf_constraint(component->type, element.value.data, value_length);
            if (rc != TLV_OK) return fail(rc, value_offset, ctx->location);
            return TLV_OK;
        case TLV_DER_SCHEMA_ANY:
            return dispatch_any(ctx, value_offset, value_length,
                                tlv_asn1_tag_is_constructed(&element.tag), depth);
        case TLV_DER_SCHEMA_SEQUENCE:
        case TLV_DER_SCHEMA_SET:
        case TLV_DER_SCHEMA_SET_OF:
        case TLV_DER_SCHEMA_SEQUENCE_OF:
            if (depth == ctx->limits->base.max_depth)
                return fail(TLV_ERR_LIMIT, value_offset, ctx->location);
            ++*level;
            stack[*level].type = component->type;
            stack[*level].depth = depth;
            stack[*level].start = value_offset;
            stack[*level].end = value_offset + value_length;
            stack[*level].pos = value_offset;
            stack[*level].next_component = 0;
            stack[*level].seen = 0;
            stack[*level].has_prev = 0;
            stack[*level].element_count = 0;
            return TLV_OK;
        default: return fail(TLV_ERR_SCHEMA, elem_base, ctx->location);
    }
}

static tlv_result_t process_sequence(der_schema_ctx_t* ctx, der_schema_frame_t* stack, int* level) {
    der_schema_frame_t* frame = &stack[*level];
    tlv_element_t element;
    size_t used, elem_base = frame->pos;
    tlv_result_t rc;

    rc = read_one(ctx, frame->pos, frame->end - frame->pos, frame->depth + 1, &element, &used);
    if (rc != TLV_OK) return rc;
    while (frame->next_component < frame->type->component_count) {
        const tlv_der_schema_component_t* comp = &frame->type->components[frame->next_component];
        const tlv_der_schema_component_t* resolved = resolve_at(comp, &element.tag, 0);
        if (resolved) {
            if (is_default_equal(ctx->data, elem_base, used, comp))
                return fail(TLV_ERR_INVALID_VALUE, elem_base, ctx->location);
            ++frame->next_component;
            frame->pos = elem_base + used;
            return handle_matched_element(ctx, element, used, elem_base, resolved, frame->depth + 1,
                                          stack, level);
        }
        if (comp->presence == TLV_DER_REQUIRED)
            return missing(elem_base, ctx->location, ctx->diagnostic, TLV_LOCATION_INSERTION);
        ++frame->next_component;
    }
    if (frame->type->extensible) {
        /* Extension marker (X.680 "..."): every declared component is
         * already matched or skipped, so anything left over is an unknown
         * future addition -- accepted as one opaque, well-formed DER-TLV
         * element (like an ANY component) without further interpretation. */
        size_t value_length, value_offset;
        rc = tlv_size_to_native(element.value.size, &value_length);
        if (rc != TLV_OK) return fail(rc, elem_base, ctx->location);
        value_offset = elem_base + used - value_length;
        rc = dispatch_any(ctx, value_offset, value_length,
                          tlv_asn1_tag_is_constructed(&element.tag), frame->depth + 1);
        if (rc != TLV_OK) return rc;
        frame->pos = elem_base + used;
        return TLV_OK;
    }
    return fail(TLV_ERR_SCHEMA, elem_base, ctx->location);
}

static tlv_result_t process_set(der_schema_ctx_t* ctx, der_schema_frame_t* stack, int* level) {
    der_schema_frame_t* frame = &stack[*level];
    tlv_element_t element;
    size_t used, elem_base = frame->pos, i, matched_index = 0;
    tlv_result_t rc;
    const tlv_der_schema_component_t* resolved = NULL;

    rc = read_one(ctx, frame->pos, frame->end - frame->pos, frame->depth + 1, &element, &used);
    if (rc != TLV_OK) return rc;
    for (i = 0; i < frame->type->component_count; ++i) {
        const tlv_der_schema_component_t* r =
            resolve_at(&frame->type->components[i], &element.tag, 0);
        if (r) {
            resolved = r;
            matched_index = i;
            break;
        }
    }
    if (!resolved) return fail(TLV_ERR_SCHEMA, elem_base, ctx->location);
    if (frame->seen & ((uint64_t)1 << matched_index))
        return fail(TLV_ERR_SCHEMA, elem_base, ctx->location);
    if (frame->has_prev) {
        tlv_asn1_class_t pc = tlv_asn1_tag_class(&frame->prev_tag),
                         cc = tlv_asn1_tag_class(&element.tag);
        uint64_t pn = 0, cn = 0;
        int known = tlv_der_tag_number(&frame->prev_tag, &pn) == TLV_OK &&
                    tlv_der_tag_number(&element.tag, &cn) == TLV_OK;
        int ordered = known && (pc < cc || (pc == cc && pn < cn));
        if (!ordered) return fail(TLV_ERR_INVALID_VALUE, elem_base, ctx->location);
    }
    if (is_default_equal(ctx->data, elem_base, used, &frame->type->components[matched_index]))
        return fail(TLV_ERR_INVALID_VALUE, elem_base, ctx->location);
    frame->seen |= (uint64_t)1 << matched_index;
    frame->prev_tag = element.tag;
    frame->has_prev = 1;
    frame->pos = elem_base + used;
    return handle_matched_element(ctx, element, used, elem_base, resolved, frame->depth + 1, stack,
                                  level);
}

static tlv_result_t process_set_of(der_schema_ctx_t* ctx, der_schema_frame_t* stack, int* level) {
    der_schema_frame_t* frame = &stack[*level];
    tlv_element_t element;
    size_t used, elem_base = frame->pos;
    tlv_result_t rc;
    const tlv_der_schema_component_t* resolved;

    if (frame->element_count == frame->type->max_elements)
        return fail(TLV_ERR_SCHEMA, elem_base, ctx->location);
    rc = read_one(ctx, frame->pos, frame->end - frame->pos, frame->depth + 1, &element, &used);
    if (rc != TLV_OK) return rc;
    resolved = resolve_at(frame->type->element, &element.tag, 0);
    if (!resolved) return fail(TLV_ERR_SCHEMA, elem_base, ctx->location);
    if (frame->has_prev) {
        size_t common = frame->prev_length < used ? frame->prev_length : used;
        int cmp = memcmp(ctx->data + frame->prev_offset, ctx->data + elem_base, common);
        int in_order = cmp < 0 || (cmp == 0 && frame->prev_length <= used);
        if (!in_order) return fail(TLV_ERR_INVALID_VALUE, elem_base, ctx->location);
    }
    frame->prev_offset = elem_base;
    frame->prev_length = used;
    frame->has_prev = 1;
    ++frame->element_count;
    frame->pos = elem_base + used;
    return handle_matched_element(ctx, element, used, elem_base, resolved, frame->depth + 1, stack,
                                  level);
}

/* SEQUENCE OF: like SET OF, but wire order is not checked -- ASN.1 does not
 * require SEQUENCE OF elements to appear in any particular order. */
static tlv_result_t process_sequence_of(der_schema_ctx_t* ctx, der_schema_frame_t* stack,
                                        int* level) {
    der_schema_frame_t* frame = &stack[*level];
    tlv_element_t element;
    size_t used, elem_base = frame->pos;
    tlv_result_t rc;
    const tlv_der_schema_component_t* resolved;

    if (frame->element_count == frame->type->max_elements)
        return fail(TLV_ERR_SCHEMA, elem_base, ctx->location);
    rc = read_one(ctx, frame->pos, frame->end - frame->pos, frame->depth + 1, &element, &used);
    if (rc != TLV_OK) return rc;
    resolved = resolve_at(frame->type->element, &element.tag, 0);
    if (!resolved) return fail(TLV_ERR_SCHEMA, elem_base, ctx->location);
    ++frame->element_count;
    frame->pos = elem_base + used;
    return handle_matched_element(ctx, element, used, elem_base, resolved, frame->depth + 1, stack,
                                  level);
}

static tlv_result_t read_input(const uint8_t* data, size_t size, const tlv_der_schema_type_t* root,
                               const tlv_der_schema_limits_t* limits, tlv_element_t* element,
                               size_t* consumed, tlv_diagnostic_t* location,
                               tlv_schema_diagnostic_t* diagnostic) {
    der_schema_ctx_t ctx;
    der_schema_frame_t stack[TLV_DER_MAX_DEPTH + 1];
    int level = -1;
    tlv_element_t root_element;
    size_t root_used;
    tlv_result_t rc;
    tlv_der_schema_component_t synthetic;
    const tlv_der_schema_component_t* resolved;

    if (!limits) limits = &tlv_der_schema_default_limits;
    if ((!data && size) || !root || !element || !consumed) return TLV_ERR_NULL_ARG;
    if (limits->base.max_depth > TLV_DER_MAX_DEPTH) return TLV_ERR_UNSUPPORTED;
    if (size > limits->base.max_input_size) return TLV_ERR_LIMIT;
    if (!size) return missing(0, location, diagnostic, TLV_LOCATION_SCOPE_END);

    ctx.data = data;
    ctx.limits = limits;
    ctx.element_count = 0;
    ctx.location = location;
    ctx.diagnostic = diagnostic;

    rc = read_one(&ctx, 0, size, 0, &root_element, &root_used);
    if (rc != TLV_OK) return rc;

    synthetic.type = root;
    synthetic.tagging = TLV_DER_TAG_NONE;
    synthetic.tag_class = TLV_ASN1_UNIVERSAL;
    synthetic.tag_number = 0;
    synthetic.presence = TLV_DER_REQUIRED;
    synthetic.default_encoding = NULL;
    synthetic.default_encoding_length = 0;
    resolved = resolve_at(&synthetic, &root_element.tag, 0);
    if (!resolved) return fail(TLV_ERR_INVALID_TAG, 0, location);

    rc = handle_matched_element(&ctx, root_element, root_used, 0, resolved, 0, stack, &level);
    if (rc != TLV_OK) return rc;

    while (level >= 0) {
        const der_schema_frame_t* frame = &stack[level];
        if (frame->pos == frame->end) {
            tlv_result_t end_rc = TLV_OK;
            if (frame->type->kind == TLV_DER_SCHEMA_SEQUENCE) {
                size_t i;
                for (i = frame->next_component; i < frame->type->component_count; ++i)
                    if (frame->type->components[i].presence == TLV_DER_REQUIRED)
                        end_rc = missing(frame->end, location, diagnostic, TLV_LOCATION_SCOPE_END);
            } else if (frame->type->kind == TLV_DER_SCHEMA_SET) {
                size_t i;
                for (i = 0; i < frame->type->component_count; ++i)
                    if (!(frame->seen & ((uint64_t)1 << i)) &&
                        frame->type->components[i].presence == TLV_DER_REQUIRED)
                        end_rc = missing(frame->end, location, diagnostic, TLV_LOCATION_SCOPE_END);
            } else if (frame->type->kind == TLV_DER_SCHEMA_SET_OF ||
                       frame->type->kind == TLV_DER_SCHEMA_SEQUENCE_OF) {
                if (frame->element_count < frame->type->min_elements)
                    end_rc = missing(frame->end, location, diagnostic, TLV_LOCATION_SCOPE_END);
            }
            if (end_rc != TLV_OK) return end_rc;
            --level;
            continue;
        }
        switch (frame->type->kind) {
            case TLV_DER_SCHEMA_SEQUENCE: rc = process_sequence(&ctx, stack, &level); break;
            case TLV_DER_SCHEMA_SET: rc = process_set(&ctx, stack, &level); break;
            case TLV_DER_SCHEMA_SET_OF: rc = process_set_of(&ctx, stack, &level); break;
            case TLV_DER_SCHEMA_SEQUENCE_OF: rc = process_sequence_of(&ctx, stack, &level); break;
            default: rc = fail(TLV_ERR_SCHEMA, frame->pos, location); break;
        }
        if (rc != TLV_OK) return rc;
    }

    *element = root_element;
    *consumed = root_used;
    return TLV_OK;
}

/* ---- Schema-aware DER writer ------------------------------------------
 *
 * Every produced element is first composed in scratch_bytes, an arena the
 * engine bump-allocates from: a component's logical content is rendered (via
 * the callback for a leaf, or by recursively composing and, for SET/SET OF,
 * reordering already-composed children for a constructed type), then
 * wrap_and_store copies that content right after a freshly written tag and
 * length -- reusing tlv_der_write_strict itself for the header bytes and,
 * for free, a redundant but harmless re-validation that the result is
 * canonical DER. With an location output, a schema/value failure is
 * retained while composition finishes in scratch only. Its owning region and
 * relative offset follow concatenation, SET sorting and wrapping, so the final
 * location is output-relative rather than an arena address. No failed encoding
 * is published, and the successful path performs no extra callback or parse. */

typedef struct der_schema_write_ctx {
    uint8_t* arena;
    size_t arena_capacity;
    size_t arena_used;
    tlv_der_schema_encode_fn encode;
    const void* context;
    const tlv_der_schema_limits_t* limits;
    tlv_der_schema_record_t* scratch;
    size_t scratch_capacity;
    int locate_failure;
    tlv_schema_diagnostic_t* diagnostic;
    tlv_result_t failure;
    size_t failure_owner;
    size_t failure_offset;
    int failure_location_known;
} der_schema_write_ctx_t;

/* Only data/schema failures with a known framing interpretation are deferred.
 * Argument, capacity, configuration and callback failures remain fail-fast. */
static int composition_failure(tlv_result_t rc) {
    return rc == TLV_ERR_SCHEMA || rc == TLV_ERR_INVALID_VALUE || rc == TLV_ERR_INVALID_LENGTH ||
           rc == TLV_ERR_INVALID_TAG;
}

static tlv_result_t defer_failure(der_schema_write_ctx_t* wctx, tlv_result_t rc, size_t owner,
                                  size_t offset) {
    if (!wctx->locate_failure || !composition_failure(rc)) return rc;
    if (wctx->failure == TLV_OK) {
        if (wctx->diagnostic && rc == TLV_ERR_SCHEMA &&
            wctx->diagnostic->kind == TLV_SCHEMA_ISSUE_NONE)
            wctx->diagnostic->kind = TLV_SCHEMA_ISSUE_VALUE;
        wctx->failure = rc;
        wctx->failure_owner = owner;
        wctx->failure_offset = offset;
        wctx->failure_location_known = 1;
    }
    return TLV_OK;
}

static tlv_result_t defer_missing(der_schema_write_ctx_t* wctx, size_t owner,
                                  tlv_location_kind_t anchor) {
    if (wctx->diagnostic && wctx->failure == TLV_OK) {
        wctx->diagnostic->kind = TLV_SCHEMA_ISSUE_MISSING;
        wctx->diagnostic->diagnostic.location.kind = anchor;
    }
    return defer_failure(wctx, TLV_ERR_SCHEMA, owner, 0);
}

static void relocate_failure(der_schema_write_ctx_t* wctx, size_t from, size_t to, size_t prefix) {
    if (wctx->failure != TLV_OK && wctx->failure_owner == from) {
        wctx->failure_owner = to;
        if (prefix > SIZE_MAX - wctx->failure_offset)
            wctx->failure_location_known = 0;
        else
            wctx->failure_offset += prefix;
    }
}

static size_t arena_alloc(der_schema_write_ctx_t* wctx, size_t length) {
    size_t offset = wctx->arena_used;
    if (length > wctx->arena_capacity - wctx->arena_used) return (size_t)-1;
    wctx->arena_used += length;
    return offset;
}

static tlv_result_t wrap_and_store(der_schema_write_ctx_t* wctx, tlv_tag_t tag, size_t content_off,
                                   size_t content_len, size_t* out_off, size_t* out_len) {
    size_t total, new_off;
    tlv_diagnostic_t relative_error = {0};
    tlv_result_t deferred = TLV_OK;
    tlv_result_t rc;
    if (wctx->failure != TLV_OK) {
        rc = tlv_encoded_size(tag, content_len, &tlv_format_der, &total);
    } else {
        rc = tlv_der_write_strict(NULL, 0, tag, wctx->arena + content_off, content_len,
                                  &wctx->limits->base, &total, &relative_error);
        if (rc != TLV_OK && wctx->locate_failure && composition_failure(rc)) {
            deferred = rc;
            (void)defer_failure(wctx, deferred, SIZE_MAX, relative_error.location.begin);
            wctx->failure_location_known = relative_error.location.kind != TLV_LOCATION_UNKNOWN;
            rc = tlv_encoded_size(tag, content_len, &tlv_format_der, &total);
        }
    }
    if (rc != TLV_OK) return rc;
    new_off = arena_alloc(wctx, total);
    if (new_off == (size_t)-1) return TLV_ERR_BUFFER_TOO_SHORT;
    if (deferred != TLV_OK) wctx->failure_owner = new_off;
    if (wctx->failure != TLV_OK) {
        /* Generate framing even for invalid Value bytes, solely to locate the
         * retained failure. These bytes can never reach the destination. */
        rc = tlv_write(wctx->arena + new_off, total, &tlv_format_der, tag,
                       wctx->arena + content_off, content_len, out_len);
    } else {
        rc = tlv_der_write_strict(wctx->arena + new_off, total, tag, wctx->arena + content_off,
                                  content_len, &wctx->limits->base, out_len, NULL);
    }
    if (rc != TLV_OK) return rc;
    if (deferred == TLV_OK) relocate_failure(wctx, content_off, new_off, total - content_len);
    *out_off = new_off;
    return TLV_OK;
}

/* The fixed wire identifier tlv_der_schema_write must emit for component,
 * mirroring resolve_at's derivation but computed directly rather than
 * matched against a wire tag. Fails for an untagged CHOICE/ANY component,
 * which callers must not need a single identifier for (a CHOICE's own
 * alternative supplies its own; an untagged ANY has none to emit either,
 * since it is only ever written via the caller's own bytes as a sibling
 * leaf, never wrapped by this helper). */
static tlv_result_t component_tag(const tlv_der_schema_component_t* component, owned_tag_t* tag) {
    if (component->tagging != TLV_DER_TAG_NONE) {
        int constructed =
            component->tagging == TLV_DER_TAG_EXPLICIT ? 1 : type_is_constructed(component->type);
        return owned_make(component->tag_class, constructed, component->tag_number, tag);
    }
    if (component->type->kind == TLV_DER_SCHEMA_ANY ||
        component->type->kind == TLV_DER_SCHEMA_CHOICE)
        return TLV_ERR_SCHEMA;
    return kind_identifier(component->type, tag);
}

static tlv_result_t encode_at(der_schema_write_ctx_t* wctx,
                              const tlv_der_schema_component_t* component, size_t index,
                              size_t depth, size_t schema_depth, int* absent, size_t* out_off,
                              size_t* out_len);

static tlv_result_t encode_leaf_content(der_schema_write_ctx_t* wctx,
                                        const tlv_der_schema_component_t* component, size_t index,
                                        size_t* out_off, size_t* out_len) {
    size_t content_len, off, written;
    int absent = 0;
    tlv_result_t rc = wctx->encode(wctx->context, component, index, NULL, 0, &content_len, &absent);
    rc = tlv_callback_result(rc, 0);
    if (rc != TLV_OK) return rc;
    if (absent) return TLV_ERR_CALLBACK;
    off = arena_alloc(wctx, content_len);
    if (off == (size_t)-1) return TLV_ERR_BUFFER_TOO_SHORT;
    absent = 0;
    rc = wctx->encode(wctx->context, component, index, wctx->arena + off, content_len, &written,
                      &absent);
    rc = tlv_callback_result(rc, 0);
    if (rc != TLV_OK) return rc;
    if (absent || written != content_len) return TLV_ERR_CALLBACK;
    *out_off = off;
    *out_len = written;
    return TLV_OK;
}

/* SEQUENCE content: present components concatenated in declared order.
 * Fixed-size local arrays are safe here: component_count is schema-bounded
 * (<= TLV_DER_SCHEMA_MAX_COMPONENTS), never input- or caller-count-driven. */
static tlv_result_t encode_children_concat(der_schema_write_ctx_t* wctx,
                                           const tlv_der_schema_component_t* components,
                                           size_t count, size_t depth, size_t* out_off,
                                           size_t* out_len) {
    size_t offs[TLV_DER_SCHEMA_MAX_COMPONENTS], lens[TLV_DER_SCHEMA_MAX_COMPONENTS];
    size_t present = 0, i, total = 0, base, pos;
    int missing = 0;
    size_t missing_offset = 0;
    for (i = 0; i < count; ++i) {
        int component_absent = 0;
        size_t off, len;
        tlv_result_t rc =
            encode_at(wctx, &components[i], 0, depth, 0, &component_absent, &off, &len);
        if (rc != TLV_OK) return rc;
        if (component_absent) {
            if (components[i].presence == TLV_DER_REQUIRED) {
                if (wctx->failure == TLV_OK) {
                    missing = 1;
                    missing_offset = total;
                }
                rc = defer_missing(wctx, SIZE_MAX, TLV_LOCATION_INSERTION);
                if (rc != TLV_OK) return rc;
            }
            continue;
        }
        offs[present] = off;
        lens[present] = len;
        ++present;
        total += len;
    }
    base = arena_alloc(wctx, total);
    if (base == (size_t)-1) return TLV_ERR_BUFFER_TOO_SHORT;
    pos = base;
    for (i = 0; i < present; ++i) {
        memcpy(wctx->arena + pos, wctx->arena + offs[i], lens[i]);
        relocate_failure(wctx, offs[i], base, pos - base);
        pos += lens[i];
    }
    if (missing) {
        wctx->failure_owner = base;
        wctx->failure_offset = missing_offset;
    }
    *out_off = base;
    *out_len = total;
    return TLV_OK;
}

/* SET content: present components concatenated in ascending effective-tag
 * order (X.690 §11.5). Fixed-size local arrays: schema-bounded, as above. */
static tlv_result_t encode_set_content(der_schema_write_ctx_t* wctx,
                                       const tlv_der_schema_type_t* type, size_t depth,
                                       size_t* out_off, size_t* out_len) {
    size_t offs[TLV_DER_SCHEMA_MAX_COMPONENTS], lens[TLV_DER_SCHEMA_MAX_COMPONENTS];
    owned_tag_t tags[TLV_DER_SCHEMA_MAX_COMPONENTS];
    size_t present = 0, i, total = 0, base, pos;
    int missing = 0;
    for (i = 0; i < type->component_count; ++i) {
        int component_absent = 0;
        size_t off, len;
        owned_tag_t tag;
        tlv_result_t rc =
            encode_at(wctx, &type->components[i], 0, depth, 0, &component_absent, &off, &len);
        if (rc != TLV_OK) return rc;
        if (component_absent) {
            if (type->components[i].presence == TLV_DER_REQUIRED) {
                if (wctx->failure == TLV_OK) missing = 1;
                rc = defer_missing(wctx, SIZE_MAX, TLV_LOCATION_SCOPE_END);
                if (rc != TLV_OK) return rc;
            }
            continue;
        }
        rc = component_tag(&type->components[i], &tag);
        if (rc != TLV_OK) return rc;
        offs[present] = off;
        lens[present] = len;
        tags[present] = tag;
        ++present;
    }
    for (i = 1; i < present; ++i) {
        size_t off_i = offs[i], len_i = lens[i];
        owned_tag_t tag_i = tags[i];
        size_t j = i;
        while (j > 0) {
            tlv_tag_t prev_view = owned_view(&tags[j - 1]), view_i = owned_view(&tag_i);
            tlv_asn1_class_t ca = tlv_asn1_tag_class(&prev_view), cb = tlv_asn1_tag_class(&view_i);
            uint64_t na = 0, nb = 0;
            int out_of_order;
            tlv_der_tag_number(&prev_view, &na);
            tlv_der_tag_number(&view_i, &nb);
            out_of_order = ca > cb || (ca == cb && na > nb);
            if (!out_of_order) break;
            offs[j] = offs[j - 1];
            lens[j] = lens[j - 1];
            tags[j] = tags[j - 1];
            --j;
        }
        offs[j] = off_i;
        lens[j] = len_i;
        tags[j] = tag_i;
    }
    for (i = 0; i < present; ++i) total += lens[i];
    base = arena_alloc(wctx, total);
    if (base == (size_t)-1) return TLV_ERR_BUFFER_TOO_SHORT;
    pos = base;
    for (i = 0; i < present; ++i) {
        memcpy(wctx->arena + pos, wctx->arena + offs[i], lens[i]);
        relocate_failure(wctx, offs[i], base, pos - base);
        pos += lens[i];
    }
    if (missing) {
        wctx->failure_owner = base;
        wctx->failure_offset = total;
    }
    *out_off = base;
    *out_len = total;
    return TLV_OK;
}

/* SET OF content: elements produced by repeated calls to type->element's
 * callback (index 0, 1, ...) until one reports absence, then concatenated in
 * ascending complete-encoding order (X.690 §11.6). Unlike SET's schema-
 * bounded component count, the element count is caller/data-driven, so
 * records live in the caller-supplied scratch array (scratch_capacity
 * bounds it, matching tlv_der_schema_limits_t.max_set_elements). */
static tlv_result_t encode_set_of_content(der_schema_write_ctx_t* wctx,
                                          const tlv_der_schema_type_t* type, size_t depth,
                                          size_t* out_off, size_t* out_len) {
    size_t count = 0, i, total = 0, base, pos;
    int cardinality = 0;
    for (;;) {
        int element_absent = 0;
        size_t off, len;
        tlv_result_t rc =
            encode_at(wctx, type->element, count, depth, 0, &element_absent, &off, &len);
        if (rc != TLV_OK) return rc;
        if (element_absent) break;
        if (count >= wctx->scratch_capacity) return TLV_ERR_BUFFER_TOO_SHORT;
        wctx->scratch[count].offset = off;
        wctx->scratch[count].length = len;
        ++count;
        if (count > type->max_elements) {
            if (wctx->failure == TLV_OK) cardinality = 1;
            rc = defer_failure(wctx, TLV_ERR_SCHEMA, SIZE_MAX, 0);
            if (rc != TLV_OK) return rc;
        }
    }
    if (count < type->min_elements) {
        tlv_result_t rc;
        if (wctx->failure == TLV_OK) cardinality = 2;
        rc = defer_missing(wctx, SIZE_MAX, TLV_LOCATION_SCOPE_END);
        if (rc != TLV_OK) return rc;
    }
    for (i = 1; i < count; ++i) {
        tlv_der_schema_record_t cur = wctx->scratch[i];
        size_t j = i;
        while (j > 0) {
            tlv_der_schema_record_t* prev = &wctx->scratch[j - 1];
            size_t common = prev->length < cur.length ? prev->length : cur.length;
            int cmp = memcmp(wctx->arena + prev->offset, wctx->arena + cur.offset, common);
            int out_of_order = cmp > 0 || (cmp == 0 && prev->length > cur.length);
            if (!out_of_order) break;
            wctx->scratch[j] = *prev;
            --j;
        }
        wctx->scratch[j] = cur;
    }
    for (i = 0; i < count; ++i) total += wctx->scratch[i].length;
    base = arena_alloc(wctx, total);
    if (base == (size_t)-1) return TLV_ERR_BUFFER_TOO_SHORT;
    pos = base;
    for (i = 0; i < count; ++i) {
        memcpy(wctx->arena + pos, wctx->arena + wctx->scratch[i].offset, wctx->scratch[i].length);
        relocate_failure(wctx, wctx->scratch[i].offset, base, pos - base);
        if (cardinality == 1 && i == type->max_elements) wctx->failure_offset = pos - base;
        pos += wctx->scratch[i].length;
    }
    if (cardinality) {
        wctx->failure_owner = base;
        if (cardinality == 2) wctx->failure_offset = total;
    }
    *out_off = base;
    *out_len = total;
    return TLV_OK;
}

/* SEQUENCE OF content: elements produced by repeated calls to type->element's
 * callback (index 0, 1, ...) until one reports absence, then concatenated in
 * that same production order -- unlike SET OF, X.690 does not require
 * SEQUENCE OF elements to be reordered. Uses the same caller-supplied
 * scratch array as encode_set_of_content, just without the sort step. */
static tlv_result_t encode_sequence_of_content(der_schema_write_ctx_t* wctx,
                                               const tlv_der_schema_type_t* type, size_t depth,
                                               size_t* out_off, size_t* out_len) {
    size_t count = 0, i, total = 0, base, pos;
    int cardinality = 0;
    for (;;) {
        int element_absent = 0;
        size_t off, len;
        tlv_result_t rc =
            encode_at(wctx, type->element, count, depth, 0, &element_absent, &off, &len);
        if (rc != TLV_OK) return rc;
        if (element_absent) break;
        if (count >= wctx->scratch_capacity) return TLV_ERR_BUFFER_TOO_SHORT;
        wctx->scratch[count].offset = off;
        wctx->scratch[count].length = len;
        ++count;
        if (count > type->max_elements) {
            if (wctx->failure == TLV_OK) cardinality = 1;
            rc = defer_failure(wctx, TLV_ERR_SCHEMA, SIZE_MAX, 0);
            if (rc != TLV_OK) return rc;
        }
    }
    if (count < type->min_elements) {
        tlv_result_t rc;
        if (wctx->failure == TLV_OK) cardinality = 2;
        rc = defer_missing(wctx, SIZE_MAX, TLV_LOCATION_SCOPE_END);
        if (rc != TLV_OK) return rc;
    }
    for (i = 0; i < count; ++i) total += wctx->scratch[i].length;
    base = arena_alloc(wctx, total);
    if (base == (size_t)-1) return TLV_ERR_BUFFER_TOO_SHORT;
    pos = base;
    for (i = 0; i < count; ++i) {
        memcpy(wctx->arena + pos, wctx->arena + wctx->scratch[i].offset, wctx->scratch[i].length);
        relocate_failure(wctx, wctx->scratch[i].offset, base, pos - base);
        if (cardinality == 1 && i == type->max_elements) wctx->failure_offset = pos - base;
        pos += wctx->scratch[i].length;
    }
    if (cardinality) {
        wctx->failure_owner = base;
        if (cardinality == 2) wctx->failure_offset = total;
    }
    *out_off = base;
    *out_len = total;
    return TLV_OK;
}

/* Selects the first CHOICE alternative reporting presence and returns its
 * own already-wrapped bytes verbatim (an untagged CHOICE has no identifier
 * of its own; its wire representation is exactly the selected alternative's). */
static tlv_result_t encode_choice(der_schema_write_ctx_t* wctx, const tlv_der_schema_type_t* type,
                                  size_t depth, size_t schema_depth, int* absent, size_t* out_off,
                                  size_t* out_len) {
    size_t i;
    if (schema_depth > TLV_DER_SCHEMA_MAX_TYPE_DEPTH) return TLV_ERR_SCHEMA;
    for (i = 0; i < type->component_count; ++i) {
        int alt_absent = 0;
        tlv_result_t rc = encode_at(wctx, &type->components[i], 0, depth, schema_depth + 1,
                                    &alt_absent, out_off, out_len);
        if (rc != TLV_OK) return rc;
        if (!alt_absent) {
            *absent = 0;
            return TLV_OK;
        }
    }
    *absent = 1;
    return TLV_OK;
}

/* type's raw, unwrapped content: a leaf's own bytes (via the callback,
 * addressed by callback_component/index -- the real, caller-visible
 * component or SET OF element this content belongs to, never a synthetic
 * stand-in) or a constructed type's composed children. Never called for
 * CHOICE (which has no content separate from its chosen alternative's own
 * complete encoding); reaching it for CHOICE is a schema error (rejected by
 * tlv_der_schema_check, since IMPLICIT tagging of a CHOICE-typed component
 * -- the only path here that could reach it -- is invalid there too). */
static tlv_result_t produce_raw_content(der_schema_write_ctx_t* wctx,
                                        const tlv_der_schema_type_t* type,
                                        const tlv_der_schema_component_t* callback_component,
                                        size_t index, size_t depth, size_t* out_off,
                                        size_t* out_len) {
    switch (type->kind) {
        case TLV_DER_SCHEMA_UNIVERSAL: {
            tlv_result_t rc =
                encode_leaf_content(wctx, callback_component, index, out_off, out_len);
            if (rc != TLV_OK) return rc;
            rc = validate_leaf_constraint(type, wctx->arena + *out_off, *out_len);
            return rc == TLV_OK ? TLV_OK : defer_failure(wctx, rc, *out_off, 0);
        }
        case TLV_DER_SCHEMA_ANY:
            return encode_leaf_content(wctx, callback_component, index, out_off, out_len);
        case TLV_DER_SCHEMA_SEQUENCE:
            if (depth == wctx->limits->base.max_depth) return TLV_ERR_LIMIT;
            return encode_children_concat(wctx, type->components, type->component_count, depth + 1,
                                          out_off, out_len);
        case TLV_DER_SCHEMA_SET:
            if (depth == wctx->limits->base.max_depth) return TLV_ERR_LIMIT;
            return encode_set_content(wctx, type, depth + 1, out_off, out_len);
        case TLV_DER_SCHEMA_SET_OF:
            if (depth == wctx->limits->base.max_depth) return TLV_ERR_LIMIT;
            return encode_set_of_content(wctx, type, depth + 1, out_off, out_len);
        case TLV_DER_SCHEMA_SEQUENCE_OF:
            if (depth == wctx->limits->base.max_depth) return TLV_ERR_LIMIT;
            return encode_sequence_of_content(wctx, type, depth + 1, out_off, out_len);
        default: return TLV_ERR_SCHEMA;
    }
}

/* type's own complete, self-tagged encoding: this is what an untagged
 * component of type emits verbatim, and what an EXPLICIT wrapper's value
 * must contain. For CHOICE this is exactly the selected alternative's own
 * complete encoding (absent, via *absent, if none is selected); for every
 * other kind it is kind_identifier(type) wrapped around
 * produce_raw_content. */
static tlv_result_t produce_natural_encoding(der_schema_write_ctx_t* wctx,
                                             const tlv_der_schema_type_t* type,
                                             const tlv_der_schema_component_t* callback_component,
                                             size_t index, size_t depth, size_t schema_depth,
                                             int* absent, size_t* out_off, size_t* out_len) {
    owned_tag_t tag;
    size_t content_off, content_len;
    tlv_result_t rc;
    *absent = 0;
    if (type->kind == TLV_DER_SCHEMA_CHOICE)
        return encode_choice(wctx, type, depth, schema_depth, absent, out_off, out_len);
    rc = kind_identifier(type, &tag);
    if (rc != TLV_OK) return rc;
    rc = produce_raw_content(wctx, type, callback_component, index, depth, &content_off,
                             &content_len);
    if (rc != TLV_OK) return rc;
    return wrap_and_store(wctx, owned_view(&tag), content_off, content_len, out_off, out_len);
}

/* Encodes one real, caller-visible component or SET OF element (component
 * is always a pointer the caller's own schema tables own -- this function
 * never fabricates a synthetic component to re-probe the callback with, so
 * every presence probe the callback sees corresponds to something it can
 * recognize). Probes presence once; if present, dispatches by tagging mode
 * and, for a CHOICE-typed untagged component, defers entirely to
 * produce_natural_encoding (whose own CHOICE handling supplies *absent if
 * no alternative is selected). */
static tlv_result_t encode_at(der_schema_write_ctx_t* wctx,
                              const tlv_der_schema_component_t* component, size_t index,
                              size_t depth, size_t schema_depth, int* absent, size_t* out_off,
                              size_t* out_len) {
    tlv_result_t rc;
    size_t ignored_size;

    *absent = 0;
    rc = wctx->encode(wctx->context, component, index, NULL, 0, &ignored_size, absent);
    rc = tlv_callback_result(rc, 0);
    if (rc != TLV_OK) return rc;
    /* Whether an absent component/element is acceptable here is a caller
     * decision, not this function's: a plain SEQUENCE/SET component's
     * presence is checked by its caller, a SET OF element uses absence
     * purely to end iteration (checked against min_elements by
     * encode_set_of_content), and a CHOICE alternative uses it to mean "not
     * selected" (checked against the CHOICE-typed component's own presence
     * once produce_natural_encoding reports none selected, below). */
    if (*absent) return TLV_OK;

    if (component->tagging == TLV_DER_TAG_NONE) {
        rc = produce_natural_encoding(wctx, component->type, component, index, depth, schema_depth,
                                      absent, out_off, out_len);
        if (rc != TLV_OK) return rc;
    } else {
        owned_tag_t tag;
        size_t content_off, content_len;
        rc = component_tag(component, &tag);
        if (rc != TLV_OK) return rc;
        if (component->tagging == TLV_DER_TAG_EXPLICIT) {
            int inner_absent = 0;
            if (depth >= wctx->limits->base.max_depth) return TLV_ERR_LIMIT;
            rc = produce_natural_encoding(wctx, component->type, component, index, depth + 1, 0,
                                          &inner_absent, &content_off, &content_len);
            if (rc != TLV_OK) return rc;
            if (inner_absent) {
                content_off = wctx->arena_used;
                content_len = 0;
                rc = defer_missing(wctx, content_off, TLV_LOCATION_SCOPE_END);
                if (rc != TLV_OK) return rc;
            }
        } else {
            rc = produce_raw_content(wctx, component->type, component, index, depth, &content_off,
                                     &content_len);
            if (rc != TLV_OK) return rc;
        }
        rc = wrap_and_store(wctx, owned_view(&tag), content_off, content_len, out_off, out_len);
        if (rc != TLV_OK) return rc;
    }

    if (!*absent && !(wctx->failure != TLV_OK && wctx->failure_owner == *out_off) &&
        component->presence == TLV_DER_DEFAULT && component->default_encoding &&
        *out_len == component->default_encoding_length) {
        int matches_default = 1;
        if (*out_len) {
            // wctx->arena is non-NULL here: every write into it above is preceded by an
            // arena_used + n > arena_capacity capacity check, so a NULL (zero-capacity) arena
            // forces *out_len == 0, which this branch already rules out. The analyzer can't
            // fold that invariant through the recursive produce_natural_encoding()/
            // wrap_and_store() call chain. Left unnamed (not pinned to e.g.
            // unix.cstring.NullArg or core.NonNullParamChecker) since which analyzer check
            // fires here depends on the platform libc's memcmp declaration.
            matches_default =
                // NOLINTNEXTLINE
                memcmp(wctx->arena + *out_off, component->default_encoding, *out_len) == 0;
        }
        if (matches_default) *absent = 1;
    }
    return TLV_OK;
}

static tlv_result_t write_input(uint8_t* data, size_t capacity, const tlv_der_schema_type_t* root,
                                tlv_der_schema_encode_fn encode, const void* context,
                                const tlv_der_schema_limits_t* limits, uint8_t* scratch_bytes,
                                size_t scratch_bytes_capacity, tlv_der_schema_record_t* scratch,
                                size_t scratch_capacity, size_t* written,
                                tlv_diagnostic_t* location, tlv_schema_diagnostic_t* diagnostic,
                                int* located) {
    der_schema_write_ctx_t wctx;
    tlv_der_schema_component_t synthetic;
    int absent = 0;
    size_t root_off = 0, root_len = 0;
    tlv_result_t rc;

    if (!limits) limits = &tlv_der_schema_default_limits;
    if ((!data && capacity) || !root || !encode || !written ||
        (!scratch_bytes && scratch_bytes_capacity) || (!scratch && scratch_capacity))
        return TLV_ERR_NULL_ARG;
    if (limits->base.max_depth > TLV_DER_MAX_DEPTH) return TLV_ERR_UNSUPPORTED;

    wctx.arena = scratch_bytes;
    wctx.arena_capacity = scratch_bytes_capacity;
    wctx.arena_used = 0;
    wctx.encode = encode;
    wctx.context = context;
    wctx.limits = limits;
    wctx.scratch = scratch;
    wctx.scratch_capacity = scratch_capacity;
    wctx.locate_failure = diagnostic != NULL;
    wctx.diagnostic = diagnostic;
    wctx.failure = TLV_OK;
    wctx.failure_owner = SIZE_MAX;
    wctx.failure_offset = 0;
    wctx.failure_location_known = 0;

    synthetic.type = root;
    synthetic.tagging = TLV_DER_TAG_NONE;
    synthetic.tag_class = TLV_ASN1_UNIVERSAL;
    synthetic.tag_number = 0;
    synthetic.presence = TLV_DER_REQUIRED;
    synthetic.default_encoding = NULL;
    synthetic.default_encoding_length = 0;

    rc = encode_at(&wctx, &synthetic, 0, 0, 0, &absent, &root_off, &root_len);
    if (wctx.failure != TLV_OK) {
        /* A secondary callback/storage failure can prevent complete framing.
         * Preserve the original result, with no invented output location. */
        *located = rc == TLV_OK && wctx.failure_owner == root_off && wctx.failure_location_known;
        size_t offset = *located ? wctx.failure_offset : 0;
        return fail(wctx.failure, offset, location);
    }
    if (rc != TLV_OK) return rc;
    if (absent) {
        *located = 1;
        return missing(0, location, diagnostic, TLV_LOCATION_INSERTION);
    }
    if (root_len > limits->base.max_input_size) return TLV_ERR_LIMIT;
    if (data) {
        if (root_len > capacity) return TLV_ERR_BUFFER_TOO_SHORT;
        if (root_len) memcpy(data, wctx.arena + root_off, root_len);
    }
    *written = root_len;
    return TLV_OK;
}

tlv_result_t tlv_der_schema_read(const uint8_t* data, size_t size,
                                 const tlv_der_schema_type_t* root,
                                 const tlv_der_schema_limits_t* limits, tlv_element_t* element,
                                 size_t* consumed, tlv_schema_diagnostic_t* diagnostic) {
    tlv_result_t rc;
    if (diagnostic) tlv_schema_diagnostic_init(diagnostic);
    if ((!data && size) || !root || !element || !consumed)
        return publish(TLV_ERR_NULL_ARG, TLV_LOCATION_DOMAIN_UNKNOWN, diagnostic);
    rc = tlv_der_schema_check(root, diagnostic);
    if (rc != TLV_OK) return rc;
    rc = read_input(data, size, root, limits, element, consumed,
                    diagnostic ? &diagnostic->diagnostic : NULL, diagnostic);
    return publish(rc, TLV_LOCATION_INPUT, diagnostic);
}

tlv_result_t tlv_der_schema_write(uint8_t* data, size_t capacity, const tlv_der_schema_type_t* root,
                                  tlv_der_schema_encode_fn encode, const void* context,
                                  const tlv_der_schema_limits_t* limits, uint8_t* scratch_bytes,
                                  size_t scratch_bytes_capacity, tlv_der_schema_record_t* scratch,
                                  size_t scratch_capacity, size_t* written,
                                  tlv_schema_diagnostic_t* diagnostic) {
    int located = 0;
    tlv_result_t rc;
    if (diagnostic) tlv_schema_diagnostic_init(diagnostic);
    if ((!data && capacity) || !root || !encode || !written ||
        (!scratch_bytes && scratch_bytes_capacity) || (!scratch && scratch_capacity))
        return publish(TLV_ERR_NULL_ARG, TLV_LOCATION_DOMAIN_UNKNOWN, diagnostic);
    rc = tlv_der_schema_check(root, diagnostic);
    if (rc != TLV_OK) return rc;
    rc = write_input(data, capacity, root, encode, context, limits, scratch_bytes,
                     scratch_bytes_capacity, scratch, scratch_capacity, written,
                     diagnostic ? &diagnostic->diagnostic : NULL, diagnostic, &located);
    if (diagnostic && !located)
        memset(&diagnostic->diagnostic.location, 0, sizeof diagnostic->diagnostic.location);
    return publish(rc, TLV_LOCATION_OUTPUT, diagnostic);
}
