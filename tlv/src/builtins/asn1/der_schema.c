#include "tlv/builtins/asn1/der_schema.h"
#include "der_profile_internal.h"
#include "der_values_internal.h"
#include "tlv/length.h"
#include <string.h>

const tlv_der_schema_limits_t tlv_der_schema_default_limits = {
    {32, (size_t)16 * 1024 * 1024, (size_t)16 * 1024 * 1024, 100000}, 10000};

static tlv_result_t fail(tlv_result_t rc, size_t offset, size_t* error_offset) {
    if (error_offset) *error_offset = offset;
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

/* The fixed wire identifier a SEQUENCE/SET/SET-OF/UNIVERSAL type carries when
 * untagged. CHOICE and ANY have no single fixed identifier and are rejected. */
static tlv_result_t kind_identifier(const tlv_der_schema_type_t* type, owned_tag_t* tag) {
    switch (type->kind) {
        case TLV_DER_SCHEMA_SEQUENCE: return owned_make(TLV_ASN1_UNIVERSAL, 1, 16, tag);
        case TLV_DER_SCHEMA_SET:
        case TLV_DER_SCHEMA_SET_OF: return owned_make(TLV_ASN1_UNIVERSAL, 1, 17, tag);
        case TLV_DER_SCHEMA_UNIVERSAL:
            return owned_make(TLV_ASN1_UNIVERSAL, universal_is_constructed(type->universal_number),
                              type->universal_number, tag);
        default: return TLV_ERR_SCHEMA;
    }
}

/* Whether an untagged instance of type is constructed on the wire. Only
 * meaningful for SEQUENCE/SET/SET_OF/UNIVERSAL; CHOICE has no single answer
 * (resolved per alternative) and ANY is never implicitly tagged. */
static int type_is_constructed(const tlv_der_schema_type_t* type) {
    switch (type->kind) {
        case TLV_DER_SCHEMA_SEQUENCE:
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
static const tlv_der_schema_component_t* resolve_at(const tlv_der_schema_component_t* component,
                                                    const tlv_tag_t* wire_tag, size_t depth) {
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
        for (i = 0; i < component->type->component_count; ++i) {
            const tlv_der_schema_component_t* resolved =
                resolve_at(&component->type->components[i], wire_tag, depth + 1);
            if (resolved) return resolved;
        }
        return NULL;
    }
    if (kind_identifier(component->type, &expected) != TLV_OK) return NULL;
    return tags_equal(&expected, wire_tag) ? component : NULL;
}

static int is_default_equal(const uint8_t* data, size_t elem_base, size_t elem_used,
                            const tlv_der_schema_component_t* component) {
    return component->presence == TLV_DER_DEFAULT && component->default_encoding &&
           elem_used == component->default_encoding_length &&
           memcmp(data + elem_base, component->default_encoding, elem_used) == 0;
}

/* ---- Schema self-check ---------------------------------------------- */

static tlv_result_t check_component(const tlv_der_schema_component_t* component, int in_choice,
                                    size_t depth);

static tlv_result_t check_type(const tlv_der_schema_type_t* type, size_t depth) {
    size_t i, j;
    tlv_result_t rc;
    if (!type) return TLV_ERR_SCHEMA;
    if (depth > TLV_DER_SCHEMA_MAX_TYPE_DEPTH) return TLV_ERR_SCHEMA;
    switch (type->kind) {
        case TLV_DER_SCHEMA_UNIVERSAL:
        case TLV_DER_SCHEMA_ANY: return TLV_OK;
        case TLV_DER_SCHEMA_SEQUENCE:
            if (type->component_count > TLV_DER_SCHEMA_MAX_COMPONENTS) return TLV_ERR_SCHEMA;
            for (i = 0; i < type->component_count; ++i) {
                rc = check_component(&type->components[i], 0, depth);
                if (rc != TLV_OK) return rc;
            }
            return TLV_OK;
        case TLV_DER_SCHEMA_SET:
        case TLV_DER_SCHEMA_CHOICE:
            if (type->component_count > TLV_DER_SCHEMA_MAX_COMPONENTS) return TLV_ERR_SCHEMA;
            for (i = 0; i < type->component_count; ++i) {
                const tlv_der_schema_component_t* c = &type->components[i];
                rc = check_component(c, type->kind == TLV_DER_SCHEMA_CHOICE, depth);
                if (rc != TLV_OK) return rc;
                /* An untagged ANY component has no fixed identifier (it matches
                 * any tag); that wildcard is only unambiguous as a SEQUENCE
                 * component, where position rather than tag disambiguates it. */
                if (c->tagging == TLV_DER_TAG_NONE && c->type->kind == TLV_DER_SCHEMA_ANY)
                    return TLV_ERR_SCHEMA;
            }
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
             * distinctness when its type is visited recursively above. */
            for (i = 0; i < type->component_count; ++i) {
                const tlv_der_schema_component_t* ci = &type->components[i];
                owned_tag_t probe;
                tlv_tag_t probe_view;
                if (ci->tagging != TLV_DER_TAG_NONE) {
                    int constructed =
                        ci->tagging == TLV_DER_TAG_EXPLICIT ? 1 : type_is_constructed(ci->type);
                    if (owned_make(ci->tag_class, constructed, ci->tag_number, &probe) != TLV_OK)
                        return TLV_ERR_SCHEMA;
                } else if (ci->type->kind == TLV_DER_SCHEMA_CHOICE) {
                    continue;
                } else if (kind_identifier(ci->type, &probe) != TLV_OK) {
                    return TLV_ERR_SCHEMA;
                }
                probe_view = owned_view(&probe);
                for (j = 0; j < type->component_count; ++j) {
                    if (j != i && resolve_at(&type->components[j], &probe_view, 0) != NULL)
                        return TLV_ERR_SCHEMA;
                }
            }
            return TLV_OK;
        case TLV_DER_SCHEMA_SET_OF:
            if (!type->element) return TLV_ERR_SCHEMA;
            if (type->min_elements > type->max_elements) return TLV_ERR_SCHEMA;
            if (type->element->presence != TLV_DER_REQUIRED) return TLV_ERR_SCHEMA;
            return check_component(type->element, 0, depth);
        default: return TLV_ERR_SCHEMA;
    }
}

static tlv_result_t check_component(const tlv_der_schema_component_t* component, int in_choice,
                                    size_t depth) {
    if (!component || !component->type) return TLV_ERR_SCHEMA;
    if (in_choice && (component->presence != TLV_DER_REQUIRED || component->default_encoding))
        return TLV_ERR_SCHEMA;
    if (component->presence == TLV_DER_DEFAULT &&
        (!component->default_encoding || !component->default_encoding_length))
        return TLV_ERR_SCHEMA;
    if (component->tagging == TLV_DER_TAG_IMPLICIT &&
        (component->type->kind == TLV_DER_SCHEMA_CHOICE ||
         component->type->kind == TLV_DER_SCHEMA_ANY))
        return TLV_ERR_SCHEMA;
    return check_type(component->type, depth + 1);
}

tlv_result_t tlv_der_schema_check(const tlv_der_schema_type_t* root, size_t* error_offset) {
    if (!root) return fail(TLV_ERR_NULL_ARG, 0, error_offset);
    return fail(check_type(root, 0), 0, error_offset);
}

/* ---- Schema-aware DER reader ----------------------------------------- */

/* Shared traversal state: data is the original input's base pointer, so
 * every offset threaded through the engine is absolute against it, and
 * element_count is the single running total tlv_der_read_entry-style reads
 * are charged against, matching tlv_der_walk's convention. */
typedef struct der_schema_ctx {
    const uint8_t* data;
    const tlv_der_schema_limits_t* limits;
    size_t element_count;
    size_t* error_offset;
} der_schema_ctx_t;

typedef struct der_schema_frame {
    const tlv_der_schema_type_t* type;
    size_t start, end, pos;
    size_t next_component;           /* SEQUENCE */
    uint64_t seen;                   /* SET: bitmap over type->components */
    int has_prev;                    /* SET/SET_OF */
    tlv_tag_t prev_tag;              /* SET: previous element's tag */
    size_t prev_offset, prev_length; /* SET_OF: previous element's complete encoding */
    size_t element_count;            /* SET_OF: elements matched so far */
} der_schema_frame_t;

static tlv_result_t read_one(der_schema_ctx_t* ctx, size_t offset, size_t size, size_t depth,
                             tlv_view_t* view, size_t* used) {
    tlv_result_t rc;
    if (depth > ctx->limits->base.max_depth || ctx->element_count == ctx->limits->base.max_elements)
        return fail(TLV_ERR_LIMIT, offset, ctx->error_offset);
    rc = tlv_der_read_entry(ctx->data + offset, size, offset, &ctx->limits->base, view, used,
                            ctx->error_offset);
    if (rc != TLV_OK) return rc;
    ++ctx->element_count;
    return TLV_OK;
}

static tlv_visit_result_t der_schema_count_visitor(const tlv_view_t* view, size_t depth,
                                                   size_t offset, void* context) {
    (void)view;
    (void)depth;
    (void)offset;
    ++(*(size_t*)context);
    return TLV_VISIT_CONTINUE;
}

/* ANY accepts exactly one well-formed DER-TLV element without ASN.1
 * semantics; a constructed one must still have well-formed generic DER-TLV
 * children, checked with the ordinary (non-strict) generic walker under a
 * limits budget reduced by what this validation has already spent, with the
 * elements it visits folded back into the running total. */
static tlv_result_t dispatch_any(der_schema_ctx_t* ctx, size_t value_offset, size_t value_length,
                                 int constructed, size_t depth) {
    tlv_der_limits_t sub_limits;
    size_t sub_offset = 0, visited = 0;
    tlv_result_t rc;
    if (!constructed) return TLV_OK;
    sub_limits.max_depth =
        depth < ctx->limits->base.max_depth ? ctx->limits->base.max_depth - depth : 0;
    sub_limits.max_input_size = ctx->limits->base.max_input_size;
    sub_limits.max_value_size = ctx->limits->base.max_value_size;
    sub_limits.max_elements = ctx->element_count < ctx->limits->base.max_elements
                                  ? ctx->limits->base.max_elements - ctx->element_count
                                  : 0;
    rc = tlv_der_walk(ctx->data + value_offset, value_length, &sub_limits, der_schema_count_visitor,
                      &visited, &sub_offset);
    ctx->element_count += visited;
    if (rc != TLV_OK) return fail(rc, value_offset + sub_offset, ctx->error_offset);
    return TLV_OK;
}

static tlv_result_t handle_matched_element(der_schema_ctx_t* ctx, tlv_view_t view, size_t used,
                                           size_t elem_base,
                                           const tlv_der_schema_component_t* component,
                                           size_t depth, size_t schema_depth,
                                           der_schema_frame_t* stack, int* level) {
    size_t value_length, value_offset;
    tlv_result_t rc;
    rc = tlv_length_to_size(view.value.length, &value_length);
    if (rc != TLV_OK) return fail(rc, elem_base, ctx->error_offset);
    value_offset = elem_base + used - value_length;

    if (component->tagging == TLV_DER_TAG_EXPLICIT) {
        tlv_view_t inner = {0};
        size_t inner_used = 0;
        if (schema_depth > TLV_DER_SCHEMA_MAX_TYPE_DEPTH)
            return fail(TLV_ERR_SCHEMA, elem_base, ctx->error_offset);
        rc = read_one(ctx, value_offset, value_length, depth + 1, &inner, &inner_used);
        if (rc != TLV_OK) return rc;
        if (inner_used != value_length)
            return fail(TLV_ERR_INVALID_VALUE, value_offset + inner_used, ctx->error_offset);
        if (component->type->kind == TLV_DER_SCHEMA_ANY)
            return dispatch_any(ctx, value_offset, inner_used,
                                tlv_der_tag_is_constructed(&inner.tag), depth + 1);
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
            if (!resolved) return fail(TLV_ERR_INVALID_TAG, value_offset, ctx->error_offset);
            return handle_matched_element(ctx, inner, inner_used, value_offset, resolved, depth + 1,
                                          schema_depth + 1, stack, level);
        }
    }

    switch (component->type->kind) {
        case TLV_DER_SCHEMA_UNIVERSAL:
            rc = tlv_der_validate_universal_value(component->type->universal_number,
                                                  view.value.data, value_length);
            if (rc != TLV_OK) return fail(rc, value_offset, ctx->error_offset);
            return TLV_OK;
        case TLV_DER_SCHEMA_ANY:
            return dispatch_any(ctx, value_offset, value_length,
                                tlv_der_tag_is_constructed(&view.tag), depth);
        case TLV_DER_SCHEMA_SEQUENCE:
        case TLV_DER_SCHEMA_SET:
        case TLV_DER_SCHEMA_SET_OF:
            if (depth == ctx->limits->base.max_depth)
                return fail(TLV_ERR_LIMIT, value_offset, ctx->error_offset);
            ++*level;
            stack[*level].type = component->type;
            stack[*level].start = value_offset;
            stack[*level].end = value_offset + value_length;
            stack[*level].pos = value_offset;
            stack[*level].next_component = 0;
            stack[*level].seen = 0;
            stack[*level].has_prev = 0;
            stack[*level].element_count = 0;
            return TLV_OK;
        default: return fail(TLV_ERR_SCHEMA, elem_base, ctx->error_offset);
    }
}

static tlv_result_t process_sequence(der_schema_ctx_t* ctx, der_schema_frame_t* stack, int* level) {
    der_schema_frame_t* frame = &stack[*level];
    tlv_view_t view;
    size_t used, elem_base = frame->pos;
    tlv_result_t rc;

    rc = read_one(ctx, frame->pos, frame->end - frame->pos, *level + 1, &view, &used);
    if (rc != TLV_OK) return rc;
    while (frame->next_component < frame->type->component_count) {
        const tlv_der_schema_component_t* comp = &frame->type->components[frame->next_component];
        const tlv_der_schema_component_t* resolved = resolve_at(comp, &view.tag, 0);
        if (resolved) {
            if (is_default_equal(ctx->data, elem_base, used, comp))
                return fail(TLV_ERR_INVALID_VALUE, elem_base, ctx->error_offset);
            ++frame->next_component;
            frame->pos = elem_base + used;
            return handle_matched_element(ctx, view, used, elem_base, resolved, *level + 1, 0,
                                          stack, level);
        }
        if (comp->presence == TLV_DER_REQUIRED)
            return fail(TLV_ERR_SCHEMA, elem_base, ctx->error_offset);
        ++frame->next_component;
    }
    return fail(TLV_ERR_SCHEMA, elem_base, ctx->error_offset);
}

static tlv_result_t process_set(der_schema_ctx_t* ctx, der_schema_frame_t* stack, int* level) {
    der_schema_frame_t* frame = &stack[*level];
    tlv_view_t view;
    size_t used, elem_base = frame->pos, i, matched_index = 0;
    tlv_result_t rc;
    const tlv_der_schema_component_t* resolved = NULL;

    rc = read_one(ctx, frame->pos, frame->end - frame->pos, *level + 1, &view, &used);
    if (rc != TLV_OK) return rc;
    for (i = 0; i < frame->type->component_count; ++i) {
        const tlv_der_schema_component_t* r = resolve_at(&frame->type->components[i], &view.tag, 0);
        if (r) {
            resolved = r;
            matched_index = i;
            break;
        }
    }
    if (!resolved) return fail(TLV_ERR_SCHEMA, elem_base, ctx->error_offset);
    if (frame->seen & ((uint64_t)1 << matched_index))
        return fail(TLV_ERR_SCHEMA, elem_base, ctx->error_offset);
    if (frame->has_prev) {
        tlv_asn1_class_t pc = tlv_der_tag_class(&frame->prev_tag),
                         cc = tlv_der_tag_class(&view.tag);
        uint64_t pn = 0, cn = 0;
        int known = tlv_der_tag_number(&frame->prev_tag, &pn) == TLV_OK &&
                    tlv_der_tag_number(&view.tag, &cn) == TLV_OK;
        int ordered = known && (pc < cc || (pc == cc && pn < cn));
        if (!ordered) return fail(TLV_ERR_INVALID_VALUE, elem_base, ctx->error_offset);
    }
    if (is_default_equal(ctx->data, elem_base, used, &frame->type->components[matched_index]))
        return fail(TLV_ERR_INVALID_VALUE, elem_base, ctx->error_offset);
    frame->seen |= (uint64_t)1 << matched_index;
    frame->prev_tag = view.tag;
    frame->has_prev = 1;
    frame->pos = elem_base + used;
    return handle_matched_element(ctx, view, used, elem_base, resolved, *level + 1, 0, stack,
                                  level);
}

static tlv_result_t process_set_of(der_schema_ctx_t* ctx, der_schema_frame_t* stack, int* level) {
    der_schema_frame_t* frame = &stack[*level];
    tlv_view_t view;
    size_t used, elem_base = frame->pos;
    tlv_result_t rc;
    const tlv_der_schema_component_t* resolved;

    if (frame->element_count == frame->type->max_elements)
        return fail(TLV_ERR_SCHEMA, elem_base, ctx->error_offset);
    rc = read_one(ctx, frame->pos, frame->end - frame->pos, *level + 1, &view, &used);
    if (rc != TLV_OK) return rc;
    resolved = resolve_at(frame->type->element, &view.tag, 0);
    if (!resolved) return fail(TLV_ERR_SCHEMA, elem_base, ctx->error_offset);
    if (frame->has_prev) {
        size_t common = frame->prev_length < used ? frame->prev_length : used;
        int cmp = memcmp(ctx->data + frame->prev_offset, ctx->data + elem_base, common);
        int in_order = cmp < 0 || (cmp == 0 && frame->prev_length <= used);
        if (!in_order) return fail(TLV_ERR_INVALID_VALUE, elem_base, ctx->error_offset);
    }
    frame->prev_offset = elem_base;
    frame->prev_length = used;
    frame->has_prev = 1;
    ++frame->element_count;
    frame->pos = elem_base + used;
    return handle_matched_element(ctx, view, used, elem_base, resolved, *level + 1, 0, stack,
                                  level);
}

tlv_result_t tlv_der_schema_read(const uint8_t* data, size_t size,
                                 const tlv_der_schema_type_t* root,
                                 const tlv_der_schema_limits_t* limits, tlv_view_t* view,
                                 size_t* consumed, size_t* error_offset) {
    der_schema_ctx_t ctx;
    der_schema_frame_t stack[TLV_DER_MAX_DEPTH + 1];
    int level = -1;
    tlv_view_t root_view;
    size_t root_used;
    tlv_result_t rc;
    tlv_der_schema_component_t synthetic;
    const tlv_der_schema_component_t* resolved;

    if (!limits) limits = &tlv_der_schema_default_limits;
    if ((!data && size) || !root || !view || !consumed)
        return fail(TLV_ERR_NULL_ARG, 0, error_offset);
    if (limits->base.max_depth > TLV_DER_MAX_DEPTH || size > limits->base.max_input_size)
        return fail(TLV_ERR_LIMIT, 0, error_offset);
    if (!size) return fail(TLV_ERR_END_OF_BUFFER, 0, error_offset);

    ctx.data = data;
    ctx.limits = limits;
    ctx.element_count = 0;
    ctx.error_offset = error_offset;

    rc = read_one(&ctx, 0, size, 0, &root_view, &root_used);
    if (rc != TLV_OK) return rc;

    synthetic.type = root;
    synthetic.tagging = TLV_DER_TAG_NONE;
    synthetic.tag_class = TLV_ASN1_UNIVERSAL;
    synthetic.tag_number = 0;
    synthetic.presence = TLV_DER_REQUIRED;
    synthetic.default_encoding = NULL;
    synthetic.default_encoding_length = 0;
    resolved = resolve_at(&synthetic, &root_view.tag, 0);
    if (!resolved) return fail(TLV_ERR_INVALID_TAG, 0, error_offset);

    rc = handle_matched_element(&ctx, root_view, root_used, 0, resolved, 0, 0, stack, &level);
    if (rc != TLV_OK) return rc;

    while (level >= 0) {
        const der_schema_frame_t* frame = &stack[level];
        if (frame->pos == frame->end) {
            tlv_result_t end_rc = TLV_OK;
            if (frame->type->kind == TLV_DER_SCHEMA_SEQUENCE) {
                size_t i;
                for (i = frame->next_component; i < frame->type->component_count; ++i)
                    if (frame->type->components[i].presence == TLV_DER_REQUIRED)
                        end_rc = fail(TLV_ERR_SCHEMA, frame->end, error_offset);
            } else if (frame->type->kind == TLV_DER_SCHEMA_SET) {
                size_t i;
                for (i = 0; i < frame->type->component_count; ++i)
                    if (!(frame->seen & ((uint64_t)1 << i)) &&
                        frame->type->components[i].presence == TLV_DER_REQUIRED)
                        end_rc = fail(TLV_ERR_SCHEMA, frame->end, error_offset);
            } else if (frame->type->kind == TLV_DER_SCHEMA_SET_OF) {
                if (frame->element_count < frame->type->min_elements)
                    end_rc = fail(TLV_ERR_SCHEMA, frame->end, error_offset);
            }
            if (end_rc != TLV_OK) return end_rc;
            --level;
            continue;
        }
        switch (frame->type->kind) {
            case TLV_DER_SCHEMA_SEQUENCE: rc = process_sequence(&ctx, stack, &level); break;
            case TLV_DER_SCHEMA_SET: rc = process_set(&ctx, stack, &level); break;
            case TLV_DER_SCHEMA_SET_OF: rc = process_set_of(&ctx, stack, &level); break;
            default: rc = fail(TLV_ERR_SCHEMA, frame->pos, error_offset); break;
        }
        if (rc != TLV_OK) return rc;
    }

    *view = root_view;
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
 * canonical DER. Once composed, a region's bytes never move again, so error
 * offsets from this internal composition are not meaningful positions in
 * the eventual output and are reported as 0, matching tlv_der_write's own
 * convention for configuration errors. */

typedef struct der_schema_write_ctx {
    uint8_t* arena;
    size_t arena_capacity;
    size_t arena_used;
    tlv_der_schema_encode_fn encode;
    const void* context;
    const tlv_der_schema_limits_t* limits;
    tlv_der_schema_record_t* scratch;
    size_t scratch_capacity;
} der_schema_write_ctx_t;

static size_t arena_alloc(der_schema_write_ctx_t* wctx, size_t length) {
    size_t offset = wctx->arena_used;
    if (length > wctx->arena_capacity - wctx->arena_used) return (size_t)-1;
    wctx->arena_used += length;
    return offset;
}

static tlv_result_t wrap_and_store(der_schema_write_ctx_t* wctx, tlv_tag_t tag, size_t content_off,
                                   size_t content_len, size_t* out_off, size_t* out_len) {
    size_t total, new_off;
    tlv_result_t rc = tlv_der_write_strict(NULL, 0, tag, wctx->arena + content_off, content_len,
                                           &wctx->limits->base, &total, NULL);
    if (rc != TLV_OK) return rc;
    new_off = arena_alloc(wctx, total);
    if (new_off == (size_t)-1) return TLV_ERR_LIMIT;
    rc = tlv_der_write_strict(wctx->arena + new_off, total, tag, wctx->arena + content_off,
                              content_len, &wctx->limits->base, out_len, NULL);
    if (rc != TLV_OK) return rc;
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
    if (rc != TLV_OK) return rc;
    if (absent) return TLV_ERR_SCHEMA;
    off = arena_alloc(wctx, content_len);
    if (off == (size_t)-1) return TLV_ERR_LIMIT;
    absent = 0;
    rc = wctx->encode(wctx->context, component, index, wctx->arena + off, content_len, &written,
                      &absent);
    if (rc != TLV_OK) return rc;
    if (absent || written != content_len) return TLV_ERR_INVALID_VALUE;
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
    for (i = 0; i < count; ++i) {
        int component_absent = 0;
        size_t off, len;
        tlv_result_t rc =
            encode_at(wctx, &components[i], 0, depth, 0, &component_absent, &off, &len);
        if (rc != TLV_OK) return rc;
        if (component_absent) {
            if (components[i].presence == TLV_DER_REQUIRED) return TLV_ERR_SCHEMA;
            continue;
        }
        offs[present] = off;
        lens[present] = len;
        ++present;
    }
    for (i = 0; i < present; ++i) total += lens[i];
    base = arena_alloc(wctx, total);
    if (base == (size_t)-1) return TLV_ERR_LIMIT;
    pos = base;
    for (i = 0; i < present; ++i) {
        memcpy(wctx->arena + pos, wctx->arena + offs[i], lens[i]);
        pos += lens[i];
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
    for (i = 0; i < type->component_count; ++i) {
        int component_absent = 0;
        size_t off, len;
        owned_tag_t tag;
        tlv_result_t rc =
            encode_at(wctx, &type->components[i], 0, depth, 0, &component_absent, &off, &len);
        if (rc != TLV_OK) return rc;
        if (component_absent) {
            if (type->components[i].presence == TLV_DER_REQUIRED) return TLV_ERR_SCHEMA;
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
            tlv_asn1_class_t ca = tlv_der_tag_class(&prev_view), cb = tlv_der_tag_class(&view_i);
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
    if (base == (size_t)-1) return TLV_ERR_LIMIT;
    pos = base;
    for (i = 0; i < present; ++i) {
        memcpy(wctx->arena + pos, wctx->arena + offs[i], lens[i]);
        pos += lens[i];
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
    for (;;) {
        int element_absent = 0;
        size_t off, len;
        tlv_result_t rc =
            encode_at(wctx, type->element, count, depth, 0, &element_absent, &off, &len);
        if (rc != TLV_OK) return rc;
        if (element_absent) break;
        if (count >= wctx->scratch_capacity) return TLV_ERR_LIMIT;
        wctx->scratch[count].offset = off;
        wctx->scratch[count].length = len;
        ++count;
        if (count > type->max_elements) return TLV_ERR_SCHEMA;
    }
    if (count < type->min_elements) return TLV_ERR_SCHEMA;
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
    if (base == (size_t)-1) return TLV_ERR_LIMIT;
    pos = base;
    for (i = 0; i < count; ++i) {
        memcpy(wctx->arena + pos, wctx->arena + wctx->scratch[i].offset, wctx->scratch[i].length);
        pos += wctx->scratch[i].length;
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
        case TLV_DER_SCHEMA_UNIVERSAL:
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
            if (schema_depth > TLV_DER_SCHEMA_MAX_TYPE_DEPTH) return TLV_ERR_SCHEMA;
            rc = produce_natural_encoding(wctx, component->type, component, index, depth + 1,
                                          schema_depth + 1, &inner_absent, &content_off,
                                          &content_len);
            if (rc != TLV_OK) return rc;
            if (inner_absent) return TLV_ERR_SCHEMA;
        } else {
            rc = produce_raw_content(wctx, component->type, component, index, depth, &content_off,
                                     &content_len);
            if (rc != TLV_OK) return rc;
        }
        rc = wrap_and_store(wctx, owned_view(&tag), content_off, content_len, out_off, out_len);
        if (rc != TLV_OK) return rc;
    }

    if (!*absent && component->presence == TLV_DER_DEFAULT && component->default_encoding &&
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

tlv_result_t tlv_der_schema_write(uint8_t* data, size_t capacity, const tlv_der_schema_type_t* root,
                                  tlv_der_schema_encode_fn encode, const void* context,
                                  const tlv_der_schema_limits_t* limits, uint8_t* scratch_bytes,
                                  size_t scratch_bytes_capacity, tlv_der_schema_record_t* scratch,
                                  size_t scratch_capacity, size_t* written, size_t* error_offset) {
    der_schema_write_ctx_t wctx;
    tlv_der_schema_component_t synthetic;
    int absent = 0;
    size_t root_off = 0, root_len = 0;
    tlv_result_t rc;

    if (!limits) limits = &tlv_der_schema_default_limits;
    if ((!data && capacity) || !root || !encode || !written ||
        (!scratch_bytes && scratch_bytes_capacity) || (!scratch && scratch_capacity))
        return fail(TLV_ERR_NULL_ARG, 0, error_offset);
    if (limits->base.max_depth > TLV_DER_MAX_DEPTH) return fail(TLV_ERR_LIMIT, 0, error_offset);

    wctx.arena = scratch_bytes;
    wctx.arena_capacity = scratch_bytes_capacity;
    wctx.arena_used = 0;
    wctx.encode = encode;
    wctx.context = context;
    wctx.limits = limits;
    wctx.scratch = scratch;
    wctx.scratch_capacity = scratch_capacity;

    synthetic.type = root;
    synthetic.tagging = TLV_DER_TAG_NONE;
    synthetic.tag_class = TLV_ASN1_UNIVERSAL;
    synthetic.tag_number = 0;
    synthetic.presence = TLV_DER_REQUIRED;
    synthetic.default_encoding = NULL;
    synthetic.default_encoding_length = 0;

    rc = encode_at(&wctx, &synthetic, 0, 0, 0, &absent, &root_off, &root_len);
    if (rc != TLV_OK) return fail(rc, 0, error_offset);
    if (root_len > limits->base.max_input_size) return fail(TLV_ERR_LIMIT, 0, error_offset);
    if (data) {
        if (root_len > capacity) return fail(TLV_ERR_BUFFER_TOO_SHORT, 0, error_offset);
        if (root_len) memcpy(data, wctx.arena + root_off, root_len);
    }
    *written = root_len;
    return TLV_OK;
}
