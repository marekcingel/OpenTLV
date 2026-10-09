// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

/* Schema workloads shared by the Callgrind driver and Google Benchmark.
 *
 * Each schema shape has a definition-check-only operation and a complete
 * operation (definition check plus input processing), for generic Schema and
 * DER Schema. Fixtures are built at run time into caller storage, so this
 * header is valid C99 and C++11 and needs no allocation. */

#ifndef OPENTLV_BENCHMARK_SCHEMA_WORKLOADS_H
#define OPENTLV_BENCHMARK_SCHEMA_WORKLOADS_H

#include "tlv/config.h"
#include "tlv/tag.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define SCHEMA_WORKLOADS_GENERIC (OPENTLV_SCHEMA && OPENTLV_READER && OPENTLV_FORMAT_BER)
#define SCHEMA_WORKLOADS_DER                                                                       \
    (OPENTLV_FORMAT_DER && OPENTLV_SCHEMA && OPENTLV_CODEC && OPENTLV_WRITER)

#if SCHEMA_WORKLOADS_GENERIC
#include "tlv/builtins/asn1/ber.h"
#include "tlv/schema/schema.h"
#endif
#if SCHEMA_WORKLOADS_DER
#include "tlv/builtins/asn1/der_schema.h"
#endif

enum {
    /* Distinct tables or types in the shared graph; each references the next two. */
    SCHEMA_SHARED_COUNT = 200,
    /* Flat input: 256 primitive OCTET STRING-like elements of 16 bytes. */
    SCHEMA_FLAT_ENTRIES = 256,
    SCHEMA_FLAT_VALUE = 16,
    SCHEMA_FLAT_ENTRY = SCHEMA_FLAT_VALUE + 2,
    SCHEMA_FLAT_WIRE = SCHEMA_FLAT_ENTRIES * SCHEMA_FLAT_ENTRY,
    /* DER wraps the flat elements in one SEQUENCE OF with a two-byte length. */
    SCHEMA_DER_FLAT_WIRE = SCHEMA_FLAT_WIRE + 4,
    /* Nested input: one SEQUENCE holding 16 chains of 20 nested empty SEQUENCEs. */
    SCHEMA_NESTED_CHAINS = 16,
    SCHEMA_NESTED_DEPTH = 20,
    SCHEMA_NESTED_CHAIN = 2 * SCHEMA_NESTED_DEPTH,
    SCHEMA_NESTED_CONTENT = SCHEMA_NESTED_CHAINS * SCHEMA_NESTED_CHAIN,
    SCHEMA_NESTED_WIRE = SCHEMA_NESTED_CONTENT + 4,
    SCHEMA_NESTED_ELEMENTS = 1 + SCHEMA_NESTED_CHAINS * SCHEMA_NESTED_DEPTH
};

typedef struct schema_workloads {
    uint8_t empty_sequence[2];
    uint8_t flat[SCHEMA_FLAT_WIRE];
    uint8_t der_flat_input[SCHEMA_DER_FLAT_WIRE];
    uint8_t nested[SCHEMA_NESTED_WIRE];
    uint8_t tag_bytes[2 + SCHEMA_FLAT_VALUE];
#if SCHEMA_WORKLOADS_GENERIC
    tlv_schema_entry_t     sequence_entry, set_entry, flat_entries[SCHEMA_FLAT_VALUE];
    tlv_structure_rule_t   shared_rules[SCHEMA_SHARED_COUNT][2];
    tlv_structure_schema_t shared[SCHEMA_SHARED_COUNT];
    tlv_structure_rule_t   flat_rules[SCHEMA_FLAT_VALUE];
    tlv_structure_schema_t flat_schema;
    tlv_structure_rule_t   recursive_rule;
    tlv_structure_schema_t recursive;
#endif
#if SCHEMA_WORKLOADS_DER
    tlv_der_schema_component_t der_shared_components[SCHEMA_SHARED_COUNT][2];
    tlv_der_schema_type_t      der_shared[SCHEMA_SHARED_COUNT];
    tlv_der_schema_type_t      der_octet_string;
    tlv_der_schema_component_t der_flat_element;
    tlv_der_schema_type_t      der_flat;
    tlv_der_schema_component_t der_recursive_element;
    tlv_der_schema_type_t      der_recursive;
#endif
} schema_workloads_t;

typedef int (*schema_workload_fn)(const schema_workloads_t*, uint64_t*);

/* Byte j of flat element i is (i + j) % 256 and its tag is 0x80 + i % 16,
 * matching the Reader workloads' ber-flat-256x16-v1 input. */
static inline void schema_workloads_flat(uint8_t* out) {
    size_t i, j;
    for (i = 0; i < SCHEMA_FLAT_ENTRIES; ++i) {
        uint8_t* entry = out + i * SCHEMA_FLAT_ENTRY;
        entry[0] = (uint8_t)(0x80 + i % 16);
        entry[1] = SCHEMA_FLAT_VALUE;
        for (j = 0; j < SCHEMA_FLAT_VALUE; ++j) entry[2 + j] = (uint8_t)(i + j);
    }
}

static inline void schema_workloads_inputs(schema_workloads_t* w) {
    size_t   i, depth;
    uint8_t* chain;
    w->empty_sequence[0] = 0x30;
    w->empty_sequence[1] = 0x00;
    schema_workloads_flat(w->flat);
    /* DER flat values are OCTET STRINGs inside one SEQUENCE OF. */
    w->der_flat_input[0] = 0x30;
    w->der_flat_input[1] = 0x82;
    w->der_flat_input[2] = (uint8_t)(SCHEMA_FLAT_WIRE >> 8);
    w->der_flat_input[3] = (uint8_t)(SCHEMA_FLAT_WIRE & 0xFF);
    memcpy(w->der_flat_input + 4, w->flat, SCHEMA_FLAT_WIRE);
    for (i = 0; i < SCHEMA_FLAT_ENTRIES; ++i) w->der_flat_input[4 + i * SCHEMA_FLAT_ENTRY] = 0x04;
    w->nested[0] = 0x30;
    w->nested[1] = 0x82;
    w->nested[2] = (uint8_t)(SCHEMA_NESTED_CONTENT >> 8);
    w->nested[3] = (uint8_t)(SCHEMA_NESTED_CONTENT & 0xFF);
    chain = w->nested + 4;
    for (depth = 0; depth < SCHEMA_NESTED_DEPTH; ++depth) {
        chain[2 * depth] = 0x30;
        chain[2 * depth + 1] = (uint8_t)(SCHEMA_NESTED_CHAIN - 2 * depth - 2);
    }
    for (i = 1; i < SCHEMA_NESTED_CHAINS; ++i)
        memcpy(chain + i * SCHEMA_NESTED_CHAIN, chain, SCHEMA_NESTED_CHAIN);
}

#if SCHEMA_WORKLOADS_GENERIC
static inline void schema_rule(tlv_structure_rule_t* rule, const tlv_schema_entry_t* entry,
                               size_t max_occurs, tlv_schema_kind_t kind,
                               const tlv_structure_schema_t* children) {
    memset(rule, 0, sizeof *rule);
    rule->entry = entry;
    rule->max_occurs = max_occurs;
    rule->kind = kind;
    rule->children = children;
}

static inline void schema_entry(tlv_schema_entry_t* entry, const uint8_t* tag, size_t min_length,
                                size_t max_length) {
    memset(entry, 0, sizeof *entry);
    entry->tag = tlv_tag(tag, 1);
    entry->min_length = min_length;
    entry->max_length = max_length;
}

static inline void schema_table(tlv_structure_schema_t* table, const tlv_structure_rule_t* rules,
                                size_t count, tlv_schema_order_t order) {
    memset(table, 0, sizeof *table);
    table->rules = rules;
    table->count = count;
    table->order = order;
}

static inline void schema_workloads_generic(schema_workloads_t* w) {
    size_t i;
    schema_entry(&w->sequence_entry, &w->tag_bytes[0], 0, SIZE_MAX);
    schema_entry(&w->set_entry, &w->tag_bytes[1], 0, SIZE_MAX);
    /* Table i accepts optional SEQUENCE -> table i+1 and SET -> table i+2. */
    for (i = 0; i < SCHEMA_SHARED_COUNT; ++i) {
        size_t count = 0;
        if (i + 1 < SCHEMA_SHARED_COUNT)
            schema_rule(&w->shared_rules[i][count++], &w->sequence_entry, 1, TLV_SCHEMA_CONSTRUCTED,
                        &w->shared[i + 1]);
        if (i + 2 < SCHEMA_SHARED_COUNT)
            schema_rule(&w->shared_rules[i][count++], &w->set_entry, 1, TLV_SCHEMA_CONSTRUCTED,
                        &w->shared[i + 2]);
        schema_table(&w->shared[i], w->shared_rules[i], count, TLV_SCHEMA_ORDER_SEQUENCE);
    }
    for (i = 0; i < SCHEMA_FLAT_VALUE; ++i) {
        schema_entry(&w->flat_entries[i], &w->tag_bytes[2 + i], SCHEMA_FLAT_VALUE,
                     SCHEMA_FLAT_VALUE);
        schema_rule(&w->flat_rules[i], &w->flat_entries[i], SIZE_MAX, TLV_SCHEMA_PRIMITIVE, NULL);
    }
    schema_table(&w->flat_schema, w->flat_rules, SCHEMA_FLAT_VALUE, TLV_SCHEMA_ORDER_ANY);
    /* T = SEQUENCE OF T, as a self-referencing table. */
    schema_rule(&w->recursive_rule, &w->sequence_entry, SIZE_MAX, TLV_SCHEMA_CONSTRUCTED,
                &w->recursive);
    schema_table(&w->recursive, &w->recursive_rule, 1, TLV_SCHEMA_ORDER_ANY);
}

static inline int schema_check_shared(const schema_workloads_t* w, uint64_t* checksum) {
    *checksum = SCHEMA_SHARED_COUNT;
    return tlv_schema_check(&w->shared[0], NULL) == TLV_OK;
}

static inline int schema_validate_shared(const schema_workloads_t* w, uint64_t* checksum) {
    *checksum = sizeof w->empty_sequence;
    return tlv_schema_validate(w->empty_sequence, sizeof w->empty_sequence, &tlv_format_ber,
                               &w->shared[0], 8, 8, NULL) == TLV_OK;
}

static inline int schema_check_flat(const schema_workloads_t* w, uint64_t* checksum) {
    *checksum = SCHEMA_FLAT_VALUE;
    return tlv_schema_check(&w->flat_schema, NULL) == TLV_OK;
}

static inline int schema_validate_flat(const schema_workloads_t* w, uint64_t* checksum) {
    *checksum = SCHEMA_FLAT_WIRE;
    return tlv_schema_validate(w->flat, SCHEMA_FLAT_WIRE, &tlv_format_ber, &w->flat_schema, 8,
                               SCHEMA_FLAT_ENTRIES, NULL) == TLV_OK;
}

static inline int schema_check_recursive(const schema_workloads_t* w, uint64_t* checksum) {
    *checksum = 1;
    return tlv_schema_check(&w->recursive, NULL) == TLV_OK;
}

static inline int schema_validate_recursive(const schema_workloads_t* w, uint64_t* checksum) {
    *checksum = SCHEMA_NESTED_WIRE;
    return tlv_schema_validate(w->nested, SCHEMA_NESTED_WIRE, &tlv_format_ber, &w->recursive,
                               SCHEMA_NESTED_DEPTH + 1, SCHEMA_NESTED_ELEMENTS, NULL) == TLV_OK;
}
#endif

#if SCHEMA_WORKLOADS_DER
static inline void der_component(tlv_der_schema_component_t*  component,
                                 const tlv_der_schema_type_t* type, tlv_der_tagging_mode_t tagging,
                                 uint64_t tag_number, tlv_der_presence_t presence) {
    memset(component, 0, sizeof *component);
    component->type = type;
    component->tagging = tagging;
    component->tag_class =
        tagging == TLV_DER_TAG_NONE ? TLV_ASN1_UNIVERSAL : TLV_ASN1_CONTEXT_SPECIFIC;
    component->tag_number = tag_number;
    component->presence = presence;
}

static inline void der_sequence_of(tlv_der_schema_type_t*            type,
                                   const tlv_der_schema_component_t* element) {
    memset(type, 0, sizeof *type);
    type->kind = TLV_DER_SCHEMA_SEQUENCE_OF;
    type->element = element;
    type->max_elements = SIZE_MAX;
}

static inline void schema_workloads_der(schema_workloads_t* w) {
    size_t i;
    /* Type i is a SEQUENCE of optional [0] IMPLICIT type i+1 and [1] IMPLICIT type i+2. */
    for (i = 0; i < SCHEMA_SHARED_COUNT; ++i) {
        size_t                 count = 0;
        tlv_der_schema_type_t* type = &w->der_shared[i];
        if (i + 1 < SCHEMA_SHARED_COUNT)
            der_component(&w->der_shared_components[i][count++], &w->der_shared[i + 1],
                          TLV_DER_TAG_IMPLICIT, 0, TLV_DER_OPTIONAL);
        if (i + 2 < SCHEMA_SHARED_COUNT)
            der_component(&w->der_shared_components[i][count++], &w->der_shared[i + 2],
                          TLV_DER_TAG_IMPLICIT, 1, TLV_DER_OPTIONAL);
        memset(type, 0, sizeof *type);
        type->kind = TLV_DER_SCHEMA_SEQUENCE;
        type->components = w->der_shared_components[i];
        type->component_count = count;
    }
    memset(&w->der_octet_string, 0, sizeof w->der_octet_string);
    w->der_octet_string.kind = TLV_DER_SCHEMA_UNIVERSAL;
    w->der_octet_string.universal_number = 4;
    der_component(&w->der_flat_element, &w->der_octet_string, TLV_DER_TAG_NONE, 0,
                  TLV_DER_REQUIRED);
    der_sequence_of(&w->der_flat, &w->der_flat_element);
    der_component(&w->der_recursive_element, &w->der_recursive, TLV_DER_TAG_NONE, 0,
                  TLV_DER_REQUIRED);
    der_sequence_of(&w->der_recursive, &w->der_recursive_element);
}

static inline int der_schema_read_checksum(const uint8_t* data, size_t size,
                                           const tlv_der_schema_type_t* root, uint64_t* checksum) {
    tlv_element_t element;
    size_t        consumed = 0;
    if (tlv_der_schema_read(data, size, root, NULL, &element, &consumed, NULL) != TLV_OK ||
        consumed != size)
        return 0;
    *checksum = consumed + (uint64_t)element.value.size;
    return 1;
}

static inline int der_schema_check_shared(const schema_workloads_t* w, uint64_t* checksum) {
    *checksum = SCHEMA_SHARED_COUNT;
    return tlv_der_schema_check(&w->der_shared[0], NULL) == TLV_OK;
}

static inline int der_schema_read_shared(const schema_workloads_t* w, uint64_t* checksum) {
    return der_schema_read_checksum(w->empty_sequence, sizeof w->empty_sequence, &w->der_shared[0],
                                    checksum);
}

static inline int der_schema_check_flat(const schema_workloads_t* w, uint64_t* checksum) {
    *checksum = 2;
    return tlv_der_schema_check(&w->der_flat, NULL) == TLV_OK;
}

static inline int der_schema_read_flat(const schema_workloads_t* w, uint64_t* checksum) {
    return der_schema_read_checksum(w->der_flat_input, SCHEMA_DER_FLAT_WIRE, &w->der_flat,
                                    checksum);
}

static inline int der_schema_check_recursive(const schema_workloads_t* w, uint64_t* checksum) {
    *checksum = 1;
    return tlv_der_schema_check(&w->der_recursive, NULL) == TLV_OK;
}

static inline int der_schema_read_recursive(const schema_workloads_t* w, uint64_t* checksum) {
    return der_schema_read_checksum(w->nested, SCHEMA_NESTED_WIRE, &w->der_recursive, checksum);
}
#endif

/* Builds every available fixture; schema_workloads_t is large, so prefer static storage. */
static inline void schema_workloads_init(schema_workloads_t* w) {
    size_t i;
    memset(w, 0, sizeof *w);
    w->tag_bytes[0] = 0x30;
    w->tag_bytes[1] = 0x31;
    for (i = 0; i < SCHEMA_FLAT_VALUE; ++i) w->tag_bytes[2 + i] = (uint8_t)(0x80 + i);
    schema_workloads_inputs(w);
#if SCHEMA_WORKLOADS_GENERIC
    schema_workloads_generic(w);
#endif
#if SCHEMA_WORKLOADS_DER
    schema_workloads_der(w);
#endif
}

#endif
