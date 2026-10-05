// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#ifndef OPENTLV_SCHEMA_QUERY_H
#define OPENTLV_SCHEMA_QUERY_H
#include "tlv/schema/schema.h"
#include "tlv/query/program.h"
#include "tlv/config.h"
#if OPENTLV_DOCUMENT
#include "tlv/document/document.h"
#include "tlv/writer/tree.h"
#endif
#ifdef __cplusplus
extern "C" {
#endif
/** @file
 * @ingroup schemas
 * @brief Optional contextual assertions composed from compiled Query programs. */
/** @brief Schema wrapper: select contexts, then require a boolean assertion in each context.
 * Programs and environment are immutable and borrowed. assert(...) is a Schema concept,
 * not Query grammar. Empty context selection succeeds. Rules execute in table order. */
typedef struct tlv_schema_query_rule {
    const tlv_query_program_t* context; /**< Node selector evaluated against the original root. */
    const tlv_query_program_t*
        assertion; /**< Boolean program, relative to each selected context. */
    const tlv_query_environment_t* environment; /**< Optional compatible codec providers. */
    const char* name;                           /**< Borrowed rule name for diagnostics. */
} tlv_schema_query_rule_t;
/** @brief One caller-stored selected context, retaining original identity and metadata. */
typedef struct tlv_schema_query_context {
    size_t ordinal;         /**< Original preorder identity. */
    tlv_tree_event_t event; /**< Borrowed context metadata, valid while input stays immutable. */
    void* node;             /**< Document context identity; unused for Tree evaluation. */
} tlv_schema_query_context_t;
/** @brief Reusable sequential workspace for all rules; no hidden candidate allocations. */
typedef struct tlv_schema_query_workspace {
    void* selector;        /**< Aligned exclusive retained selector execution storage. */
    size_t selector_size;  /**< Selector storage bytes. */
    void* assertion;       /**< Aligned exclusive assertion execution storage. */
    size_t assertion_size; /**< Assertion storage bytes. */
    tlv_schema_query_context_t* contexts; /**< Explicit selected-context array. */
    size_t context_capacity;              /**< Maximum selected contexts, including overlaps. */
    tlv_tree_frame_t* frames; /**< Borrowed Reader stack, at least max_depth+1 entries. */
    size_t frame_capacity;    /**< Reader stack entries. */
} tlv_schema_query_workspace_t;
/** @brief Rule-aware failure preserving native Query/Reader/codec diagnostics. */
typedef struct tlv_schema_query_diagnostic {
    size_t rule;                    /**< Zero-based failing rule. */
    tlv_schema_diagnostic_t schema; /**< Failed boolean context, field=name, expected=true. */
    tlv_query_diagnostic_t query;   /**< Original engine/Reader failure, separately preserved. */
} tlv_schema_query_diagnostic_t;
/** @brief Discover aggregate sequential execution requirements and validate result types.
 * @param rules Immutable borrowed descriptors.
 * @param count Descriptor count; zero permits NULL.
 * @param depth Maximum traversal depth.
 * @param nodes Retained-node capacity including nonmatches.
 * @param selector Required largest selector workspace bytes among all rules.
 * @param assertion Required largest assertion workspace bytes among all rules.
 * @param alignment Required common alignment for both workspaces.
 * @return Native sizing/type/capacity error or OK; outputs unchanged on failure.
 * @note Context arrays and Reader frames are additional explicit storage. Rules reuse
 * the two workspaces sequentially; Document Value snapshot and owning tree are separate. */
TLV_API tlv_result_t tlv_schema_query_size(const tlv_schema_query_rule_t* rules, size_t count,
                                           size_t depth, size_t nodes, size_t* selector,
                                           size_t* assertion, size_t* alignment);
/** @brief Validate contextual boolean assertions over immutable complete input.
 * @param data Stable input bytes, alive through the call.
 * @param size Input byte count.
 * @param format Borrowed Format/context.
 * @param rules Compiled rules, composing with existing structural validation separately.
 * @param count Rule count; zero skips assertion validation explicitly.
 * @param depth Maximum depth.
 * @param nodes Explicit retained-node capacity.
 * @param work Charged budget per execution (selector and each assertion context).
 * @param workspace Caller storage, disjoint from input/programs.
 * @param diagnostic Optional structured failure; Reader failures remain their original codes.
 * @return OK, SCHEMA for false assertion, or native storage/Reader/Query failure.
 * @note Rejects all D rules before input traversal. Every context uses the original
 * whole input and normal Query relative-context semantics. Full structural coverage;
 * no subtree pruning. Work is O(sum of selector and per-context assertion executions).
 * No allocation or independent path/expression evaluator. */
TLV_API tlv_result_t tlv_schema_query_validate_buffer(
    const uint8_t* data, size_t size, const tlv_format_t* format,
    const tlv_schema_query_rule_t* rules, size_t count, size_t depth, size_t nodes, size_t work,
    tlv_schema_query_workspace_t* workspace, tlv_schema_query_diagnostic_t* diagnostic);
#if OPENTLV_DOCUMENT
/** @brief Validate the same assertion programs over an immutable Document, including D.
 * @param document Owning tree, alive and unchanged throughout validation.
 * @param rules Borrowed compiled rules.
 * @param count Rule count; zero skips validation explicitly.
 * @param depth Maximum depth.
 * @param nodes Explicit retained-node capacity.
 * @param work Native budget per selector/context assertion execution.
 * @param workspace Sequential execution and context storage from query_size.
 * @param values Caller-owned canonical Value snapshot if programs require Values.
 * @param capacity Value storage bytes.
 * @param staging Bounded Writer frames/scratch when Values are required.
 * @param diagnostic Optional original engine and Schema context failure.
 * @return OK, SCHEMA for false, or original Query/Writer/capacity failure.
 * @note No allocation. D uses the same VM and original Document contexts. Historical
 * Source offsets are unavailable. Structural Schema rules remain separately optional. */
TLV_API tlv_result_t tlv_schema_query_validate_document(
    const tlv_document_t* document, const tlv_schema_query_rule_t* rules, size_t count,
    size_t depth, size_t nodes, size_t work, tlv_schema_query_workspace_t* workspace,
    uint8_t* values, size_t capacity, tlv_tree_writer_workspace_t* staging,
    tlv_schema_query_diagnostic_t* diagnostic);
#endif
#ifdef __cplusplus
}
#endif
#endif
