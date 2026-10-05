// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#ifndef OPENTLV_QUERY_PROGRAM_H
#define OPENTLV_QUERY_PROGRAM_H

#include "tlv/query/query.h"
#include "tlv/codec/codec.h"
#include "tlv/definition.h"
#ifdef __cplusplus
extern "C" {
#endif

/** @file
 * @ingroup traversal
 * @brief Caller-stored immutable Query programs and bounded event execution.
 * @note All calls are allocation-free and iterative. Storage must be aligned
 * to the reported alignment, alive and unchanged while borrowed. Internal
 * program images are release-specific, not a persistent serialization format.
 */

/** @addtogroup traversal
 * @{ */

/** @brief Whole-expression execution requirements, ordered by available storage. */
typedef enum tlv_query_level {
    TLV_QUERY_S0, /**< Decisions at complete node publication. */
    TLV_QUERY_S1, /**< Deferred scope evidence with bounded depth summaries. */
    TLV_QUERY_S2, /**< Explicit input-dependent candidate capacity. */
    TLV_QUERY_D   /**< Document navigation and bounded work. */
} tlv_query_level_t;

/** @brief Query-specific diagnostic category; original result codes remain intact. */
typedef enum tlv_query_error_kind {
    TLV_QUERY_ERROR_NONE,        /**< No failure. */
    TLV_QUERY_ERROR_SYNTAX,      /**< Invalid token or grammar. */
    TLV_QUERY_ERROR_CAPABILITY,  /**< Recognized feature unavailable in this backend. */
    TLV_QUERY_ERROR_LIMIT,       /**< Named capacity or work budget exhausted. */
    TLV_QUERY_ERROR_STORAGE,     /**< Invalid storage or alignment. */
    TLV_QUERY_ERROR_EVENTS,      /**< Unbalanced or otherwise invalid structural feed. */
    TLV_QUERY_ERROR_SOURCE,      /**< Requested Source property unavailable. */
    TLV_QUERY_ERROR_READER,      /**< Original Reader failure; reader detail is preserved. */
    TLV_QUERY_ERROR_BINDING,     /**< Missing, unknown, duplicate or incompatible variable. */
    TLV_QUERY_ERROR_CARDINALITY, /**< Scalar conversion did not receive exactly one node. */
    TLV_QUERY_ERROR_CODEC        /**< Strict Value decoding failed. */
} tlv_query_error_kind_t;

/** @brief Earliest publication frontier for the conservatively selected backend. */
typedef enum tlv_query_decision_timing {
    TLV_QUERY_DECISION_NODE,  /**< Complete BEGIN/ELEMENT publication. */
    TLV_QUERY_DECISION_SCOPE, /**< Selected root END, or primitive publication. */
    TLV_QUERY_DECISION_EOF    /**< Final EOF or complete Document snapshot evaluation. */
} tlv_query_decision_timing_t;

/** @brief Fixed-layout compiler/execution failure, initialized by diagnostic entry points.
 * @note This value type is not extensible; changing its layout requires an ABI change. */
typedef struct tlv_query_diagnostic {
    tlv_query_error_kind_t kind;    /**< Query failure category. */
    size_t begin;                   /**< Inclusive Query byte offset. */
    size_t end;                     /**< Exclusive Query byte offset; EOF spans may be empty. */
    size_t source_offset;           /**< Input byte offset when has_source_offset is nonzero. */
    int has_source_offset;          /**< Distinguish missing Source from offset zero. */
    const char* expected;           /**< Static expected-token description, or NULL. */
    const char* limit;              /**< Static resource name, or NULL. */
    size_t configured;              /**< Configured resource bound, when limit is present. */
    tlv_reader_diagnostic_t reader; /**< Original Reader diagnostic on Reader failure. */
    tlv_codec_result_t codec;       /**< Original codec failure when kind is CODEC. */
} tlv_query_diagnostic_t;

/** @brief Category of a Query expression's result. */
typedef enum tlv_query_result_kind {
    TLV_QUERY_RESULT_NODES,   /**< Ordered unique node sequence. */
    TLV_QUERY_RESULT_BOOL,    /**< Boolean scalar. */
    TLV_QUERY_RESULT_INTEGER, /**< Signed 64-bit scalar. */
    TLV_QUERY_RESULT_BYTES,   /**< Byte scalar. */
    TLV_QUERY_RESULT_STRING   /**< UTF-8 string scalar. */
} tlv_query_result_kind_t;

/** @brief Fixed-layout scalar output. Spans borrow immutable input, program or workspace
 * until execution reset. Read only after successful finish; nodes use result_next. */
typedef struct tlv_query_result {
    tlv_query_result_kind_t kind; /**< Value category. */
    int boolean;                  /**< Boolean value. */
    int64_t integer;              /**< Integer or UTC Unix seconds. */
    const uint8_t* data;          /**< Borrowed byte/string span. */
    size_t size;                  /**< Span bytes. */
} tlv_query_result_t;

/** @brief Closed conversion-function selectors; no arbitrary function execution. */
typedef enum tlv_query_conversion {
    TLV_QUERY_NUM,  /**< Domain-selected integer. */
    TLV_QUERY_BCD,  /**< Packed decimal. */
    TLV_QUERY_TEXT, /**< Explicit UTF-8 text. */
    TLV_QUERY_DATE  /**< UTC Unix seconds. */
} tlv_query_conversion_t;

/** @brief Complete-Value decode adapter, returning original codec status.
 * @param[in] context Borrowed immutable thread-safe provider context.
 * @param[in] event Candidate metadata, or NULL for literal/binding conversion.
 * @param[in] data Complete contiguous Value bytes.
 * @param[in] size Input bytes.
 * @param[in,out] scratch Private aligned caller storage for this VM frame.
 * @param[in] capacity Scratch bytes.
 * @param[out] result Tagged scalar; may borrow input or scratch until reset.
 * @note No allocation. Callback work is outside the engine work bound. */
typedef tlv_codec_result_t (*tlv_query_decode_t)(const void* context, const tlv_tree_event_t* event,
                                                 const uint8_t* data, size_t size, void* scratch,
                                                 size_t capacity, tlv_query_result_t* result);

/** @brief Immutable compile requirement/execution provider. IDs, not pointers, enter programs. */
typedef struct tlv_query_hook {
    uint32_t id;                     /**< Nonzero caller-defined stable capability ID. */
    tlv_query_conversion_t function; /**< Closed conversion selector. */
    size_t scratch_size;             /**< Per-invocation scratch bytes. */
    size_t scratch_alignment;        /**< Power of two, at most 16. */
    const void* context;             /**< Borrowed provider context. */
    tlv_query_decode_t decode;       /**< Execution callback; NULL allowed only for compilation. */
} tlv_query_hook_t;

/** @brief Optional semantic tag adapter beside Format, preserving raw tag identity. */
typedef struct tlv_query_tag_adapter {
    uint32_t id;         /**< Nonzero caller-defined compatibility ID. */
    const void* context; /**< Borrowed immutable context. */
    tlv_result_t (*class_of)(const void*, const tlv_tag_t*,
                             int64_t*); /**< Optional class decomposition. */
    tlv_result_t (*number_of)(const void*, const tlv_tag_t*,
                              int64_t*); /**< Optional semantic number. */
} tlv_query_tag_adapter_t;

/** @brief Compile-time scoped lookup returning a borrowed tag copied during compile.
 * @param[in] context Resolver context, borrowed only during compile.
 * @param[in] namespace_name Bounded namespace; empty for unqualified lookup.
 * @param[in] namespace_size Namespace bytes.
 * @param[in] name Bounded symbolic name.
 * @param[in] name_size Name bytes.
 * @param[out] tag Borrowed raw identifier.
 * @return OK for one match, INVALID_TAG for unknown, INVALID_ARG for conflicts. */
typedef tlv_result_t (*tlv_query_resolve_t)(const void* context, const char* namespace_name,
                                            size_t namespace_size, const char* name,
                                            size_t name_size, tlv_tag_t* tag);

/** @brief Borrowed immutable environment, unchanged/alive through execution and suspension.
 * @note Concurrent execution requires thread-safe callbacks and contexts. Capability IDs
 * and scratch requirements must match compilation; no protocol dispatch exists in Query. */
typedef struct tlv_query_environment {
    const tlv_format_t* format;          /**< Optional Format for constructed classification. */
    const tlv_query_tag_adapter_t* tags; /**< Optional semantic tag provider. */
    const tlv_query_hook_t* hooks;       /**< Conversion provider array. */
    size_t hook_count; /**< Providers; duplicate IDs/function selectors are invalid. */
} tlv_query_environment_t;

/** @brief Compile-time variable declaration; names omit the dollar prefix.
 * @note The name is borrowed only during compilation; the program copies Query text.
 * Integer, bytes and string declarations are supported. Duplicate names are invalid. */
typedef struct tlv_query_variable {
    const char* name;             /**< Required NUL-terminated variable name. */
    tlv_query_result_kind_t type; /**< Required value category. */
} tlv_query_variable_t;

/** @brief Versioned compile options; initialize using tlv_query_compile_options_init(). */
typedef struct tlv_query_compile_options {
    size_t struct_size;                         /**< Set by initializer; must match this release. */
    unsigned language_version;                  /**< Explicit full language version; currently 1. */
    size_t max_text;                            /**< Maximum Query bytes. */
    size_t max_tokens;                          /**< Maximum lexical tokens. */
    size_t max_nesting;                         /**< Maximum open parentheses/predicates. */
    size_t max_states;                          /**< Maximum compiled expression nodes. */
    const tlv_query_variable_t* variables;      /**< Optional borrowed variable declarations. */
    size_t variable_count;                      /**< Number of entries in variables. */
    tlv_query_resolve_t resolve;                /**< Optional scoped name resolver. */
    const void* resolve_context;                /**< Borrowed only during compilation. */
    const tlv_query_environment_t* environment; /**< Compile-time capability environment. */
    size_t max_resolved_tag;                    /**< Copied tag byte bound per symbolic test. */
    size_t max_pattern; /**< Runtime KMP pattern capacity in explicit workspace. */
    int optimize;       /**< Enable bounded constant folding and compatible test sharing. */
} tlv_query_compile_options_t;

/** @brief Program requirements and whole-plan information. */
typedef struct tlv_query_program_info {
    size_t struct_size;  /**< Caller-provided writable extent; initialize to sizeof this type. */
    size_t program_size; /**< Exact immutable storage bytes. */
    size_t program_alignment;            /**< Required address alignment. */
    size_t scratch_size;                 /**< Exact compile scratch bytes for this input. */
    size_t scratch_alignment;            /**< Required scratch alignment. */
    size_t states;                       /**< Query-dependent state count. */
    unsigned language_version;           /**< Compiled language selection. */
    tlv_query_level_t level;             /**< Lowest conservatively proven execution level. */
    tlv_query_result_kind_t result_kind; /**< Finalized result category. */
    size_t expression_values; /**< Maximum intermediate value slots; no C stack recursion. */
    size_t instructions;      /**< Immutable expression instruction count. */
    size_t variable_slots;    /**< Unique referenced variables and exact execution binding slots. */
    size_t codec_scratch;     /**< Aligned scratch stride per conversion frame. */
    size_t pattern_bytes;     /**< Runtime pattern capacity. */
    size_t optimized_states;  /**< Folded/shared states. */
    size_t expression_stack;  /**< Maximum iterative retained-evaluator frame count. */
    size_t candidate_size;    /**< Private retained descriptor bytes per input node. */
    size_t candidate_alignment; /**< Descriptor alignment within caller execution storage. */
    size_t frame_states;        /**< Per-depth state slots for depth-bounded execution. */
    tlv_query_decision_timing_t decision_timing; /**< Earliest result publication frontier. */
    int stable_input_required; /**< Delayed spans must remain alive/immutable until reset. */
} tlv_query_program_info_t;

/** @brief Opaque immutable caller-owned program. */
typedef struct tlv_query_program tlv_query_program_t;
/** @brief Opaque mutable caller-owned execution workspace. */
typedef struct tlv_query_exec tlv_query_exec_t;

/** @brief Fixed-layout borrowed requirement for one unique referenced variable. */
typedef struct tlv_query_variable_info {
    const char* name; /**< Name without dollar prefix; borrowed from program, not NUL-terminated. */
    size_t name_size; /**< Name bytes. */
    tlv_query_result_kind_t type; /**< Required binding type. */
} tlv_query_variable_info_t;

/** @brief Count unique referenced variables in first-reference order.
 * @param[in] program Live immutable program.
 * @return Unique variable count; zero for NULL or an inconsistent internal image.
 * @note Unused compile-environment declarations are not program requirements. */
TLV_API size_t tlv_query_program_variable_count(const tlv_query_program_t* program);

/** @brief Read a unique referenced variable requirement.
 * @param[in] program Live immutable program.
 * @param[in] index Zero-based slot in first-reference order.
 * @param[out] info Fixed-layout output; unchanged on failure.
 * @return #TLV_OK; #TLV_ERR_NULL_ARG for missing pointers; #TLV_ERR_INVALID_ARG
 * for invalid image or index. The name remains valid while the program is alive. */
TLV_API tlv_result_t tlv_query_program_variable(const tlv_query_program_t* program, size_t index,
                                                tlv_query_variable_info_t* info);

/** @brief Initialize safe compile defaults; NULL is a no-op.
 * @param[out] options Optional destination for current defaults. */
TLV_API void tlv_query_compile_options_init(tlv_query_compile_options_t* options);

/**
 * @brief Discover compiler scratch requirements without interpreting unsupported syntax.
 * @param[in] text Required bounded text, not retained.
 * @param[in] size Text bytes; NUL is an invalid token.
 * @param[in] options Optional initialized options; NULL selects defaults.
 * @param[out] bytes Required output for exact lexer/parser scratch capacity.
 * @param[out] alignment Required alignment output.
 * @param[out] diagnostic Optional initialized failure detail.
 * @return #TLV_OK on success; #TLV_ERR_NULL_ARG for missing arguments;
 * #TLV_ERR_INVALID_ARG for invalid options or lexical input;
 * #TLV_ERR_LIMIT for text/token bounds; #TLV_ERR_OVERFLOW for sizing overflow.
 * @note Never allocates; size/alignment outputs are unchanged on failure.
 */
TLV_API tlv_result_t tlv_query_compile_scratch(const char* text, size_t size,
                                               const tlv_query_compile_options_t* options,
                                               size_t* bytes, size_t* alignment,
                                               tlv_query_diagnostic_t* diagnostic);

/**
 * @brief Compile or size an immutable, relocatable full-language Query program.
 * @param[in] text Required bounded text, not retained after success.
 * @param[in] size Text bytes.
 * @param[in] options Optional initialized options.
 * @param[in,out] scratch Required aligned temporary storage, exclusive during this call.
 * @param[in] scratch_size Available scratch bytes.
 * @param[out] storage Aligned program output; NULL with zero capacity requests sizing.
 * @param[in] capacity Available output bytes.
 * @param[in,out] info Required requirements output; set struct_size to the writable extent.
 * @param[out] diagnostic Optional failure detail.
 * @return #TLV_OK for a supported Query program or sizing pass.
 * @return #TLV_ERR_UNSUPPORTED_TYPE for recognized later-phase capabilities.
 * @return #TLV_ERR_BUFFER_TOO_SHORT for insufficient scratch/output; info is
 * populated for insufficient program output, not insufficient scratch.
 * @return #TLV_ERR_INVALID_ARG for syntax/options/alignment; #TLV_ERR_NULL_ARG
 * for missing pointers; #TLV_ERR_LIMIT for configured resources.
 * @note Storage, scratch, text and info must not overlap. Failure preserves
 * program storage. Sizing and writing are deterministic for identical input/options.
 * @note After semantic analysis, info is also populated for capability/type
 * failures. Earlier lexical, grammar, scratch and arithmetic failures leave it unchanged.
 * @note struct_size must cover the prefix through result_kind. Writes are limited
 * to min(struct_size, sizeof current info); unknown trailing caller bytes are preserved.
 * struct_size is preserved. Rebuilding is required for callers predating this contract.
 */
TLV_API tlv_result_t tlv_query_compile(const char* text, size_t size,
                                       const tlv_query_compile_options_t* options, void* scratch,
                                       size_t scratch_size, void* storage, size_t capacity,
                                       tlv_query_program_info_t* info,
                                       tlv_query_diagnostic_t* diagnostic);

/**
 * @brief Canonically format a compiled program, including size discovery.
 * @param[in] program Required live program returned by compile.
 * @param[out] output Optional output; NULL requires capacity zero.
 * @param[in] capacity Available bytes including terminator.
 * @param[out] required Required output, including terminator.
 * @return #TLV_OK on discovery/write; #TLV_ERR_NULL_ARG for missing arguments;
 * #TLV_ERR_BUFFER_TOO_SHORT with required set and output unchanged.
 * @note Never allocates. Output and required must not overlap program storage.
 * @return #TLV_ERR_INVALID_ARG for misalignment or inconsistent internal image.
 */
TLV_API tlv_result_t tlv_query_program_format(const tlv_query_program_t* program, char* output,
                                              size_t capacity, size_t* required);

/**
 * @brief Discover runtime workspace for a compiled S0/S1 plan and depth capacity.
 * @param[in] program Required live immutable program.
 * @param[in] max_depth Maximum node depth; roots have depth zero.
 * @param[out] bytes Required exact workspace size.
 * @param[out] alignment Required workspace alignment.
 * @return #TLV_OK; #TLV_ERR_NULL_ARG for missing pointers; #TLV_ERR_OVERFLOW
 * for arithmetic overflow; #TLV_ERR_UNSUPPORTED_TYPE for unsupported plans.
 * @return #TLV_ERR_INVALID_ARG for misalignment or inconsistent internal image.
 * @note Checks the readable image produced by this release's compiler once;
 * this pointer-only API cannot validate arbitrary or truncated external storage.
 */
TLV_API tlv_result_t tlv_query_exec_size(const tlv_query_program_t* program, size_t max_depth,
                                         size_t* bytes, size_t* alignment);

/**
 * @brief Initialize or reset independent S0/S1 execution in caller workspace.
 * @param[in] program Required immutable program; must remain alive and unchanged
 * throughout execution. Feed does not repeat initialization validation.
 * @param[in,out] storage Required aligned workspace, exclusive to this execution.
 * @param[in] capacity Available workspace bytes.
 * @param[in] max_depth Maximum node depth.
 * @param[in] max_elements Maximum published nodes, including nonmatches.
 * @param[in] max_work Maximum charged state evaluations and inspected Value bytes.
 * @param[out] exec Required borrowed execution handle, unchanged on failure.
 * @return #TLV_OK; #TLV_ERR_BUFFER_TOO_SHORT for short storage;
 * #TLV_ERR_INVALID_ARG for alignment/zero budgets; otherwise exec_size errors.
 * @note Never allocates. Program and workspace must not overlap.
 */
TLV_API tlv_result_t tlv_query_exec_init(const tlv_query_program_t* program, void* storage,
                                         size_t capacity, size_t max_depth, size_t max_elements,
                                         size_t max_work, tlv_query_exec_t** exec);

/** @brief Bind one typed variable before consuming any event.
 * @param[in,out] exec Required fresh initialized execution.
 * @param[in] name Required variable name without dollar prefix.
 * @param[in] type Integer, bytes or UTF-8 string category matching its declaration.
 * @param[in] integer Signed value used only for integer bindings.
 * @param[in] data Borrowed bytes/string; NULL is permitted for an empty span.
 * @param[in] size Span bytes, ignored for integer bindings.
 * @param[out] diagnostic Optional binding failure detail.
 * @return #TLV_OK; #TLV_ERR_NULL_ARG for missing pointers; #TLV_ERR_INVALID_ARG
 * for unknown/duplicate/incompatible bindings or used execution.
 * @note No text interpolation or allocation occurs. Span storage must remain alive
 * and unchanged until reset. To copy a span, the caller copies into its own storage.
 * Reinitialization clears all bindings. Rebinding during STOP/NEED_MORE_DATA is invalid.
 * Invalid bindings leave state unchanged. All referenced variables must be bound
 * before the first event, including variables in predicates with no matching nodes. */
TLV_API tlv_result_t tlv_query_exec_bind(tlv_query_exec_t* exec, const char* name,
                                         tlv_query_result_kind_t type, int64_t integer,
                                         const uint8_t* data, size_t size,
                                         tlv_query_diagnostic_t* diagnostic);

/**
 * @brief Select a relative node context before feeding events.
 * @param[in,out] exec Required fresh execution; no event may have been consumed.
 * @param[in] ordinal Zero-based preorder identity below the element budget.
 * @return #TLV_OK; #TLV_ERR_NULL_ARG for NULL execution; #TLV_ERR_INVALID_ARG
 * for used execution or an out-of-budget identity.
 * @note Absolute paths still use the virtual root. Relative paths select children
 * of this context; dot selects it. Missing context fails at EOF. Ancestor
 * evidence includes outside ancestors. Retained evaluation keeps complete borrowed events until
 * reset; failure preserves state.
 */
TLV_API tlv_result_t tlv_query_exec_context(tlv_query_exec_t* exec, size_t ordinal);

/** @brief Observed execution work and structural validation coverage. */
typedef struct tlv_query_exec_info {
    size_t struct_size; /**< Caller-provided writable extent; initialize to sizeof this type. */
    size_t elements;    /**< Published nodes, including nonmatches. */
    size_t work;        /**< Charged state/byte work. */
    size_t skipped_subtrees; /**< Explicitly omitted descendant extents. */
    int finished;            /**< Balanced final EOF was reached. */
    int full_validation;     /**< Finished successfully without omitted descendants. */
    int invalid;             /**< Execution failed and requires reset. */
} tlv_query_exec_info_t;

/**
 * @brief Enable or disable proven subtree pruning before feeding events.
 * @param[in,out] exec Required fresh execution.
 * @param[in] enabled Zero disables; nonzero explicitly permits partial validation.
 * @return #TLV_OK; #TLV_ERR_NULL_ARG for NULL; #TLV_ERR_INVALID_ARG for used state.
 * @note The adapter prunes only exhausted forward child plans with no possible
 * descendant match. Descendant plans and selected relative contexts are conservatively
 * drained. Malformed skipped descendants can be concealed; framing errors still propagate.
 */
TLV_API tlv_result_t tlv_query_exec_pruning(tlv_query_exec_t* exec, int enabled);

/**
 * @brief Read execution counters and coverage without altering continuation.
 * @param[in] exec Required initialized execution.
 * @param[in,out] info Required observed status output with initialized struct_size.
 * @return #TLV_OK; #TLV_ERR_NULL_ARG for a missing pointer.
 * @note Never allocates. STOP/NEED_MORE_DATA do not imply finished/full validation.
 * Writes are bounded by struct_size, which must cover elements; struct_size and
 * unknown trailing caller bytes are preserved. Invalid extents return #TLV_ERR_INVALID_ARG.
 */
TLV_API tlv_result_t tlv_query_exec_info(const tlv_query_exec_t* exec, tlv_query_exec_info_t* info);

/**
 * @brief Feed one complete canonical event and report whether its node matches.
 * @param[in,out] exec Required initialized execution.
 * @param[in] event Required complete event. S0 borrows during this call; retained execution
 * borrows its complete spans until reset.
 * @param[out] matched Required zero/one result; S1 END selects its original BEGIN.
 * @param[out] diagnostic Optional failure detail.
 * @return #TLV_OK; #TLV_ERR_INVALID_ARG for invalid sequence;
 * #TLV_ERR_LIMIT for depth/elements/work; #TLV_ERR_INVALID_VALUE for
 * unavailable Source metadata; #TLV_ERR_NULL_ARG for missing pointers.
 * @note Errors invalidate execution until reset. S1 accepts proven independent root
 * scopes only; use exec_selected for delayed publications. S1 borrows one root's
 * complete spans through its END, requiring stable backing storage across windows.
 * S0 retains no borrowed payload;
 * retained execution reports matched=0 and publishes results only after finish.
 * Each node is emitted at most once, in preorder. Skipped END is rejected under
 * the default full-validation policy. Values must be complete contiguous spans.
 */
TLV_API tlv_result_t tlv_query_exec_feed(tlv_query_exec_t* exec, const tlv_tree_event_t* event,
                                         int* matched, tlv_query_diagnostic_t* diagnostic);

/** @brief Read the node selected by the most recent successful S1 feed.
 * @param[in] exec S1 execution whose most recent feed reported matched=1.
 * @param[out] event Original complete BEGIN/ELEMENT metadata, unchanged on failure.
 * @return OK, NULL argument or invalid state.
 * @note A matched END selects its original BEGIN. Complete spans borrow stable caller
 * input; feeding another event supersedes this publication. No allocation or payload copy. */
TLV_API tlv_result_t tlv_query_exec_selected(const tlv_query_exec_t* exec, tlv_tree_event_t* event);

/**
 * @brief Complete the virtual root at final EOF and require balanced events.
 * @param[in,out] exec Required active execution.
 * @param[out] diagnostic Optional failure detail.
 * @return #TLV_OK on balanced EOF; #TLV_ERR_INVALID_ARG on invalid/unbalanced
 * feed; #TLV_ERR_NULL_ARG for NULL execution. Repeated successful finish is harmless.
 */
TLV_API tlv_result_t tlv_query_exec_finish(tlv_query_exec_t* exec,
                                           tlv_query_diagnostic_t* diagnostic);

/** @brief Visitor for one borrowed matching BEGIN or ELEMENT event.
 * @param[in] event Complete matching node; borrowed only for this call.
 * @param[in] context Caller-provided callback context.
 * @return Continue, stop after this event, or report a visitor error. */
typedef tlv_visit_result_t (*tlv_query_event_visitor_t)(const tlv_tree_event_t* event,
                                                        void* context);

/**
 * @brief Run compiled Query over the canonical Tree Reader with resumable continuation.
 * @param[in,out] reader Required cursor at a tree boundary, then exclusively used here.
 * @param[in,out] exec Required active execution retained across resumable outcomes.
 * @param[in] visitor Required callback; no retained payload lifetime is extended.
 * @param[in] context Optional callback context.
 * @param[out] diagnostic Optional Query and original Reader detail.
 * @return #TLV_OK at validated EOF or callback STOP; #TLV_NEED_MORE_DATA
 * without partial events; #TLV_ERR_VISITOR for callback error; original Reader
 * or Query error otherwise; #TLV_ERR_NULL_ARG for missing arguments.
 * @warning Callback effects are not rolled back. STOP is partial validation;
 * resume to final EOF for full structural coverage. Retained execution validates input before
 * callbacks and retains borrowed spans until reset; its STOP resumes the finalized sequence. No
 * Schema/DER semantic validation is implied. Replace input only under Reader frontier rules.
 */
TLV_API tlv_result_t tlv_query_program_visit(tlv_tree_reader_t* reader, tlv_query_exec_t* exec,
                                             tlv_query_event_visitor_t visitor, void* context,
                                             tlv_query_diagnostic_t* diagnostic);

/**
 * @brief Test existence with explicit full-validation or early-return behavior.
 * @param[in,out] reader Required exclusive Tree Reader.
 * @param[in,out] exec Required execution, retained across NEED_MORE_DATA.
 * @param[in] early_return Nonzero returns at the first match; zero drains to final EOF.
 * @param[out] found Required boolean output; unchanged on failure or NEED_MORE_DATA.
 * @param[out] diagnostic Optional failure detail.
 * @return #TLV_OK with existence result; otherwise original visit/Reader errors.
 * @note Matches observed earlier in this execution remain part of existence.
 * Early-return success has partial coverage; inspect exec_info or resume with
 * early_return zero. A malformed suffix still fails full-validation mode.
 */
TLV_API tlv_result_t tlv_query_program_exists(tlv_tree_reader_t* reader, tlv_query_exec_t* exec,
                                              int early_return, int* found,
                                              tlv_query_diagnostic_t* diagnostic);

/** @brief Discover retained-event workspace for compiled Query results.
 * @param[in] program Immutable live program.
 * @param[in] max_depth Maximum node depth.
 * @param[in] max_nodes Explicit nonzero retained-node capacity.
 * @param[out] bytes Required caller workspace bytes.
 * @param[out] alignment Required alignment.
 * @return OK or NULL/invalid-image/capacity/overflow errors. No hidden node set. */
TLV_API tlv_result_t tlv_query_eval_size(const tlv_query_program_t* program, size_t max_depth,
                                         size_t max_nodes, size_t* bytes, size_t* alignment);

/** @brief Initialize retained canonical-event execution and bounded iterative evaluation.
 * @param[in] program Live immutable program.
 * @param[in] environment Compatible borrowed providers; NULL when none required.
 * @param[in,out] storage Aligned exclusive caller workspace.
 * @param[in] capacity Workspace bytes.
 * @param[in] max_depth Maximum node depth.
 * @param[in] max_nodes Explicit retained-node capacity.
 * @param[in] max_work Charged instruction/byte work limit.
 * @param[out] exec Execution handle, unchanged on failure.
 * @return OK or size/alignment/environment errors. D plans initialize for Document only.
 * @note Feed borrows complete events until reset. Input, Source and environment must
 * remain immutable/alive through suspension, even when Reader replaces its current
 * window. Retention capacity covers every published node, not just final matches;
 * descriptors and VM node sets are sized by eval_size. Payload bytes are never copied.
 * Overflow reports the named candidates limit and invalidates until reset. No callbacks
 * have run before finalized retained publication; callback effects never roll back.
 * D plans reject event/Reader execution before consuming input. Pruning is unavailable; results
 * become public only after balanced EOF and successful evaluation. No allocation occurs. */
TLV_API tlv_result_t tlv_query_eval_init(const tlv_query_program_t* program,
                                         const tlv_query_environment_t* environment, void* storage,
                                         size_t capacity, size_t max_depth, size_t max_nodes,
                                         size_t max_work, tlv_query_exec_t** exec);

/** @brief Read a finalized scalar or node result category.
 * @param[in] exec Successfully finished retained execution.
 * @param[out] result Tagged output, unchanged before completion/error.
 * @return OK or NULL/invalid-state errors. */
TLV_API tlv_result_t tlv_query_exec_result(const tlv_query_exec_t* exec,
                                           tlv_query_result_t* result);

/** @brief Pull finalized unique node events in document order.
 * @param[in,out] exec Successfully finished retained node-result execution.
 * @param[out] event Matching event, unchanged on exhaustion/error.
 * @return OK, END_OF_BUFFER, or NULL/invalid-state errors. */
TLV_API tlv_result_t tlv_query_result_next(tlv_query_exec_t* exec, tlv_tree_event_t* event);

/** @brief Format normalized plan details; sizing and atomic short-output handling.
 * @param[in] program Live program.
 * @param[out] output Optional destination, NULL with zero capacity for sizing.
 * @param[in] capacity Output bytes including terminator.
 * @param[out] required Required bytes including terminator.
 * @return OK or pointer/image/capacity errors. */
TLV_API tlv_result_t tlv_query_program_explain(const tlv_query_program_t* program, char* output,
                                               size_t capacity, size_t* required);

/** @} */
#ifdef __cplusplus
}
#endif
#endif
