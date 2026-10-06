// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#ifndef OPENTLV_QUERY_PLAN_H
#define OPENTLV_QUERY_PLAN_H
#include "tlv/query/program.h"

/** @file
 * @ingroup traversal
 * @brief Release-specific C representation shared by runtime and static Query plans.
 * @note This is a native C layout, not a persistent serialization ABI. Rebuild
 * generated plans when TLV_QUERY_PLAN_VERSION changes. All words use host byte order.
 * An image contains header, count instructions, text_size optional diagnostic bytes
 * plus a zero terminator, then payload_size bytes. No pointers enter the image.
 * Use tlv_query_plan_open() before executing manually constructed or external data.
 */
/** @addtogroup traversal
 * @{ */
/** @brief Native image signature; swapped byte order is incompatible. */
#define TLV_QUERY_PLAN_MAGIC UINT32_C(0x51525932)
/** @brief Exact supported representation version, independent of language version. */
#define TLV_QUERY_PLAN_VERSION UINT32_C(6)
/** @brief Absent instruction reference. All other references point backward. */
#define TLV_QUERY_PLAN_NONE UINT32_MAX
/** @brief Closed plan opcode selectors. */
typedef enum tlv_query_plan_opcode {
    TLV_QUERY_OP_TEST,      /**< test selector. */
    TLV_QUERY_OP_ROOT,      /**< root selector. */
    TLV_QUERY_OP_SELF,      /**< self selector. */
    TLV_QUERY_OP_META,      /**< meta selector. */
    TLV_QUERY_OP_LITERAL,   /**< literal selector. */
    TLV_QUERY_OP_BYTES,     /**< bytes selector. */
    TLV_QUERY_OP_STRING,    /**< string selector. */
    TLV_QUERY_OP_VARIABLE,  /**< variable selector. */
    TLV_QUERY_OP_CHILD,     /**< child selector. */
    TLV_QUERY_OP_DESC,      /**< desc selector. */
    TLV_QUERY_OP_FILTER,    /**< filter selector. */
    TLV_QUERY_OP_UNION,     /**< union selector. */
    TLV_QUERY_OP_INTERSECT, /**< intersect selector. */
    TLV_QUERY_OP_EXCEPT,    /**< except selector. */
    TLV_QUERY_OP_EQ,        /**< eq selector. */
    TLV_QUERY_OP_NE,        /**< ne selector. */
    TLV_QUERY_OP_LT,        /**< lt selector. */
    TLV_QUERY_OP_LE,        /**< le selector. */
    TLV_QUERY_OP_GT,        /**< gt selector. */
    TLV_QUERY_OP_GE,        /**< ge selector. */
    TLV_QUERY_OP_AND,       /**< and selector. */
    TLV_QUERY_OP_OR,        /**< or selector. */
    TLV_QUERY_OP_CALL,      /**< call selector. */
    TLV_QUERY_OP_ARGS,      /**< args selector. */
    TLV_QUERY_OP_BOOL,      /**< bool selector. */
} tlv_query_plan_opcode_t;
/** @brief Closed plan axis selectors. */
typedef enum tlv_query_plan_axis {
    TLV_QUERY_AXIS_CHILD,           /**< child selector. */
    TLV_QUERY_AXIS_SELF,            /**< self selector. */
    TLV_QUERY_AXIS_DESC,            /**< desc selector. */
    TLV_QUERY_AXIS_ANCESTOR,        /**< ancestor selector. */
    TLV_QUERY_AXIS_DESC_SELF,       /**< desc self selector. */
    TLV_QUERY_AXIS_PARENT,          /**< parent selector. */
    TLV_QUERY_AXIS_ANCESTOR_SELF,   /**< ancestor self selector. */
    TLV_QUERY_AXIS_FOLLOW_SIBLING,  /**< follow sibling selector. */
    TLV_QUERY_AXIS_PRECEDE_SIBLING, /**< precede sibling selector. */
    TLV_QUERY_AXIS_FOLLOW,          /**< follow selector. */
    TLV_QUERY_AXIS_PRECEDE,         /**< precede selector. */
} tlv_query_plan_axis_t;
/** @brief Closed plan function selectors. */
typedef enum tlv_query_plan_function {
    TLV_QUERY_FN_VALUE,       /**< value selector. */
    TLV_QUERY_FN_LEN,         /**< len selector. */
    TLV_QUERY_FN_NOT,         /**< not selector. */
    TLV_QUERY_FN_STARTS,      /**< starts selector. */
    TLV_QUERY_FN_ENDS,        /**< ends selector. */
    TLV_QUERY_FN_CONTAINS,    /**< contains selector. */
    TLV_QUERY_FN_SUBSTR,      /**< substr selector. */
    TLV_QUERY_FN_MASK,        /**< mask selector. */
    TLV_QUERY_FN_RANGE,       /**< range selector. */
    TLV_QUERY_FN_COUNT,       /**< count selector. */
    TLV_QUERY_FN_EXISTS,      /**< exists selector. */
    TLV_QUERY_FN_EMPTY,       /**< empty selector. */
    TLV_QUERY_FN_POSITION,    /**< position selector. */
    TLV_QUERY_FN_LAST,        /**< last selector. */
    TLV_QUERY_FN_NUM,         /**< num selector. */
    TLV_QUERY_FN_BCD,         /**< bcd selector. */
    TLV_QUERY_FN_TEXT,        /**< text selector. */
    TLV_QUERY_FN_DATE,        /**< date selector. */
    TLV_QUERY_FN_TAG,         /**< tag selector. */
    TLV_QUERY_FN_CLASS,       /**< class selector. */
    TLV_QUERY_FN_CONSTRUCTED, /**< constructed selector. */
    TLV_QUERY_FN_NUMBER,      /**< number selector. */
    TLV_QUERY_FN_NAME,        /**< name selector. */
    TLV_QUERY_FN_UNKNOWN,     /**< unknown selector. */
} tlv_query_plan_function_t;
/** @brief Metadata selectors for TLV_QUERY_OP_META. */
typedef enum tlv_query_plan_metadata {
    TLV_QUERY_META_LEN,    /**< Logical Value length. */
    TLV_QUERY_META_DEPTH,  /**< Tree depth. */
    TLV_QUERY_META_INDEX,  /**< Sibling index. */
    TLV_QUERY_META_OFFSET, /**< Source offset. */
    TLV_QUERY_META_HLEN    /**< Source Header size. */
} tlv_query_plan_metadata_t;
/** @brief Internal value categories used by instruction type fields. */
typedef enum tlv_query_plan_type {
    TLV_QUERY_PLAN_NODES,   /**< Node selection. */
    TLV_QUERY_PLAN_BOOL,    /**< Boolean. */
    TLV_QUERY_PLAN_INTEGER, /**< Signed integer. */
    TLV_QUERY_PLAN_BYTES,   /**< Byte span. */
    TLV_QUERY_PLAN_STRING   /**< UTF-8 span. */
} tlv_query_plan_type_t;
/** @brief One immutable, topologically ordered execution instruction. */
typedef struct tlv_query_instruction {
    uint32_t op;              /**< Operation selector. */
    uint32_t left;            /**< Left operand or PLAN_NONE. */
    uint32_t right;           /**< Right operand or PLAN_NONE. */
    uint32_t begin;           /**< Optional diagnostic start offset. */
    uint32_t end;             /**< Optional diagnostic end offset. */
    uint32_t axis;            /**< Navigation axis. */
    uint32_t anchor;          /**< Root/context anchor; 2 marks positional literals. */
    uint32_t scalar;          /**< Boolean predicate-context flag. */
    uint32_t type;            /**< Plan value category. */
    uint32_t low;             /**< First instruction in this expression subtree. */
    uint32_t predicate_guard; /**< Earlier predicate context or PLAN_NONE. */
    uint32_t path_guard;      /**< Earlier path prefix or PLAN_NONE. */
    uint32_t path_kind;       /**< CHILD, DESC or SELF opcode for a path guard. */
    uint32_t grouped;         /**< Boolean grouped-expression marker. */
    uint32_t nested;          /**< Boolean nested absolute-root marker. */
    uint32_t variable_slot;   /**< Zero-based runtime parameter slot. */
    uint32_t data_offset;     /**< Payload byte offset for constant, tag or parameter name. */
    uint32_t data_size;       /**< Payload byte count; names exclude a terminator. */
    uint32_t resolved;        /**< Tag mode: 0 wildcard, 1 exact, 2 masked. */
    uint32_t hook_id;         /**< Stable application-defined codec contract ID; zero if unused. */
    uint32_t scratch_size;    /**< Aligned codec scratch bound. */
    uint32_t reuse;           /**< Equivalent earlier tag-test instruction or PLAN_NONE. */
    uint32_t folded;          /**< Boolean constant value. */
    uint32_t selector;        /**< Function or metadata selector. */
    uint32_t immediate_low;   /**< Low 32 bits of integer magnitude. */
    uint32_t immediate_high;  /**< High 32 bits of integer magnitude. */
    uint32_t negative;        /**< Integer sign, zero or one; zero has positive sign. */
    uint32_t context;         /**< Boolean dot/dot-dot abbreviation marker. */
    uint32_t mask_offset;     /**< Payload offset of data_size mask bytes for masked tags. */
} tlv_query_instruction_t;
/** @brief Native plan header; also the existing opaque program handle. */
typedef struct tlv_query_program {
    uint32_t magic;       /**< PLAN_MAGIC signature. */
    uint32_t version;     /**< Exact PLAN_VERSION. */
    uint32_t count;       /**< Nonzero instruction count. */
    uint32_t root;        /**< Result instruction index. */
    uint32_t text_size;   /**< Optional diagnostic/source text byte count, zero for static plans. */
    uint32_t text_offset; /**< sizeof(header) + count * sizeof(instruction). */
    uint32_t level;       /**< Required S0/S1/S2/D execution profile. */
    uint32_t reserved;    /**< Exact image extent, including terminator and payload. */
    uint32_t variable_count;   /**< Number of parameter slots. */
    uint32_t payload_size;     /**< Payload byte extent. */
    uint32_t pattern_capacity; /**< Maximum runtime search-pattern length. */
    uint32_t codec_stride;     /**< Maximum codec scratch stride, a multiple of 16. */
    uint32_t tag_id;           /**< Stable semantic tag-provider contract ID; zero if unused. */
} tlv_query_plan_t;
#ifdef __cplusplus
extern "C" {
#endif
/** @brief Validate and borrow a bounded native plan without a Query frontend.
 * @param[in] image Aligned readable image, immutable while borrowed.
 * @param[in] size Exact byte extent, excluding any trailing C structure padding.
 * @param[out] program Borrowed execution handle, set only on success.
 * @param[out] diagnostic Optional initialized error detail.
 * @return OK, NULL_ARG, INVALID_ARG for malformed plans, or UNSUPPORTED_TYPE
 * for incompatible versions or unavailable execution capabilities.
 * @note No allocation, parsing, name resolution or planning occurs. Runtime
 * provider compatibility is checked by eval_init. Resolved names are copied raw
 * tag bytes; changing their model mapping requires rebuilding the plan. Hook
 * and semantic-tag IDs denote application-owned immutable semantic contracts,
 * not internal schema indices. Keep their meaning stable or assign new IDs.
 * Image, program output and diagnostic must be disjoint. Overlap is rejected
 * before writes, including diagnostic initialization.
 */
TLV_API tlv_result_t tlv_query_plan_open(const void* image, size_t size,
                                         const tlv_query_program_t** program,
                                         tlv_query_diagnostic_t* diagnostic);
/** @brief Inspect requirements of a validated immutable plan without the frontend.
 * @param[in] program Handle returned by plan_open or runtime compilation.
 * @param[in,out] info Output with struct_size initialized to its writable extent.
 * @return OK, NULL_ARG or INVALID_ARG for an invalid handle or output extent.
 * @note Compiler scratch and optimization-history fields are zero. Execution
 * sizing still takes application depth/node limits through exec_size or eval_size.
 */
TLV_API tlv_result_t tlv_query_plan_info(const tlv_query_program_t* program,
                                         tlv_query_program_info_t* info);
#ifdef __cplusplus
}
#endif
/** @} */
#endif
