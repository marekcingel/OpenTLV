// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#ifndef OPENTLV_TLVPP_QUERY_STATIC_HPP
#define OPENTLV_TLVPP_QUERY_STATIC_HPP
#include "tlv++/query/program.hpp"
#include <array>

/** @file
 * @brief C++11 constexpr composition of the canonical C Query plan.
 * @note This typed builder emits native instructions, not query text. Its initial
 * vocabulary covers raw child/descendant paths, metadata, integer/byte constants,
 * typed named parameters, comparisons and Boolean predicates. Use the runtime
 * compiler for the rest of the language. No alternative executor is introduced.
 */
namespace tlv {
namespace static_query {
/** @cond INTERNAL */
namespace detail {
constexpr uint32_t none = TLV_QUERY_PLAN_NONE;
template <size_t... I> struct indices {};
template <size_t N, size_t... I> struct sequence : sequence<N - 1, N - 1, I...> {};
template <size_t... I> struct sequence<0, I...> {
    using type = indices<I...>;
};
constexpr uint32_t shifted(uint32_t i, size_t base) {
    return i == none ? none : static_cast<uint32_t>(i + base);
}
constexpr uint64_t magnitude(int64_t value) {
    return value < 0 ? static_cast<uint64_t>(-(value + 1)) + 1 : static_cast<uint64_t>(value);
}
constexpr tlv_query_instruction_t node(uint32_t op, uint32_t type, uint32_t left = none,
                                       uint32_t right = none, uint32_t bytes = 0,
                                       uint32_t selector = 0, int64_t value = 0,
                                       uint32_t axis = TLV_QUERY_AXIS_CHILD) {
    return {op,
            left,
            right,
            0,
            0,
            axis,
            op == TLV_QUERY_OP_TEST ? 1u : 0u,
            0,
            type,
            0,
            none,
            none,
            0,
            0,
            0,
            0,
            0,
            bytes,
            op == TLV_QUERY_OP_TEST && bytes ? 1u : 0u,
            0,
            0,
            none,
            0,
            selector,
            static_cast<uint32_t>(magnitude(value)),
            static_cast<uint32_t>(magnitude(value) >> 32),
            value < 0 ? 1u : 0u,
            0,
            0};
}
constexpr bool path_entry(const tlv_query_instruction_t& n, uint32_t op) {
    return op == TLV_QUERY_OP_CHILD && n.op == TLV_QUERY_OP_TEST && n.predicate_guard == none &&
           n.path_guard == none;
}
constexpr tlv_query_instruction_t relocate(const tlv_query_instruction_t& n, size_t base,
                                           size_t payload, uint32_t op = TLV_QUERY_OP_EQ,
                                           uint32_t parent = none, uint32_t slot = 0) {
    return {n.op,
            shifted(n.left, base),
            shifted(n.right, base),
            0,
            0,
            n.axis,
            path_entry(n, op) ? 0u : n.anchor,
            n.scalar,
            n.type,
            static_cast<uint32_t>(n.low + base),
            op == TLV_QUERY_OP_FILTER && n.predicate_guard == none
                ? parent
                : shifted(n.predicate_guard, base),
            path_entry(n, op) ? parent : shifted(n.path_guard, base),
            path_entry(n, op)
                ? static_cast<uint32_t>(n.axis == TLV_QUERY_AXIS_DESC ? TLV_QUERY_OP_DESC
                                                                      : TLV_QUERY_OP_CHILD)
                : n.path_kind,
            n.grouped,
            n.nested,
            slot,
            static_cast<uint32_t>(n.data_offset + payload),
            n.data_size,
            n.resolved,
            n.hook_id,
            n.scratch_size,
            shifted(n.reuse, base),
            n.folded,
            n.selector,
            n.immediate_low,
            n.immediate_high,
            n.negative,
            n.context,
            static_cast<uint32_t>(n.mask_offset + payload)};
}
constexpr bool letter(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}
constexpr bool name_tail(const char* name, size_t size, size_t i) {
    return i == size || ((letter(name[i]) || (name[i] >= '0' && name[i] <= '9') || name[i] == '_' ||
                          name[i] == '-') &&
                         name_tail(name, size, i + 1));
}
} // namespace detail
/** @endcond */
template <size_t N, size_t P> class plan;
/** @brief Immutable typed instruction composition, usable in C++11 constant expressions.
 * @tparam N Instruction count.
 * @tparam P Payload byte count.
 * @tparam Kind Native plan result category. */
template <size_t N, size_t P, tlv_query_plan_type_t Kind> struct expression {
    std::array<tlv_query_instruction_t, N> nodes;   /**< Immutable instruction values. */
    std::array<uint8_t, P>                 payload; /**< Raw constant/tag/name bytes. */
    /** @brief Materialize a source-free native plan; constexpr evaluates at compile time.
     * @return Owned inline plan; conflicting parameter types reject constant evaluation.
     * @note Node plans include an explicit virtual root and path join, preserving
     * absolute-path semantics even when execution has a relative context. These
     * two instructions count toward the native 128-instruction limit. */
    constexpr plan<N + (Kind == TLV_QUERY_PLAN_NODES ? 2 : 0), P> compile() const;
};
/** @cond INTERNAL */
namespace detail {
template <size_t N, size_t P, tlv_query_plan_type_t K>
constexpr tlv_query_instruction_t rooted_node(const expression<N, P, K>& e, size_t i) {
    return K != TLV_QUERY_PLAN_NODES ? e.nodes[i]
           : i == 0                  ? node(TLV_QUERY_OP_ROOT, TLV_QUERY_PLAN_NODES)
           : i == N + 1
               ? node(TLV_QUERY_OP_CHILD, TLV_QUERY_PLAN_NODES, 0, static_cast<uint32_t>(N))
               : relocate(e.nodes[i - 1], 1, 0, TLV_QUERY_OP_CHILD, 0);
}
template <size_t N, size_t P, tlv_query_plan_type_t K, size_t... I>
constexpr expression<N + (K == TLV_QUERY_PLAN_NODES ? 2 : 0), P, K>
rooted(const expression<N, P, K>& e, indices<I...>) {
    return {{{rooted_node(e, I)...}}, e.payload};
}
template <size_t N, size_t P, tlv_query_plan_type_t K>
constexpr bool same_bytes(const expression<N, P, K>& e, size_t a, size_t b, size_t i = 0) {
    return e.nodes[a].data_size == e.nodes[b].data_size &&
           (i == e.nodes[a].data_size ||
            (e.payload[e.nodes[a].data_offset + i] == e.payload[e.nodes[b].data_offset + i] &&
             same_bytes(e, a, b, i + 1)));
}
template <size_t N, size_t P, tlv_query_plan_type_t K>
constexpr size_t first_parameter(const expression<N, P, K>& e, size_t i, size_t j = 0) {
    return j == i || (e.nodes[j].op == TLV_QUERY_OP_VARIABLE && same_bytes(e, i, j))
               ? j
               : first_parameter(e, i, j + 1);
}
template <size_t N, size_t P, tlv_query_plan_type_t K>
constexpr uint32_t parameters(const expression<N, P, K>& e, size_t end) {
    return !end ? 0
                : parameters(e, end - 1) + (e.nodes[end - 1].op == TLV_QUERY_OP_VARIABLE &&
                                                    first_parameter(e, end - 1) == end - 1
                                                ? 1u
                                                : 0u);
}
template <size_t N, size_t P, tlv_query_plan_type_t K>
constexpr bool consistent(const expression<N, P, K>& e, size_t i = 0) {
    return i == N || ((e.nodes[i].op != TLV_QUERY_OP_VARIABLE ||
                       e.nodes[first_parameter(e, i)].type == e.nodes[i].type) &&
                      consistent(e, i + 1));
}
template <size_t N, size_t P, tlv_query_plan_type_t K>
constexpr tlv_query_instruction_t materialize(const expression<N, P, K>& e, size_t i) {
    return relocate(e.nodes[i], 0, 0, TLV_QUERY_OP_EQ, none,
                    e.nodes[i].op == TLV_QUERY_OP_VARIABLE ? parameters(e, first_parameter(e, i))
                                                           : 0);
}
template <size_t N, size_t P> struct image {
    tlv_query_plan_t                       header;
    std::array<tlv_query_instruction_t, N> nodes;
    char                                   source[1];
    std::array<uint8_t, P ? P : 1>         payload;
};
template <size_t N, size_t P, tlv_query_plan_type_t K>
constexpr uint8_t payload_byte(const expression<N, P, K>& e, size_t i) {
    return i < P ? e.payload[i] : 0;
}
} // namespace detail
/** @endcond */
/** @brief Owned inline native plan, suitable for static constexpr storage.
 * @tparam N Instruction count.
 * @tparam P Payload byte count.
 * @note A borrowed program never extends this object's lifetime. Keep this object
 * immutable and alive through every program and execution that borrows it. */
template <size_t N, size_t P> class plan {
    using image_type = detail::image<N, P>;
    image_type image_;
    template <size_t... I, size_t... B, tlv_query_plan_type_t K>
    constexpr plan(const expression<N, P, K>& e, detail::indices<I...>, detail::indices<B...>)
        : image_{{TLV_QUERY_PLAN_MAGIC, TLV_QUERY_PLAN_VERSION, static_cast<uint32_t>(N),
                  static_cast<uint32_t>(N - 1), 0,
                  static_cast<uint32_t>(sizeof(tlv_query_plan_t) +
                                        N * sizeof(tlv_query_instruction_t)),
                  K == TLV_QUERY_PLAN_NODES ? TLV_QUERY_S0 : TLV_QUERY_S2,
                  static_cast<uint32_t>(sizeof(tlv_query_plan_t) +
                                        N * sizeof(tlv_query_instruction_t) + 1 + P),
                  detail::parameters(e, N), static_cast<uint32_t>(P), 0, 0, 0},
                 {{detail::materialize(e, I)...}},
                 {0},
                 {{detail::payload_byte(e, B)...}}} {}

public:
    /** @brief Materialize typed native instructions; no runtime parser is involved.
     * @param e Typed expression with consistent named parameter types. */
    template <tlv_query_plan_type_t K>
    constexpr explicit plan(const expression<N, P, K>& e)
        : plan(e, typename detail::sequence<N>::type{},
               typename detail::sequence < P ? P : 1 > ::type{}) {
        static_assert(N > 0 && N <= 128, "constexpr Query supports 1..128 instructions");
        static_assert(P <= 65536, "constexpr Query payload limit is 65536 bytes");
        static_assert(sizeof(std::array<tlv_query_instruction_t, N>) ==
                          N * sizeof(tlv_query_instruction_t),
                      "native instruction layout required");
        static_assert(offsetof(image_type, nodes) == sizeof(tlv_query_plan_t),
                      "native image layout required");
        static_assert(offsetof(image_type, payload) ==
                          sizeof(tlv_query_plan_t) + N * sizeof(tlv_query_instruction_t) + 1,
                      "native payload layout required");
    }
    /** @brief Inspect the native header during constant evaluation. */
    constexpr const tlv_query_plan_t& header() const {
        return image_.header;
    }
    /** @brief Inspect a native instruction; index must be less than header().count. */
    constexpr const tlv_query_instruction_t& instruction(size_t index) const {
        return image_.nodes[index];
    }
    /** @brief Borrow native image bytes for C interoperability. */
    const void* data() const& {
        return &image_;
    }
    /** @brief Prevent borrowing a temporary plan. */
    const void* data() const&& = delete;
    /** @brief Exact native image extent, excluding trailing C++ object padding. */
    constexpr size_t size() const {
        return image_.header.reserved;
    }
    /** @brief Validate and borrow through the existing C++ Query facade without allocation. */
    expected<query_program, query_failure> program() const& {
        return query_program::from_plan(data(), size());
    }
    /** @brief Prevent returning a program that borrows a temporary plan. */
    expected<query_program, query_failure> program() const&& = delete;
};
template <size_t N, size_t P, tlv_query_plan_type_t K>
constexpr plan<N + (K == TLV_QUERY_PLAN_NODES ? 2 : 0), P> expression<N, P, K>::compile() const {
    return detail::consistent(*this)
               ? plan<N + (K == TLV_QUERY_PLAN_NODES ? 2 : 0), P>(detail::rooted(
                     *this,
                     typename detail::sequence<N + (K == TLV_QUERY_PLAN_NODES ? 2 : 0)>::type{}))
               : throw std::invalid_argument("conflicting constexpr Query parameter types");
}
/** @cond INTERNAL */
namespace detail {
template <uint32_t Op, tlv_query_plan_type_t K, size_t N, size_t P, tlv_query_plan_type_t L,
          size_t M, size_t Q, tlv_query_plan_type_t R>
constexpr tlv_query_instruction_t combined_node(const expression<N, P, L>& a,
                                                const expression<M, Q, R>& b, size_t i) {
    return i < N       ? a.nodes[i]
           : i < N + M ? relocate(b.nodes[i - N], N, P, Op, N - 1)
                       : node(Op, K, N - 1, N + M - 1);
}
template <size_t N, size_t P, tlv_query_plan_type_t L, size_t M, size_t Q, tlv_query_plan_type_t R>
constexpr uint8_t combined_byte(const expression<N, P, L>& a, const expression<M, Q, R>& b,
                                size_t i) {
    return i < P ? a.payload[i] : b.payload[i - P];
}
template <uint32_t Op, tlv_query_plan_type_t K, size_t N, size_t P, tlv_query_plan_type_t L,
          size_t M, size_t Q, tlv_query_plan_type_t R, size_t... I, size_t... B>
constexpr expression<N + M + 1, P + Q, K>
combine(const expression<N, P, L>& a, const expression<M, Q, R>& b, indices<I...>, indices<B...>) {
    return {{{combined_node<Op, K>(a, b, I)...}}, {{combined_byte(a, b, B)...}}};
}
template <uint32_t Op, tlv_query_plan_type_t K, size_t N, size_t P, tlv_query_plan_type_t L,
          size_t M, size_t Q, tlv_query_plan_type_t R>
constexpr expression<N + M + 1, P + Q, K> combine(const expression<N, P, L>& a,
                                                  const expression<M, Q, R>& b) {
    return combine<Op, K>(a, b, typename sequence<N + M + 1>::type{},
                          typename sequence<P + Q>::type{});
}
template <tlv_query_plan_type_t K, size_t N, size_t... I>
constexpr expression<1, N - 1, K> parameter(const char (&name)[N], indices<I...>) {
    return {{{node(TLV_QUERY_OP_VARIABLE, K, none, none, N - 1)}},
            {{static_cast<uint8_t>(name[I])...}}};
}
} // namespace detail
/** @endcond */
/** @brief Select an exact raw tag among root children; compose deeper paths with operator/.
 * @tparam Bytes Tag identity bytes; an empty pack selects any tag. */
template <uint8_t... Bytes>
constexpr expression<1, sizeof...(Bytes), TLV_QUERY_PLAN_NODES> child() {
    return {{{detail::node(TLV_QUERY_OP_TEST, TLV_QUERY_PLAN_NODES, detail::none, detail::none,
                           sizeof...(Bytes))}},
            {{Bytes...}}};
}
/** @brief Select descendants with an exact raw tag; an empty byte pack selects any tag. */
template <uint8_t... Bytes>
constexpr expression<1, sizeof...(Bytes), TLV_QUERY_PLAN_NODES> descendant() {
    return {{{detail::node(TLV_QUERY_OP_TEST, TLV_QUERY_PLAN_NODES, detail::none, detail::none,
                           sizeof...(Bytes), 0, 0, TLV_QUERY_AXIS_DESC)}},
            {{Bytes...}}};
}
/** @brief Logical Value length of the candidate node. */
constexpr expression<1, 0, TLV_QUERY_PLAN_INTEGER> length() {
    return {{{detail::node(TLV_QUERY_OP_META, TLV_QUERY_PLAN_INTEGER, detail::none, detail::none, 0,
                           TLV_QUERY_META_LEN)}},
            {{}}};
}
/** @brief Candidate tree depth. */
constexpr expression<1, 0, TLV_QUERY_PLAN_INTEGER> depth() {
    return {{{detail::node(TLV_QUERY_OP_META, TLV_QUERY_PLAN_INTEGER, detail::none, detail::none, 0,
                           TLV_QUERY_META_DEPTH)}},
            {{}}};
}
/** @brief Exact signed integer constant, including INT64_MIN. */
constexpr expression<1, 0, TLV_QUERY_PLAN_INTEGER> integer(int64_t value) {
    return {{{detail::node(TLV_QUERY_OP_LITERAL, TLV_QUERY_PLAN_INTEGER, detail::none, detail::none,
                           0, 0, value)}},
            {{}}};
}
/** @brief Raw byte constant. */
template <uint8_t... Bytes>
constexpr expression<1, sizeof...(Bytes), TLV_QUERY_PLAN_BYTES> bytes() {
    return {{{detail::node(TLV_QUERY_OP_BYTES, TLV_QUERY_PLAN_BYTES, detail::none, detail::none,
                           sizeof...(Bytes))}},
            {{Bytes...}}};
}
/** @brief Candidate Value bytes. */
constexpr expression<1, 0, TLV_QUERY_PLAN_BYTES> value() {
    return {{{detail::node(TLV_QUERY_OP_CALL, TLV_QUERY_PLAN_BYTES, detail::none, detail::none, 0,
                           TLV_QUERY_FN_VALUE)}},
            {{}}};
}
/** @brief Named runtime parameter; repeated names share one slot in first-reference order.
 * @tparam Kind Integer, bytes or string native plan category.
 * @param name ASCII variable identifier without a dollar prefix.
 * @return Typed parameter reference; invalid names reject constant evaluation. */
template <tlv_query_plan_type_t Kind = TLV_QUERY_PLAN_INTEGER, size_t N>
constexpr expression<1, N - 1, Kind> parameter(const char (&name)[N]) {
    static_assert(Kind == TLV_QUERY_PLAN_INTEGER || Kind == TLV_QUERY_PLAN_BYTES ||
                      Kind == TLV_QUERY_PLAN_STRING,
                  "supported parameter type");
    return N > 1 && name[N - 1] == 0 && detail::letter(name[0]) && detail::name_tail(name, N - 1, 1)
               ? detail::parameter<Kind>(name, typename detail::sequence<N - 1>::type{})
               : throw std::invalid_argument("invalid constexpr Query parameter name");
}
/** @brief Filter node selection by a Boolean predicate, using native eager semantics. */
template <size_t N, size_t P, size_t M, size_t Q>
constexpr expression<N + M + 1, P + Q, TLV_QUERY_PLAN_NODES>
where(const expression<N, P, TLV_QUERY_PLAN_NODES>& nodes,
      const expression<M, Q, TLV_QUERY_PLAN_BOOL>&  predicate) {
    return detail::combine<TLV_QUERY_OP_FILTER, TLV_QUERY_PLAN_NODES>(nodes, predicate);
}
/** @brief Compose a child/descendant path with the native prefix guards. */
template <size_t N, size_t P, size_t M, size_t Q>
constexpr expression<N + M + 1, P + Q, TLV_QUERY_PLAN_NODES>
operator/(const expression<N, P, TLV_QUERY_PLAN_NODES>& a,
          const expression<M, Q, TLV_QUERY_PLAN_NODES>& b) {
    return detail::combine<TLV_QUERY_OP_CHILD, TLV_QUERY_PLAN_NODES>(a, b);
}
/** @brief Compare like-typed scalar expressions through the native comparison operation. */
template <size_t N, size_t P, size_t M, size_t Q, tlv_query_plan_type_t K>
constexpr expression<N + M + 1, P + Q, TLV_QUERY_PLAN_BOOL>
operator==(const expression<N, P, K>& a, const expression<M, Q, K>& b) {
    static_assert(K != TLV_QUERY_PLAN_NODES, "node sets are not scalar operands");
    return detail::combine<TLV_QUERY_OP_EQ, TLV_QUERY_PLAN_BOOL>(a, b);
}
/** @brief Compare like-typed scalar expressions through the native comparison operation. */
template <size_t N, size_t P, size_t M, size_t Q, tlv_query_plan_type_t K>
constexpr expression<N + M + 1, P + Q, TLV_QUERY_PLAN_BOOL>
operator!=(const expression<N, P, K>& a, const expression<M, Q, K>& b) {
    static_assert(K != TLV_QUERY_PLAN_NODES, "node sets are not scalar operands");
    return detail::combine<TLV_QUERY_OP_NE, TLV_QUERY_PLAN_BOOL>(a, b);
}
/** @brief Compare like-typed scalar expressions through the native comparison operation. */
template <size_t N, size_t P, size_t M, size_t Q, tlv_query_plan_type_t K>
constexpr expression<N + M + 1, P + Q, TLV_QUERY_PLAN_BOOL>
operator<(const expression<N, P, K>& a, const expression<M, Q, K>& b) {
    static_assert(K != TLV_QUERY_PLAN_NODES, "node sets are not scalar operands");
    return detail::combine<TLV_QUERY_OP_LT, TLV_QUERY_PLAN_BOOL>(a, b);
}
/** @brief Compare like-typed scalar expressions through the native comparison operation. */
template <size_t N, size_t P, size_t M, size_t Q, tlv_query_plan_type_t K>
constexpr expression<N + M + 1, P + Q, TLV_QUERY_PLAN_BOOL>
operator<=(const expression<N, P, K>& a, const expression<M, Q, K>& b) {
    static_assert(K != TLV_QUERY_PLAN_NODES, "node sets are not scalar operands");
    return detail::combine<TLV_QUERY_OP_LE, TLV_QUERY_PLAN_BOOL>(a, b);
}
/** @brief Compare like-typed scalar expressions through the native comparison operation. */
template <size_t N, size_t P, size_t M, size_t Q, tlv_query_plan_type_t K>
constexpr expression<N + M + 1, P + Q, TLV_QUERY_PLAN_BOOL>
operator>(const expression<N, P, K>& a, const expression<M, Q, K>& b) {
    static_assert(K != TLV_QUERY_PLAN_NODES, "node sets are not scalar operands");
    return detail::combine<TLV_QUERY_OP_GT, TLV_QUERY_PLAN_BOOL>(a, b);
}
/** @brief Compare like-typed scalar expressions through the native comparison operation. */
template <size_t N, size_t P, size_t M, size_t Q, tlv_query_plan_type_t K>
constexpr expression<N + M + 1, P + Q, TLV_QUERY_PLAN_BOOL>
operator>=(const expression<N, P, K>& a, const expression<M, Q, K>& b) {
    static_assert(K != TLV_QUERY_PLAN_NODES, "node sets are not scalar operands");
    return detail::combine<TLV_QUERY_OP_GE, TLV_QUERY_PLAN_BOOL>(a, b);
}
/** @brief Compose eager Boolean operands with the native operation. */
template <size_t N, size_t P, size_t M, size_t Q>
constexpr expression<N + M + 1, P + Q, TLV_QUERY_PLAN_BOOL>
operator&&(const expression<N, P, TLV_QUERY_PLAN_BOOL>& a,
           const expression<M, Q, TLV_QUERY_PLAN_BOOL>& b) {
    return detail::combine<TLV_QUERY_OP_AND, TLV_QUERY_PLAN_BOOL>(a, b);
}
/** @brief Compose eager Boolean operands with the native operation. */
template <size_t N, size_t P, size_t M, size_t Q>
constexpr expression<N + M + 1, P + Q, TLV_QUERY_PLAN_BOOL>
operator||(const expression<N, P, TLV_QUERY_PLAN_BOOL>& a,
           const expression<M, Q, TLV_QUERY_PLAN_BOOL>& b) {
    return detail::combine<TLV_QUERY_OP_OR, TLV_QUERY_PLAN_BOOL>(a, b);
}
} // namespace static_query
} // namespace tlv
#endif
