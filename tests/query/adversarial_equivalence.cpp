// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#include "tlv++/query/static.hpp"
#include <cstdio>
#include <cstring>
namespace q = tlv::static_query;
extern "C" const tlv_query_program_t* query_generated_plan(unsigned);
static unsigned                       current_case, current_seed;
#define CHECK(x)                                                                                   \
    do {                                                                                           \
        if (!(x)) {                                                                                \
            std::fprintf(stderr, "case=%u seed=%u line=%d: %s\n", current_case, current_seed,      \
                         __LINE__, #x);                                                            \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)
struct outcome {
    tlv_result_t            status;
    tlv_query_error_kind_t  diagnostic;
    tlv_query_result_kind_t kind;
    int64_t                 integer;
    size_t                  configured, source_offset;
    int                     has_source_offset;
    tlv_codec_result_t      codec;
    const char*             expected;
    const char*             limit;
    size_t                  ordinals[8], count;
};
static bool equal(const outcome& a, const outcome& b) {
    return a.status == b.status && a.diagnostic == b.diagnostic && a.kind == b.kind &&
           a.integer == b.integer && a.count == b.count && a.configured == b.configured &&
           a.has_source_offset == b.has_source_offset && a.source_offset == b.source_offset &&
           a.codec == b.codec &&
           (a.expected && b.expected ? !std::strcmp(a.expected, b.expected)
                                     : a.expected == b.expected) &&
           (a.limit && b.limit ? !std::strcmp(a.limit, b.limit) : a.limit == b.limit) &&
           !std::memcmp(a.ordinals, b.ordinals, a.count * sizeof *a.ordinals);
}
static int execute(const tlv_query_program_t* p, unsigned seed, size_t capacity, size_t work,
                   outcome& out, bool retained) {
    alignas(16) uint8_t workspace[65536];
    size_t              bytes, alignment;
    CHECK((retained ? tlv_query_eval_size(p, 3, capacity, &bytes, &alignment)
                    : tlv_query_exec_size(p, 3, &bytes, &alignment)) == TLV_OK);
    CHECK(bytes <= sizeof workspace && alignment <= 16);
    tlv_query_exec_t* e = nullptr;
    auto              init = [&](void* storage, size_t size) {
        return retained ? tlv_query_eval_init(p, nullptr, storage, size, 3, capacity, work, &e)
                        : tlv_query_exec_init(p, storage, size, 3, capacity, work, &e);
    };
    CHECK(init(workspace, bytes - 1) == TLV_ERR_BUFFER_TOO_SHORT);
    CHECK(e == nullptr);
    CHECK(init(workspace + 1, bytes) == TLV_ERR_INVALID_ARG);
    CHECK(init(workspace, bytes) == TLV_OK);
    if (seed & 1u) CHECK(tlv_query_exec_context(e, 0) == TLV_OK);
    if (tlv_query_program_variable_count(p))
        CHECK(tlv_query_exec_bind(e, "n", TLV_QUERY_RESULT_INTEGER, seed % 4, nullptr, 0,
                                  nullptr) == TLV_OK);
    uint8_t    tags[8], values[8][4]{};
    uint8_t    parent_value[32]{};
    size_t     parent_size = 0;
    const bool nested = seed % 3 == 0;
    for (size_t i = 0; i < 8; ++i) {
        tags[i] =
            static_cast<uint8_t>(1 + ((seed * 1664525u + unsigned(i) * 1013904223u) >> 12) % 4);
        if (i > 0 && i < 4) {
            parent_value[parent_size++] = tags[i];
            parent_value[parent_size++] = static_cast<uint8_t>((seed + i) % 4);
            parent_size += (seed + i) % 4;
        }
    }
    tlv_query_diagnostic_t diagnostic{};
    out = outcome{};
    out.status = TLV_OK;
    for (size_t i = 0; i < 8 && out.status == TLV_OK; ++i) {
        tlv_tree_event_t event{};
        event.kind = nested && i == 0 ? TLV_TREE_BEGIN : TLV_TREE_ELEMENT;
        event.depth = nested && i > 0 && i < 4 ? 1 : 0;
        event.element.tag = tlv_tag(tags + i, 1);
        event.element.value.data = values[i];
        event.element.value.size = (seed + i) % 4;
        if (nested && i == 0) {
            event.element.value.data = parent_value;
            event.element.value.size = parent_size;
        }
        event.offset = i;
        int matched = 79;
        out.status = tlv_query_exec_feed(e, &event, &matched, &diagnostic);
        if (out.status != TLV_OK)
            CHECK(matched == 79);
        else if (retained)
            CHECK(matched == 0);
        else if (matched)
            out.ordinals[out.count++] = i;
        if (nested && i == 3 && out.status == TLV_OK) {
            event = tlv_tree_event_t{};
            event.kind = TLV_TREE_END;
            out.status = tlv_query_exec_feed(e, &event, &matched, &diagnostic);
        }
    }
    if (out.status == TLV_OK) out.status = tlv_query_exec_finish(e, &diagnostic);
    out.diagnostic = diagnostic.kind;
    out.configured = diagnostic.configured;
    out.has_source_offset = diagnostic.has_source_offset;
    out.source_offset = diagnostic.source_offset;
    out.codec = diagnostic.codec;
    out.expected = diagnostic.expected;
    out.limit = diagnostic.limit;
    if (out.status != TLV_OK) {
        tlv_query_result_t result{};
        CHECK(tlv_query_exec_result(e, &result) == TLV_ERR_INVALID_ARG);
        CHECK(tlv_query_exec_finish(e, nullptr) == TLV_ERR_INVALID_ARG);
        CHECK(tlv_query_exec_reset(e) == TLV_OK);
        return 0;
    }
    if (!retained) return 0;
    tlv_query_result_t result{};
    CHECK(tlv_query_exec_result(e, &result) == TLV_OK);
    out.kind = result.kind;
    if (result.kind == TLV_QUERY_RESULT_INTEGER || result.kind == TLV_QUERY_RESULT_BOOL) {
        out.integer = result.kind == TLV_QUERY_RESULT_INTEGER ? result.integer : result.boolean;
        return 0;
    }
    for (;;) {
        tlv_tree_event_t event{};
        size_t           ordinal = 999;
        auto             rc = tlv_query_result_next_ordinal(e, &event, &ordinal);
        if (rc == TLV_ERR_END_OF_BUFFER) {
            CHECK(ordinal == 999);
            break;
        }
        CHECK(rc == TLV_OK && out.count < 8);
        CHECK(event.offset == ordinal && (!out.count || ordinal > out.ordinals[out.count - 1]));
        out.ordinals[out.count++] = ordinal;
    }
    return 0;
}
static int metadata(const tlv_query_program_t* a, const tlv_query_program_t* b) {
    tlv_query_program_info_t x{}, y{};
    x.struct_size = sizeof x;
    y.struct_size = sizeof y;
    CHECK(tlv_query_plan_info(a, &x) == TLV_OK && tlv_query_plan_info(b, &y) == TLV_OK);
    CHECK(x.level == y.level && x.result_kind == y.result_kind &&
          x.variable_slots == y.variable_slots);
    CHECK(x.stable_input_required == y.stable_input_required &&
          x.decision_timing == y.decision_timing);
    CHECK(x.constructed_values_required == y.constructed_values_required);
    CHECK(x.candidate_size == y.candidate_size && x.candidate_alignment == y.candidate_alignment);
    CHECK(x.codec_scratch == y.codec_scratch && x.pattern_bytes == y.pattern_bytes &&
          a->tag_id == b->tag_id);
    for (size_t i = 0; i < x.variable_slots; ++i) {
        tlv_query_variable_info_t av{}, bv{};
        CHECK(tlv_query_program_variable(a, i, &av) == TLV_OK &&
              tlv_query_program_variable(b, i, &bv) == TLV_OK);
        CHECK(av.type == bv.type && av.name_size == bv.name_size &&
              !std::memcmp(av.name, bv.name, av.name_size));
    }
    size_t ab, aa, bb, ba;
    CHECK(tlv_query_eval_size(a, 3, 8, &ab, &aa) == TLV_OK &&
          tlv_query_eval_size(b, 3, 8, &bb, &ba) == TLV_OK);
    CHECK(aa == ba && ab == bb);
    CHECK(a->count == b->count);
    if (a->level <= TLV_QUERY_S1) {
        CHECK(tlv_query_exec_size(a, 3, &ab, &aa) == TLV_OK &&
              tlv_query_exec_size(b, 3, &bb, &ba) == TLV_OK);
        CHECK(aa == ba && ab == bb);
    }
    return 0;
}
template <class Plan> static int check(unsigned index, const Plan& plan, const char* source) {
    current_case = index;
    const tlv_query_program_t *compiled = nullptr, *generated = nullptr;
    CHECK(tlv_query_plan_open(plan.data(), plan.size(), &compiled, nullptr) == TLV_OK);
    auto image = query_generated_plan(index);
    CHECK(image && tlv_query_plan_open(image, image->reserved, &generated, nullptr) == TLV_OK);
    CHECK(metadata(compiled, generated) == 0);
#if OPENTLV_QUERY_FRONTEND
    alignas(16) uint8_t         storage[8192], scratch[65536];
    tlv_query_compile_options_t options;
    tlv_query_compile_options_init(&options);
    tlv_query_variable_t variable = {"n", TLV_QUERY_RESULT_INTEGER};
    options.variables = &variable;
    options.variable_count = 1;
    tlv_query_program_info_t info{};
    info.struct_size = sizeof info;
    CHECK(tlv_query_compile(source, std::strlen(source), &options, scratch, sizeof scratch, storage,
                            sizeof storage, &info, nullptr) == TLV_OK);
    const auto* runtime = reinterpret_cast<const tlv_query_program_t*>(storage);
    CHECK(metadata(compiled, runtime) == 0);
#else
    (void)source;
#endif
    for (int mode = compiled->level <= TLV_QUERY_S1 ? 0 : 1; mode < 2; ++mode)
        for (current_seed = 1; current_seed <= 32; ++current_seed)
            for (unsigned budget = 0; budget < 3; ++budget) {
                outcome a{}, b{};
                size_t  nodes = budget == 1 ? 7 : 8, work = budget == 2 ? 1 : 100000;
                CHECK(execute(compiled, current_seed, nodes, work, a, mode != 0) == 0);
                CHECK(execute(generated, current_seed, nodes, work, b, mode != 0) == 0);
                CHECK(equal(a, b));
#if OPENTLV_QUERY_FRONTEND
                CHECK(execute(runtime, current_seed, nodes, work, b, mode != 0) == 0);
                CHECK(equal(a, b));
#endif
            }
    return 0;
}
int main() {
#define CASE(index, expression, text)                                                              \
    {                                                                                              \
        static constexpr auto plan = (expression).compile();                                       \
        CHECK(check(index, plan, text) == 0);                                                      \
    }
#include "adversarial_cases.inc"
#undef CASE
    std::puts(
        "adversarial equivalence: 77 generated expression plans x 32 seeds x 3 budgets passed");
    return 0;
}
