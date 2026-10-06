// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#include "tlv++/query/static.hpp"
#include <cstdio>
#include <cstdlib>
#include <new>
namespace q = tlv::static_query;
static size_t allocations = 0;
static bool   observe = false;
void*         operator new(size_t size) {
    if (observe) ++allocations;
    if (void* p = std::malloc(size ? size : 1)) return p;
    throw std::bad_alloc();
}
void* operator new[](size_t size) {
    return ::operator new(size);
}
void operator delete(void* p) noexcept {
    std::free(p);
}
void operator delete[](void* p) noexcept {
    std::free(p);
}
#if __cplusplus >= 201402L
void operator delete(void* p, size_t) noexcept {
    std::free(p);
}
void operator delete[](void* p, size_t) noexcept {
    std::free(p);
}
#endif
#define CHECK(x)                                                                                   \
    do {                                                                                           \
        if (!(x)) {                                                                                \
            std::fprintf(stderr, "line %d: %s\n", __LINE__, #x);                                   \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

static constexpr auto root_plan =
    q::where(q::child<0x5a>(), q::length() == q::parameter("n")).compile();
static constexpr auto nested_plan =
    q::where(q::child<0x70>() / q::descendant<0x5a>(),
             (q::length() >= q::parameter("n")) && (q::length() <= q::parameter("n")))
        .compile();
static constexpr auto bytes_plan =
    q::where(q::descendant<0x5a>(), q::value() == q::bytes<0x11>()).compile();
static constexpr auto byte_parameter =
    q::where(q::descendant<0x5a>(), q::value() == q::parameter<TLV_QUERY_PLAN_BYTES>("wanted"))
        .compile();
static constexpr auto bounds_plan =
    q::where(q::descendant<0x5a>(),
             (q::length() >= q::parameter("n")) && (q::length() <= q::parameter("max")))
        .compile();
static constexpr auto negative_plan = q::integer(INT64_MIN).compile();
static_assert(root_plan.header().text_size == 0, "source-free native image");
static_assert(root_plan.header().count == 7,
              "absolute root and path instructions exist at compile time");
static_assert(nested_plan.header().variable_count == 1, "repeated names share a slot");
static_assert(bounds_plan.header().variable_count == 2, "distinct parameter slots");
static_assert(negative_plan.instruction(0).negative == 1, "integer sign");
static_assert(negative_plan.instruction(0).immediate_high == 0x80000000u, "INT64_MIN magnitude");

static int run(const tlv::query_program& program, bool retained, int64_t n, unsigned& bits,
               int64_t* scalar = nullptr) {
    alignas(16) uint8_t workspace[65536];
    auto execution = tlv::query_execution::external(program, workspace, sizeof workspace, 3, 16,
                                                    100000, nullptr, retained);
    CHECK(execution);
    const uint8_t wanted = 0x11;
    for (size_t i = 0; i < program.variable_count(); ++i) {
        auto info = program.variable(i);
        CHECK(info);
        if (info->name_size == 1)
            CHECK(execution->bind("n", n));
        else if (info->name_size == 3)
            CHECK(execution->bind("max", int64_t(2)));
        else
            CHECK(execution->bind("wanted",
                                  tlv::bytes(reinterpret_cast<const tlv::byte*>(&wanted), 1)));
    }
    const uint8_t tags[] = {0x70, 0x5a, 0x5a, 0x71, 0x5a, 0x71, 0x70, 0x5a};
    const size_t  depths[] = {0, 1, 1, 1, 2, 1, 0, 0};
    const uint8_t value[] = {0x11, 0x22};
    bits = 0;
    for (size_t i = 0; i < 8; ++i) {
        tlv_tree_event_t event{};
        event.kind = i == 0 || i == 3   ? TLV_TREE_BEGIN
                     : i == 5 || i == 6 ? TLV_TREE_END
                                        : TLV_TREE_ELEMENT;
        event.depth = depths[i];
        event.offset = i;
        event.element.tag = tlv_tag(&tags[i], 1);
        event.element.value.data = value;
        event.element.value.size = i == 2 ? 2 : 1;
        int matched = 0;
        CHECK(tlv_query_exec_feed(execution->c_exec(), &event, &matched, nullptr) == TLV_OK);
        if (matched) bits |= 1u << i;
    }
    CHECK(tlv_query_exec_finish(execution->c_exec(), nullptr) == TLV_OK);
    if (retained) {
        auto result = execution->result();
        CHECK(result);
        if (scalar) {
            CHECK(result->kind == TLV_QUERY_RESULT_INTEGER);
            *scalar = result->integer;
        } else {
            tlv_tree_event_t event;
            tlv_result_t     rc;
            while ((rc = tlv_query_result_next(execution->c_exec(), &event)) == TLV_OK)
                bits |= 1u << event.offset;
            CHECK(rc == TLV_ERR_END_OF_BUFFER);
        }
    }
    CHECK(execution->reset());
    CHECK(!execution->result());
    return 0;
}
template <typename Plan>
static int check(const Plan& plan, const char* text, unsigned one, unsigned two) {
    observe = true;
    auto program = plan.program();
    CHECK(program);
    CHECK(program->info().scratch_size == 0);
    CHECK(program->info().instructions == plan.header().count);
    for (int retained = 0; retained < 2; ++retained) {
        unsigned bits;
        CHECK(run(*program, retained != 0, 1, bits) == 0 && bits == one);
        CHECK(run(*program, retained != 0, 2, bits) == 0 && bits == two);
    }
    observe = false;
    CHECK(allocations == 0);
    CHECK(!program->explain().empty());
#if OPENTLV_QUERY_FRONTEND
    tlv_query_variable_t        vars[] = {{"n", TLV_QUERY_RESULT_INTEGER},
                                          {"max", TLV_QUERY_RESULT_INTEGER},
                                          {"wanted", TLV_QUERY_RESULT_BYTES}};
    tlv_query_compile_options_t options;
    tlv_query_compile_options_init(&options);
    options.variables = vars;
    options.variable_count = 3;
    for (int optimize = 0; optimize < 2; ++optimize) {
        options.optimize = optimize;
        auto runtime = tlv::query_program::compile(text, &options);
        CHECK(runtime);
        for (int retained = 0; retained < 2; ++retained) {
            unsigned bits;
            CHECK(run(*runtime, retained != 0, 1, bits) == 0 && bits == one);
            CHECK(run(*runtime, retained != 0, 2, bits) == 0 && bits == two);
        }
    }
#else
    (void)text;
#endif
    return 0;
}
int main() {
    CHECK(check(root_plan, "/5A[@len=$n]", 128, 0) == 0);
    CHECK(check(nested_plan, "/70//5A[@len >= $n and @len <= $n]", 18, 4) == 0);
    CHECK(check(bytes_plan, "//5A[value() = x'11']", 146, 146) == 0);
    CHECK(check(byte_parameter, "//5A[value() = $wanted]", 146, 146) == 0);
    CHECK(check(bounds_plan, "//5A[@len >= $n and @len <= $max]", 150, 4) == 0);
    auto scalar = negative_plan.program();
    CHECK(scalar);
    unsigned ignored;
    int64_t  number;
    CHECK(run(*scalar, true, 0, ignored, &number) == 0 && number == INT64_MIN);
    return 0;
}
