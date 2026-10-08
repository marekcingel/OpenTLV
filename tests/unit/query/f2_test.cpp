// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#include "../../diagnostic_assertions.h"
#include "tlv/query/adapters.h"
#include "tlv/builtins/emv/query.h"
#include "tlv/builtins/asn1/query.h"
#include "tlv/builtins/asn1/ber.h"
#include "tlv/config.h"
#include "controlled_format.h"
#include <gtest/gtest.h>
#include <cstring>
#include <string>
#include <vector>

namespace {
struct Buffer {
    std::vector<uint8_t> bytes;
    void*                data;
    Buffer(size_t size, size_t alignment) : bytes(size + alignment) {
        data = reinterpret_cast<void*>((reinterpret_cast<uintptr_t>(bytes.data()) + alignment - 1) &
                                       ~(alignment - 1));
    }
};
int constructed(const void*, const tlv_tag_t* tag) {
    return tag->size == 1 && tag->data[0] == 0x70;
}
tlv_visit_result_t noop(const tlv_tree_event_t* event, void* context) {
    if (context) static_cast<std::vector<size_t>*>(context)->push_back(event->offset);
    return TLV_VISIT_CONTINUE;
}
struct Evaluation {
    tlv_query_compile_options_t   options{};
    tlv_query_environment_t       environment{};
    tlv_query_program_info_t      info{};
    tlv_query_diagnostic_t        diagnostic{};
    tlv_query_result_t            result{};
    tlv_format_t                  format = controlled::format;
    std::vector<tlv_query_hook_t> hooks;
    std::vector<uint8_t>          program_storage, workspace;
    const tlv_query_program_t*    program = nullptr;
    tlv_query_exec_t*             exec = nullptr;
    size_t                        workspace_size = 0;
    Evaluation() {
        tlv_query_compile_options_init(&options);
        info.struct_size = sizeof info;
        size_t      count;
        const auto* builtin = tlv_query_builtin_hooks(&count);
        hooks.assign(builtin, builtin + count);
#if OPENTLV_FORMAT_BER
        hooks.push_back(tlv_asn1_query_date);
#endif
        format.is_constructed = constructed;
        environment.format = &format;
        environment.hooks = hooks.data();
        environment.hook_count = hooks.size();
        options.environment = &environment;
    }
    tlv_result_t compile(const std::string& text) {
        size_t size, alignment;
        auto   rc = TLV_DIAGNOSTIC_RESULT(
            diagnostic, tlv_query_compile_scratch(text.data(), text.size(), &options, &size,
                                                  &alignment, &diagnostic));
        if (rc != TLV_OK) return rc;
        Buffer scratch(size, alignment);
        rc = TLV_DIAGNOSTIC_RESULT(diagnostic, tlv_query_compile(text.data(), text.size(), &options,
                                                                 scratch.data, size, nullptr, 0,
                                                                 &info, &diagnostic));
        if (rc != TLV_OK) return rc;
        program_storage.resize(info.program_size + 16);
        void* storage = reinterpret_cast<void*>(
            (reinterpret_cast<uintptr_t>(program_storage.data()) + 15) & ~uintptr_t(15));
        rc = TLV_DIAGNOSTIC_RESULT(
            diagnostic, tlv_query_compile(text.data(), text.size(), &options, scratch.data, size,
                                          storage, info.program_size, &info, &diagnostic));
        program = static_cast<const tlv_query_program_t*>(storage);
        return rc;
    }
    tlv_result_t init(size_t nodes = 64, size_t work = 1000000) {
        size_t alignment;
        auto   rc = tlv_query_eval_size(program, 16, nodes, &workspace_size, &alignment);
        if (rc != TLV_OK) return rc;
        workspace.resize(workspace_size + alignment);
        void* storage = reinterpret_cast<void*>(
            (reinterpret_cast<uintptr_t>(workspace.data()) + alignment - 1) & ~(alignment - 1));
        return tlv_query_eval_init(program, &environment, storage, workspace_size, 16, nodes, work,
                                   &exec);
    }
    tlv_result_t run(const std::vector<uint8_t>& wire, std::vector<size_t>* selected = nullptr) {
        tlv_tree_frame_t  frames[16];
        tlv_tree_reader_t reader;
        auto              rc =
            tlv_tree_reader_init(&reader, wire.data(), wire.size(), &format, frames, 16, 16, 1000);
        if (rc != TLV_OK) return rc;
        rc = TLV_DIAGNOSTIC_RESULT(
            diagnostic, tlv_query_program_visit(&reader, exec, noop, selected, &diagnostic));
        if (rc != TLV_OK) return rc;
        rc = tlv_query_exec_result(exec, &result);
        return rc;
    }
};
} // namespace
TEST(Unit_Tlv_QueryF2, ScalarsStringsAndClosedFunctions) {
    const std::vector<uint8_t> wire = {0x5a, 2, 0x12, 0x34};
    struct Case {
        const char*             text;
        tlv_query_result_kind_t type;
        int64_t                 integer;
    };
    const Case cases[] = {{"true and not(false)", TLV_QUERY_RESULT_BOOL, 1},
                          {"'hello' = \"hello\"", TLV_QUERY_RESULT_BOOL, 1},
                          {"'a\\\'b' = \"a'b\"", TLV_QUERY_RESULT_BOOL, 1},
                          {"count(//5A)", TLV_QUERY_RESULT_INTEGER, 1},
                          {"exists(//5A)", TLV_QUERY_RESULT_BOOL, 1},
                          {"empty(//84)", TLV_QUERY_RESULT_BOOL, 1},
                          {"len(value(//5A))", TLV_QUERY_RESULT_INTEGER, 2},
                          {"num(value(//5A))", TLV_QUERY_RESULT_INTEGER, 0x1234},
                          {"bcd(//5A)", TLV_QUERY_RESULT_INTEGER, 1234},
                          {"len('abc')", TLV_QUERY_RESULT_INTEGER, 3},
                          {"contains(value(//5A),substr(x'001234',1))", TLV_QUERY_RESULT_BOOL, 1}};
    for (const auto& c : cases) {
        SCOPED_TRACE(c.text);
        Evaluation e;
        ASSERT_EQ(TLV_OK, e.compile(c.text));
        ASSERT_EQ(TLV_OK, e.init());
        ASSERT_EQ(TLV_OK, e.run(wire));
        EXPECT_EQ(c.type, e.result.kind);
        EXPECT_EQ(c.integer, c.type == TLV_QUERY_RESULT_BOOL ? e.result.boolean : e.result.integer);
    }
}
TEST(Unit_Tlv_QueryF2, CardinalityAndValidationPrecedeScalarPublication) {
    for (const char* text : {"value(//5A)", "num(//5A)", "tag(//5A)"}) {
        Evaluation e;
        ASSERT_EQ(TLV_OK, e.compile(text));
        ASSERT_EQ(TLV_OK, e.init());
        EXPECT_EQ(TLV_ERR_INVALID_VALUE, e.run({}));
        EXPECT_EQ(TLV_QUERY_ERROR_CARDINALITY, e.diagnostic.kind);
        ASSERT_EQ(TLV_OK, e.init());
        EXPECT_EQ(TLV_ERR_INVALID_VALUE, e.run({0x5a, 0, 0x5a, 0}));
        EXPECT_EQ(TLV_QUERY_ERROR_CARDINALITY, e.diagnostic.kind);
    }
    Evaluation e;
    ASSERT_EQ(TLV_OK, e.compile("exists(//5A)"));
    ASSERT_EQ(TLV_OK, e.init());
    tlv_query_result_t sentinel{};
    sentinel.integer = 99;
    EXPECT_EQ(TLV_ERR_INVALID_STATE, tlv_query_exec_result(e.exec, &sentinel));
    EXPECT_EQ(99, sentinel.integer);
    EXPECT_NE(TLV_OK, e.run({0x5a, 0, 0x84}));
    EXPECT_EQ(TLV_ERR_INVALID_STATE, tlv_query_exec_result(e.exec, &sentinel));
    EXPECT_EQ(99, sentinel.integer);
}
TEST(Unit_Tlv_QueryF2, PositionLastChainedPredicatesAndDeferredSetAlgebra) {
    const std::vector<uint8_t> wire = {0x70, 6, 0x5a, 1, 1, 0x5a, 1, 2,
                                       0x70, 3, 0x5a, 1, 3, 0x5a, 1, 4};
    struct Case {
        const char*         query;
        std::vector<size_t> offsets;
    };
    const Case cases[] = {{"//70/5A[position() = last()]", {5, 10}},
                          {"(//5A)[2]", {5}},
                          {"(//5A)[@len=1][2]", {5}},
                          {"//5A except //70/5A", {13}},
                          {"//70[count(5A) = 2]", {0}},
                          {"//70[not(84)] intersect //70[exists(5A)]", {0, 8}},
                          {"//70[last()]", {8}}};
    for (const auto& c : cases) {
        SCOPED_TRACE(c.query);
        Evaluation e;
        ASSERT_EQ(TLV_OK, e.compile(c.query));
        ASSERT_EQ(TLV_OK, e.init());
        std::vector<size_t> selected;
        ASSERT_EQ(TLV_OK, e.run(wire, &selected));
        EXPECT_EQ(c.offsets, selected);
    }
}
TEST(Unit_Tlv_QueryF2, StrictCodecErrorsAndEagerBooleanEvaluation) {
    for (const char* text :
         {"//5A[bcd(.) > 0]", "//5A[false and bcd(.) > 0]", "//5A[true or bcd(.) > 0]"}) {
        Evaluation e;
        ASSERT_EQ(TLV_OK, e.compile(text));
        ASSERT_EQ(TLV_OK, e.init());
        EXPECT_EQ(TLV_ERR_INVALID_VALUE, e.run({0x5a, 1, 0xff}));
        EXPECT_EQ(TLV_QUERY_ERROR_CODEC, e.diagnostic.kind);
        EXPECT_EQ(TLV_CODEC_ERR_INVALID_VALUE, e.diagnostic.codec);
        EXPECT_TRUE(e.diagnostic.has_source_offset);
        EXPECT_EQ(0u, e.diagnostic.source_offset);
        EXPECT_LT(e.diagnostic.begin, e.diagnostic.end);
    }
    Evaluation e;
    ASSERT_EQ(TLV_OK, e.compile("text(//5A)"));
    ASSERT_EQ(TLV_OK, e.init());
    const std::vector<uint8_t> wire = {0x5a, 3, 'a', 0, 'b'};
    ASSERT_EQ(TLV_OK, e.run(wire));
    EXPECT_EQ(TLV_QUERY_RESULT_STRING, e.result.kind);
    EXPECT_EQ(3u, e.result.size);
    EXPECT_EQ(0, std::memcmp(wire.data() + 2, e.result.data, 3));
}
TEST(Unit_Tlv_QueryF2, RuntimePatternBindingsAndExplicitCapacity) {
    Evaluation           e;
    tlv_query_variable_t variable = {"pattern", TLV_QUERY_RESULT_BYTES};
    e.options.variables = &variable;
    e.options.variable_count = 1;
    e.options.max_pattern = 3;
    ASSERT_EQ(TLV_OK, e.compile("//5A[contains(value(),$pattern)]"));
    ASSERT_EQ(TLV_OK, e.init());
    const uint8_t pattern[] = {0, '[', '$'};
    ASSERT_EQ(TLV_OK, tlv_query_exec_bind(e.exec, "pattern", TLV_QUERY_RESULT_BYTES, 0, pattern,
                                          sizeof pattern, &e.diagnostic));
    ASSERT_EQ(TLV_OK, e.run({0x5a, 4, 0, '[', '$', ']'}));
    ASSERT_EQ(TLV_OK, e.init());
    const uint8_t large[] = {0, 0, 0, 0};
    ASSERT_EQ(TLV_OK, tlv_query_exec_bind(e.exec, "pattern", TLV_QUERY_RESULT_BYTES, 0, large,
                                          sizeof large, &e.diagnostic));
    EXPECT_EQ(TLV_ERR_LIMIT, e.run({0x5a, 5, 0, 0, 0, 0, 0}));
    EXPECT_STREQ("pattern", e.diagnostic.limit);
    ASSERT_EQ(e.compile("//5A[contains(x'0000000000',$pattern)]"), TLV_OK);
    size_t size, alignment;
    ASSERT_EQ(tlv_query_exec_size(e.program, 16, &size, &alignment), TLV_OK);
    Buffer scratch(size, alignment);
    ASSERT_EQ(tlv_query_exec_init(e.program, scratch.data, size, 16, 100, 1000000, &e.exec),
              TLV_OK);
    ASSERT_EQ(tlv_query_exec_bind(e.exec, "pattern", TLV_QUERY_RESULT_BYTES, 0, large, sizeof large,
                                  &e.diagnostic),
              TLV_OK);
    EXPECT_EQ(e.run({0x5a, 0}), TLV_ERR_LIMIT);
    EXPECT_STREQ("pattern", e.diagnostic.limit);
    EXPECT_EQ(e.compile("//5A[contains(value(),x'00000000')]"), TLV_ERR_LIMIT);
}
TEST(Unit_Tlv_QueryF2, NameResolutionCopiesIdentifiersAndDetectsConflicts) {
    uint8_t                         tag = 0x5a;
    tlv_definition_t                definition = {tlv_tag(&tag, 1), "PAN"};
    tlv_definition_registry_t       registry = {&definition, 1};
    tlv_query_definition_scope_t    scopes[] = {{"a", &registry}, {"b", &registry}};
    tlv_query_definition_resolver_t resolver = {scopes, 2};
    Evaluation                      e;
    e.options.resolve = tlv_query_definition_resolve;
    e.options.resolve_context = &resolver;
    EXPECT_EQ(TLV_ERR_INVALID_ARG, e.compile("//PAN"));
    EXPECT_EQ(TLV_ERR_INVALID_TAG, e.compile("//a:unknown"));
    ASSERT_EQ(TLV_OK, e.compile("//a:PAN"));
    tag = 0x84;
    ASSERT_EQ(TLV_OK, e.init());
    std::vector<size_t> selected;
    ASSERT_EQ(TLV_OK, e.run({0x5a, 0}, &selected));
    EXPECT_EQ((std::vector<size_t>{0}), selected);
    tag = 0x5a;
    ASSERT_EQ(TLV_OK, e.compile("//70[name('a','PAN')]"));
    EXPECT_EQ(e.info.level, TLV_QUERY_S2);
    ASSERT_EQ(TLV_OK, e.init());
    selected.clear();
    ASSERT_EQ(TLV_OK, e.run({0x70, 2, 0x5a, 0}, &selected));
    EXPECT_EQ(selected, std::vector<size_t>({0}));
    ASSERT_EQ(TLV_OK, e.compile("//name('a','PAN')"));
    ASSERT_EQ(TLV_OK, e.init());
    selected.clear();
    ASSERT_EQ(TLV_OK, e.run({0x5a, 0}, &selected));
    EXPECT_EQ((std::vector<size_t>{0}), selected);
#if OPENTLV_EMV
    e.options.resolve = tlv_emv_query_resolve;
    e.options.resolve_context = nullptr;
    ASSERT_EQ(TLV_OK, e.compile("//emv:PAN"));
    ASSERT_EQ(TLV_OK, e.init());
    selected.clear();
    ASSERT_EQ(TLV_OK, e.run({0x5a, 0}, &selected));
    EXPECT_EQ((std::vector<size_t>{0}), selected);
#endif
}
TEST(Unit_Tlv_QueryF2, EnvironmentMismatchIsRejectedBeforeInput) {
    Evaluation e;
    ASSERT_EQ(TLV_OK, e.compile("num(//5A)"));
    e.hooks[0].id += 100;
    EXPECT_EQ(TLV_ERR_UNSUPPORTED, e.init());
    e.hooks[0].id -= 100;
    e.hooks[0].decode = nullptr;
    EXPECT_EQ(TLV_ERR_UNSUPPORTED, e.init());
    Evaluation flat;
    EXPECT_EQ(TLV_ERR_UNSUPPORTED, flat.compile("class()"));
    EXPECT_EQ(TLV_ERR_UNSUPPORTED, flat.compile("number()"));
    EXPECT_EQ(TLV_ERR_INVALID_ARG, flat.compile("text()"));
    EXPECT_EQ(TLV_ERR_INVALID_VALUE, flat.compile("value(x'00')"));
    EXPECT_EQ(TLV_ERR_INVALID_VALUE, flat.compile("'text' = x'74657874'"));
}
#if OPENTLV_FORMAT_BER
TEST(Unit_Tlv_QueryF2, Asn1CapabilitiesAndUtcDateAdapter) {
    Evaluation e;
    e.environment.tags = &tlv_asn1_query_tags;
    e.format = tlv_format_ber;
    ASSERT_EQ(TLV_OK, e.compile("//80[class() = 2 and number() = 0 and not(constructed())]"));
    ASSERT_EQ(TLV_OK, e.init());
    std::vector<size_t> selected;
    ASSERT_EQ(TLV_OK, e.run({0x80, 0}, &selected));
    EXPECT_EQ((std::vector<size_t>{0}), selected);
    ASSERT_EQ(TLV_OK, e.compile("date(//18)"));
    ASSERT_EQ(TLV_OK, e.init());
    const std::string    date = "19700101000000Z";
    std::vector<uint8_t> wire = {0x18, 15};
    wire.insert(wire.end(), date.begin(), date.end());
    ASSERT_EQ(TLV_OK, e.run(wire));
    EXPECT_EQ(0, e.result.integer);
    ASSERT_EQ(TLV_OK, e.init());
    wire[2] = '2';
    wire[3] = '0';
    wire[4] = '2';
    wire[5] = '3';
    wire[6] = '0';
    wire[7] = '2';
    wire[8] = '3';
    wire[9] = '0';
    EXPECT_EQ(TLV_ERR_INVALID_VALUE, e.run(wire));
    EXPECT_EQ(TLV_QUERY_ERROR_CODEC, e.diagnostic.kind);
}
#endif
TEST(Unit_Tlv_QueryF2, OptimizedAndUnoptimizedAgreeAndExplainIsAtomic) {
    const std::vector<uint8_t> wire = {0x5a, 0, 0x84, 0};
    Evaluation                 optimized, plain;
    plain.options.optimize = 0;
    const std::string query = "(//5A | //5A)[true and not(false)]";
    ASSERT_EQ(TLV_OK, optimized.compile(query));
    ASSERT_EQ(TLV_OK, plain.compile(query));
    ASSERT_EQ(TLV_OK, optimized.init());
    ASSERT_EQ(TLV_OK, plain.init());
    std::vector<size_t> a, b;
    ASSERT_EQ(TLV_OK, optimized.run(wire, &a));
    ASSERT_EQ(TLV_OK, plain.run(wire, &b));
    EXPECT_EQ(a, b);
    size_t required;
    ASSERT_EQ(TLV_OK, tlv_query_program_explain(optimized.program, nullptr, 0, &required));
    std::vector<char> text(required, '!');
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
              tlv_query_program_explain(optimized.program, text.data(), required - 1, &required));
    EXPECT_EQ('!', text[0]);
    ASSERT_EQ(TLV_OK,
              tlv_query_program_explain(optimized.program, text.data(), text.size(), &required));
    EXPECT_NE(nullptr, std::strstr(text.data(), "level="));
}

TEST(Unit_Tlv_QueryF2, WorkspaceLimitsFinalizationAndResume) {
    Evaluation e;
    ASSERT_EQ(e.compile("(//5A)[position()>0]"), TLV_OK);
    size_t size, alignment;
    ASSERT_EQ(tlv_query_eval_size(e.program, 16, 2, &size, &alignment), TLV_OK);
    Buffer            storage(size, alignment);
    tlv_query_exec_t* output = nullptr;
    EXPECT_EQ(tlv_query_eval_init(e.program, &e.environment, storage.data, size - 1, 16, 2, 1000000,
                                  &output),
              TLV_ERR_BUFFER_TOO_SHORT);
    EXPECT_EQ(output, nullptr);
    EXPECT_EQ(tlv_query_eval_init(e.program, &e.environment,
                                  static_cast<uint8_t*>(storage.data) + 1, size, 16, 2, 1000000,
                                  &output),
              TLV_ERR_INVALID_ARG);
    ASSERT_EQ(e.init(2), TLV_OK);
    const uint8_t     wire[] = {0x5a, 1, 0x12, 0x5a, 1, 0x34};
    tlv_tree_frame_t  frames[16];
    tlv_tree_reader_t reader;
    ASSERT_EQ(tlv_tree_reader_init(&reader, wire, sizeof wire, &e.format, frames, 16, 16, 10),
              TLV_OK);
    auto stop = [](const tlv_tree_event_t*, void*) { return TLV_VISIT_STOP; };
    ASSERT_EQ(tlv_query_program_visit(&reader, e.exec, stop, nullptr, &e.diagnostic), TLV_OK);
    tlv_query_exec_info_t info{};
    info.struct_size = sizeof info;
    ASSERT_EQ(tlv_query_exec_info(e.exec, &info), TLV_OK);
    EXPECT_TRUE(info.finished);
    EXPECT_TRUE(info.full_validation);
    std::vector<size_t> remaining;
    ASSERT_EQ(tlv_query_program_visit(&reader, e.exec, noop, &remaining, &e.diagnostic), TLV_OK);
    EXPECT_EQ(remaining, std::vector<size_t>({3}));
    tlv_tree_event_t event{};
    event.offset = 999;
    EXPECT_EQ(tlv_query_result_next(e.exec, &event), TLV_ERR_END_OF_BUFFER);
    EXPECT_EQ(event.offset, 999u);
    ASSERT_EQ(e.init(1), TLV_OK);
    EXPECT_EQ(e.run(std::vector<uint8_t>(wire, wire + sizeof wire)), TLV_ERR_LIMIT);
    ASSERT_EQ(e.init(2, 1), TLV_OK);
    EXPECT_EQ(e.run(std::vector<uint8_t>(wire, wire + sizeof wire)), TLV_ERR_LIMIT);
    size = 123;
    alignment = 456;
    EXPECT_EQ(tlv_query_eval_size(e.program, SIZE_MAX, 2, &size, &alignment), TLV_ERR_OVERFLOW);
    EXPECT_EQ(size, 123u);
    EXPECT_EQ(alignment, 456u);
}
TEST(Unit_Tlv_QueryF2, ClosedFunctionTypesAndOptimizerEquivalence) {
    for (const char* text :
         {"count()", "exists(x'01')", "empty(true)", "position(1)", "last(1)", "value(true)",
          "len(true)", "num(true)", "bcd('12')", "text(true)", "tag(x'01')", "constructed(x'01')",
          "not(1)", "substr(x'01', true)", "contains('a', 'b')", "starts-with(x'01')",
          "ends-with(x'01', true)"}) {
        Evaluation e;
        EXPECT_NE(e.compile(text), TLV_OK) << text;
    }
    for (const char* text : {"-9223372036854775808 < 0", "x'0012' < x'0013'", "'a' != 'b'", "70/.",
                             "//70/./5A", "//5A[true and not(false)]"}) {
        Evaluation a, b;
        b.options.optimize = 0;
        ASSERT_EQ(a.compile(text), TLV_OK) << text;
        ASSERT_EQ(b.compile(text), TLV_OK) << text;
        ASSERT_EQ(a.init(), TLV_OK);
        ASSERT_EQ(b.init(), TLV_OK);
        std::vector<size_t>        left, right;
        const std::vector<uint8_t> wire = {0x70, 3, 0x5a, 1, 0x12};
        ASSERT_EQ(a.run(wire, &left), TLV_OK) << text;
        ASSERT_EQ(b.run(wire, &right), TLV_OK) << text;
        EXPECT_EQ(left, right);
        EXPECT_EQ(a.result.kind, b.result.kind);
        EXPECT_EQ(a.result.boolean, b.result.boolean);
    }
}

TEST(Unit_Tlv_QueryF2, IncrementalFinalizationAndAncestorPositions) {
    Evaluation e;
    ASSERT_EQ(e.compile("count(//5A)"), TLV_OK);
    ASSERT_EQ(e.init(), TLV_OK);
    const uint8_t     first[] = {0x5a, 1, 0x12};
    const uint8_t     rest[] = {0x5a, 1, 0x34};
    tlv_tree_frame_t  frames[16];
    tlv_tree_reader_t reader;
    ASSERT_EQ(tlv_tree_reader_init_incremental(&reader, first, sizeof first, &e.format, frames, 16,
                                               16, 10),
              TLV_OK);
    EXPECT_EQ(TLV_DIAGNOSTIC_RESULT(e.diagnostic, tlv_query_program_visit(&reader, e.exec, noop,
                                                                          nullptr, &e.diagnostic)),
              TLV_NEED_MORE_DATA);
    tlv_query_result_t output{};
    output.integer = 999;
    EXPECT_EQ(tlv_query_exec_result(e.exec, &output), TLV_ERR_INVALID_STATE);
    EXPECT_EQ(output.integer, 999);
    ASSERT_EQ(tlv_tree_reader_set_input(&reader, rest, sizeof rest, sizeof first, 1), TLV_OK);
    ASSERT_EQ(tlv_query_program_visit(&reader, e.exec, noop, nullptr, &e.diagnostic), TLV_OK);
    ASSERT_EQ(tlv_query_exec_result(e.exec, &output), TLV_OK);
    EXPECT_EQ(output.integer, 2);
    ASSERT_EQ(e.compile("//5A[ancestor::70[1][@len=3]]"), TLV_OK);
    ASSERT_EQ(e.init(), TLV_OK);
    std::vector<size_t> selected;
    ASSERT_EQ(e.run({0x70, 5, 0x70, 3, 0x5a, 1, 0x12}, &selected), TLV_OK);
    EXPECT_EQ(selected, std::vector<size_t>({4}));
}

TEST(Unit_Tlv_QueryF2, ProviderScratchAlignmentAndResultValidation) {
    struct State {
        size_t calls;
        bool   bad;
    } state = {0, false};
    auto decode = [](const void* context, const tlv_tree_event_t*, const uint8_t*, size_t,
                     void* scratch, size_t capacity,
                     tlv_query_result_t* result) -> tlv_codec_result_t {
        State* state = const_cast<State*>(static_cast<const State*>(context));
        if (reinterpret_cast<uintptr_t>(scratch) % 16 || capacity != 32)
            return TLV_CODEC_ERR_INVALID_VALUE;
        ++state->calls;
        std::memset(scratch, 0, capacity);
        result->kind = state->bad ? TLV_QUERY_RESULT_STRING : TLV_QUERY_RESULT_INTEGER;
        result->integer = 42;
        return TLV_CODEC_OK;
    };
    Evaluation e;
    e.hooks[0].id = 100;
    e.hooks[0].scratch_size = 32;
    e.hooks[0].scratch_alignment = 16;
    e.hooks[0].context = &state;
    e.hooks[0].decode = decode;
    ASSERT_EQ(e.compile("num(x'01')=num(x'02')"), TLV_OK);
    EXPECT_EQ(e.info.codec_scratch, 32u);
    ASSERT_EQ(e.init(), TLV_OK);
    EXPECT_EQ(tlv_query_exec_pruning(e.exec, 1), TLV_ERR_INVALID_ARG);
    ASSERT_EQ(e.run({}), TLV_OK);
    EXPECT_TRUE(e.result.boolean);
    EXPECT_EQ(state.calls, 2u);
    state.bad = true;
    ASSERT_EQ(e.init(), TLV_OK);
    EXPECT_EQ(e.run({}), TLV_ERR_CALLBACK);
    EXPECT_EQ(e.diagnostic.kind, TLV_QUERY_ERROR_CALLBACK);
    EXPECT_EQ(e.diagnostic.codec, TLV_CODEC_OK);
    EXPECT_LT(e.diagnostic.begin, e.diagnostic.end);
}

TEST(Unit_Tlv_QueryF2, ProviderTextResultDiagnostics) {
    struct Case {
        bool               missing_data;
        tlv_codec_result_t status;
    };
    const Case cases[] = {
        {false, TLV_CODEC_OK}, {true, TLV_CODEC_OK}, {false, TLV_CODEC_ERR_UNSUPPORTED}};
    for (const auto& test : cases) {
        SCOPED_TRACE(test.missing_data);
        SCOPED_TRACE(test.status);
        Evaluation e;
        for (auto& hook : e.hooks) {
            if (hook.function != TLV_QUERY_TEXT) continue;
            hook.context = &test;
            hook.decode = [](const void* context, const tlv_tree_event_t*, const uint8_t*, size_t,
                             void*, size_t, tlv_query_result_t* result) -> tlv_codec_result_t {
                const auto&          test = *static_cast<const Case*>(context);
                static const uint8_t invalid_utf8[] = {0xff};
                result->kind = TLV_QUERY_RESULT_STRING;
                result->data = test.missing_data ? nullptr : invalid_utf8;
                result->size = 1;
                return test.status;
            };
        }
        ASSERT_EQ(e.compile("text(//5A)"), TLV_OK);
        ASSERT_EQ(e.init(), TLV_OK);
        EXPECT_EQ(e.run({0x5a, 1, 1}),
                  test.status == TLV_CODEC_OK ? TLV_ERR_CALLBACK : TLV_ERR_INVALID_VALUE);
        EXPECT_EQ(e.diagnostic.kind,
                  test.status == TLV_CODEC_OK ? TLV_QUERY_ERROR_CALLBACK : TLV_QUERY_ERROR_CODEC);
        EXPECT_EQ(e.diagnostic.codec, test.status);
        EXPECT_LT(e.diagnostic.begin, e.diagnostic.end);
    }
}
