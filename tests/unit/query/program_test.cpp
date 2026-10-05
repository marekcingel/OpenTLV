// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#include "tlv/query/program.h"
#include "../../../tlv/src/query/program_internal.h"
#include "controlled_format.h"
#include <gtest/gtest.h>
#include <cstring>
#include <string>
#include <vector>

namespace {
struct Program {
    std::vector<uint64_t>    storage;
    tlv_query_program_info_t info{};
    tlv_query_diagnostic_t   diagnostic{};
    tlv_result_t             compile(const std::string&                 text,
                                     const tlv_query_compile_options_t* options = nullptr) {
        info.struct_size = sizeof info;
        size_t size, alignment;
        auto   rc = tlv_query_compile_scratch(text.data(), text.size(), options, &size, &alignment,
                                              &diagnostic);
        if (rc != TLV_OK) return rc;
        std::vector<uint64_t> scratch((size + 7) / 8);
        rc = tlv_query_compile(text.data(), text.size(), options, scratch.data(), size, nullptr, 0,
                               &info, &diagnostic);
        if (rc != TLV_OK) return rc;
        storage.resize((info.program_size + 7) / 8);
        return tlv_query_compile(text.data(), text.size(), options, scratch.data(), size,
                                 storage.data(), info.program_size, &info, &diagnostic);
    }
    const tlv_query_program_t* get() const {
        return reinterpret_cast<const tlv_query_program_t*>(storage.data());
    }
};
int constructed(const void*, const tlv_tag_t* tag) {
    return tag->size == 1 && tag->data[0] == 0x70;
}
tlv_visit_result_t collect_event(const tlv_tree_event_t* event, void* context) {
    static_cast<std::vector<size_t>*>(context)->push_back(event->offset);
    return TLV_VISIT_CONTINUE;
}
std::vector<size_t> run(Program& p, const std::vector<uint8_t>& data,
                        tlv_result_t* result = nullptr, size_t work = 100000) {
    size_t bytes, alignment;
    EXPECT_EQ(TLV_OK, tlv_query_exec_size(p.get(), 32, &bytes, &alignment));
    std::vector<uint64_t> workspace((bytes + 7) / 8);
    tlv_query_exec_t*     exec = nullptr;
    EXPECT_EQ(TLV_OK, tlv_query_exec_init(p.get(), workspace.data(), bytes, 32, 1000, work, &exec));
    tlv_tree_frame_t  frames[32];
    tlv_tree_reader_t reader;
    auto              format = controlled::format;
    format.is_constructed = constructed;
    EXPECT_EQ(TLV_OK, tlv_tree_reader_init(&reader, data.data(), data.size(), &format, frames, 32,
                                           32, 1000));
    std::vector<size_t> matches;
    auto rc = tlv_query_program_visit(&reader, exec, collect_event, &matches, &p.diagnostic);
    if (result)
        *result = rc;
    else
        EXPECT_EQ(TLV_OK, rc);
    return matches;
}
} // namespace

TEST(Unit_Tlv_QueryProgram, DescendantUnionIsOrderedAndUnique) {
    Program p;
    ASSERT_EQ(TLV_OK, p.compile("//70//5A | //5A"));
    const std::vector<uint8_t> data = {0x70, 3, 0x5A, 1, 0x12, 0x5A, 1, 0x34};
    EXPECT_EQ((std::vector<size_t>{2, 5}), run(p, data));
    auto copy = p.storage;
    p.storage = copy;
    EXPECT_EQ((std::vector<size_t>{2, 5}), run(p, data));
}
TEST(Unit_Tlv_QueryProgram, SignedIntegersAndSubstringBounds) {
    Program p;
    ASSERT_EQ(TLV_OK, p.compile("//5A[@len > -1 and -9223372036854775808 < -1]"));
    EXPECT_EQ((std::vector<size_t>{0}), run(p, {0x5A, 1, 0x12}));
    ASSERT_EQ(TLV_OK, p.compile("//5A[-0 = 0 and -2 < -1 and 9223372036854775807 > @len]"));
    EXPECT_EQ((std::vector<size_t>{0}), run(p, {0x5A, 0}));
    EXPECT_EQ(TLV_ERR_OVERFLOW, p.compile("//5A[@len = 9223372036854775808]"));
    EXPECT_EQ(TLV_ERR_OVERFLOW, p.compile("//5A[@len = -9223372036854775809]"));
    ASSERT_EQ(TLV_OK, p.compile("//5A[substr(value(), -1) = x'']"));
    tlv_result_t rc;
    EXPECT_TRUE(run(p, {0x5A, 1, 0x12}, &rc).empty());
    EXPECT_EQ(TLV_ERR_INVALID_VALUE, rc);
}
TEST(Unit_Tlv_QueryProgram, UniqueVariableRequirementsAndCompactWorkspace) {
    tlv_query_variable_t        variables[] = {{"unused", TLV_QUERY_RESULT_BYTES},
                                               {"min-1", TLV_QUERY_RESULT_INTEGER}};
    tlv_query_compile_options_t options;
    tlv_query_compile_options_init(&options);
    options.variables = variables;
    options.variable_count = 2;
    Program p;
    ASSERT_EQ(TLV_OK, p.compile("//5A[@len > $min-1 and @len != $min-1]", &options));
    EXPECT_EQ(1u, p.info.variable_slots);
    EXPECT_EQ(1u, tlv_query_program_variable_count(p.get()));
    tlv_query_variable_info_t variable{};
    ASSERT_EQ(TLV_OK, tlv_query_program_variable(p.get(), 0, &variable));
    EXPECT_EQ("min-1", std::string(variable.name, variable.name_size));
    EXPECT_EQ(TLV_QUERY_RESULT_INTEGER, variable.type);
    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_query_program_variable(p.get(), 1, &variable));
    EXPECT_EQ("min-1", std::string(variable.name, variable.name_size));
    size_t bytes, alignment;
    ASSERT_EQ(TLV_OK, tlv_query_exec_size(p.get(), 0, &bytes, &alignment));
    EXPECT_EQ(sizeof(tlv_query_exec_t) + (p.info.states + 1) * sizeof(query_value_t) +
                  sizeof(size_t) + p.info.states,
              bytes);
    std::vector<uint64_t> workspace((bytes + 7) / 8);
    tlv_query_exec_t*     exec;
    ASSERT_EQ(TLV_OK, tlv_query_exec_init(p.get(), workspace.data(), bytes, 0, 10, 1000, &exec));
    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_query_exec_bind(exec, "unused", TLV_QUERY_RESULT_BYTES, 0,
                                                       nullptr, 0, &p.diagnostic));
    ASSERT_EQ(TLV_OK, tlv_query_exec_bind(exec, "min-1", TLV_QUERY_RESULT_INTEGER, -1, nullptr, 0,
                                          &p.diagnostic));
    tlv_tree_event_t event{};
    const uint8_t    tag = 0x5a;
    event.kind = TLV_TREE_ELEMENT;
    event.element.tag = tlv_tag(&tag, 1);
    int matched;
    ASSERT_EQ(TLV_OK, tlv_query_exec_feed(exec, &event, &matched, &p.diagnostic));
    EXPECT_EQ(1, matched);
    auto copy = p.storage;
    p.storage = copy;
    ASSERT_EQ(TLV_OK, tlv_query_program_variable(p.get(), 0, &variable));
    EXPECT_EQ("min-1", std::string(variable.name, variable.name_size));
    auto* nodes = const_cast<query_node_t*>(query_nodes(p.get()));
    for (size_t i = 0; i < p.info.states; ++i)
        if (nodes[i].op == Q_VARIABLE) {
            nodes[i].type = V_BOOL;
            break;
        }
    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_query_exec_size(p.get(), 0, &bytes, &alignment));
    ASSERT_EQ(TLV_OK, p.compile("//5A"));
    EXPECT_EQ(0u, tlv_query_program_variable_count(p.get()));
    ASSERT_EQ(TLV_OK, tlv_query_exec_size(p.get(), 0, &bytes, &alignment));
    EXPECT_EQ(sizeof(tlv_query_exec_t) + p.info.states * sizeof(query_value_t) + sizeof(size_t) +
                  p.info.states,
              bytes);
}
TEST(Unit_Tlv_QueryProgram, VariableIdentifiersFollowGrammar) {
    Program p;
    EXPECT_EQ(TLV_ERR_INVALID_ARG, p.compile("//5A[@len > $123]"));
    EXPECT_EQ(TLV_QUERY_ERROR_SYNTAX, p.diagnostic.kind);
    EXPECT_EQ(TLV_ERR_INVALID_ARG, p.compile("//5A[@len > $?foo]"));
    EXPECT_EQ(TLV_ERR_INVALID_ARG, p.compile("//5A[@len > $_foo]"));
    tlv_query_compile_options_t options;
    tlv_query_compile_options_init(&options);
    tlv_query_variable_t variable = {"123", TLV_QUERY_RESULT_INTEGER};
    options.variables = &variable;
    options.variable_count = 1;
    EXPECT_EQ(TLV_ERR_INVALID_ARG, p.compile("//5A", &options));
    variable.name = "a?b";
    EXPECT_EQ(TLV_ERR_INVALID_ARG, p.compile("//5A", &options));
}
TEST(Unit_Tlv_QueryProgram, IntersectionAndDifferenceBindMoreStronglyThanUnion) {
    Program p;
    ASSERT_EQ(TLV_OK, p.compile("//5A | //5A except //5A"));
    EXPECT_EQ((std::vector<size_t>{0}), run(p, {0x5a, 0}));
    ASSERT_EQ(TLV_OK, p.compile("(//5A | //5A) except //5A"));
    EXPECT_TRUE(run(p, {0x5a, 0}).empty());
    ASSERT_EQ(TLV_OK, p.compile("//5A | //70 intersect //70 except //70"));
    EXPECT_EQ((std::vector<size_t>{0}), run(p, {0x5a, 0, 0x70, 0}));
}
TEST(Unit_Tlv_QueryProgram, CallerSizedInfoPreservesUnknownAndUnavailableFields) {
    const std::string text = "//5A";
    size_t            bytes, alignment;
    ASSERT_EQ(TLV_OK, tlv_query_compile_scratch(text.data(), text.size(), nullptr, &bytes,
                                                &alignment, nullptr));
    std::vector<uint64_t> scratch((bytes + 7) / 8);
    struct Extended {
        tlv_query_program_info_t info;
        uint64_t                 sentinel;
    } output{};
    output.info.struct_size = sizeof output;
    output.sentinel = UINT64_MAX;
    ASSERT_EQ(TLV_OK, tlv_query_compile(text.data(), text.size(), nullptr, scratch.data(), bytes,
                                        nullptr, 0, &output.info, nullptr));
    EXPECT_EQ(UINT64_MAX, output.sentinel);
    EXPECT_EQ(sizeof output, output.info.struct_size);
    output.info.struct_size = offsetof(tlv_query_program_info_t, expression_values);
    output.info.expression_values = SIZE_MAX;
    ASSERT_EQ(TLV_OK, tlv_query_compile(text.data(), text.size(), nullptr, scratch.data(), bytes,
                                        nullptr, 0, &output.info, nullptr));
    EXPECT_EQ(SIZE_MAX, output.info.expression_values);
    output.info.struct_size = 0;
    EXPECT_EQ(TLV_ERR_INVALID_ARG,
              tlv_query_compile(text.data(), text.size(), nullptr, scratch.data(), bytes, nullptr,
                                0, &output.info, nullptr));
    Program p;
    ASSERT_EQ(TLV_OK, p.compile(text));
    ASSERT_EQ(TLV_OK, tlv_query_exec_size(p.get(), 0, &bytes, &alignment));
    std::vector<uint64_t> workspace((bytes + 7) / 8);
    tlv_query_exec_t*     exec;
    ASSERT_EQ(TLV_OK, tlv_query_exec_init(p.get(), workspace.data(), bytes, 0, 10, 100, &exec));
    tlv_query_exec_info_t info{};
    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_query_exec_info(exec, &info));
    info.struct_size = offsetof(tlv_query_exec_info_t, work);
    info.work = SIZE_MAX;
    ASSERT_EQ(TLV_OK, tlv_query_exec_info(exec, &info));
    EXPECT_EQ(0u, info.elements);
    EXPECT_EQ(SIZE_MAX, info.work);
}
TEST(Unit_Tlv_QueryProgram, SetOperationsUseNodeIdentityAndSourceOrder) {
    Program                    p;
    const std::vector<uint8_t> data = {0x70, 3, 0x5A, 1, 0x12, 0x5A, 1, 0x12};
    ASSERT_EQ(TLV_OK, p.compile("//5A intersect //70//5A"));
    EXPECT_EQ((std::vector<size_t>{2}), run(p, data));
    ASSERT_EQ(TLV_OK, p.compile("//5A except //70//5A"));
    EXPECT_EQ((std::vector<size_t>{5}), run(p, data));
    ASSERT_EQ(TLV_OK, p.compile("(//5A | //5A) intersect (//5A | //70)"));
    EXPECT_EQ((std::vector<size_t>{2, 5}), run(p, data));
    EXPECT_EQ(TLV_OK, p.compile("//5A except //70[not(5A)]"));
    EXPECT_EQ(TLV_QUERY_D, p.info.level);
}
TEST(Unit_Tlv_QueryProgram, TypedBindingsAreIndependentAndNeverQueryText) {
    tlv_query_variable_t        variables[] = {{"aid", TLV_QUERY_RESULT_BYTES},
                                               {"min", TLV_QUERY_RESULT_INTEGER}};
    tlv_query_compile_options_t options;
    tlv_query_compile_options_init(&options);
    options.variables = variables;
    options.variable_count = 2;
    Program p;
    ASSERT_EQ(TLV_OK, p.compile("//84[value() = $aid and @len > $min]", &options));
    size_t bytes, alignment;
    ASSERT_EQ(TLV_OK, tlv_query_exec_size(p.get(), 2, &bytes, &alignment));
    std::vector<uint64_t> first((bytes + 7) / 8), second((bytes + 7) / 8);
    tlv_query_exec_t *    a, *b;
    ASSERT_EQ(TLV_OK, tlv_query_exec_init(p.get(), first.data(), bytes, 2, 10, 1000, &a));
    ASSERT_EQ(TLV_OK, tlv_query_exec_init(p.get(), second.data(), bytes, 2, 10, 1000, &b));
    const uint8_t aid[] = {0, '$', '[', ']'};
    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_query_exec_bind(a, "unknown", TLV_QUERY_RESULT_BYTES, 0, aid,
                                                       sizeof aid, &p.diagnostic));
    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_query_exec_bind(a, "aid", TLV_QUERY_RESULT_INTEGER, 1,
                                                       nullptr, 0, &p.diagnostic));
    ASSERT_EQ(TLV_OK, tlv_query_exec_bind(a, "aid", TLV_QUERY_RESULT_BYTES, 0, aid, sizeof aid,
                                          &p.diagnostic));
    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_query_exec_bind(a, "aid", TLV_QUERY_RESULT_BYTES, 0, aid,
                                                       sizeof aid, &p.diagnostic));
    ASSERT_EQ(TLV_OK, tlv_query_exec_bind(a, "min", TLV_QUERY_RESULT_INTEGER, INT64_MIN, nullptr, 0,
                                          &p.diagnostic));
    ASSERT_EQ(TLV_OK,
              tlv_query_exec_bind(b, "aid", TLV_QUERY_RESULT_BYTES, 0, nullptr, 0, &p.diagnostic));
    ASSERT_EQ(TLV_OK, tlv_query_exec_bind(b, "min", TLV_QUERY_RESULT_INTEGER, 0, nullptr, 0,
                                          &p.diagnostic));
    const uint8_t    tag = 0x84;
    tlv_tree_event_t event{};
    event.kind = TLV_TREE_ELEMENT;
    event.element.tag = tlv_tag(&tag, 1);
    event.element.value.data = aid;
    event.element.value.size = sizeof aid;
    int matched;
    ASSERT_EQ(TLV_OK, tlv_query_exec_feed(a, &event, &matched, &p.diagnostic));
    EXPECT_EQ(1, matched);
    ASSERT_EQ(TLV_OK, tlv_query_exec_feed(b, &event, &matched, &p.diagnostic));
    EXPECT_EQ(0, matched);
    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_query_exec_bind(a, "min", TLV_QUERY_RESULT_INTEGER, 0,
                                                       nullptr, 0, &p.diagnostic));
    ASSERT_EQ(TLV_OK, tlv_query_exec_init(p.get(), first.data(), bytes, 2, 10, 1000, &a));
    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_query_exec_feed(a, &event, &matched, &p.diagnostic));
    EXPECT_EQ(TLV_QUERY_ERROR_BINDING, p.diagnostic.kind);
    options.variable_count = 0;
    EXPECT_EQ(TLV_ERR_INVALID_ARG, p.compile("//84[value() = $aid]", &options));
}
TEST(Unit_Tlv_QueryProgram, MetadataBytesAndAncestorPredicates) {
    Program p;
    ASSERT_EQ(TLV_OK, p.compile("//5A[@len = 1 and starts-with(value(), x'12') and ancestor::70]"));
    EXPECT_EQ((std::vector<size_t>{2}), run(p, {0x70, 3, 0x5A, 1, 0x12, 0x5A, 1, 0x12}));
    ASSERT_EQ(TLV_OK, p.compile("//5A[substr(value(), 0, 1) = x'12']"));
    EXPECT_EQ((std::vector<size_t>{0}), run(p, {0x5A, 2, 0x12, 0x34}));
}
TEST(Unit_Tlv_QueryProgram, BindingsValidateUtf8TypesAndEmptyInput) {
    tlv_query_variable_t        variables[] = {{"a", TLV_QUERY_RESULT_STRING},
                                               {"b", TLV_QUERY_RESULT_STRING}};
    tlv_query_compile_options_t options;
    tlv_query_compile_options_init(&options);
    options.variables = variables;
    options.variable_count = 2;
    Program p;
    ASSERT_EQ(TLV_OK, p.compile("//5A[$a = $b]", &options));
    EXPECT_EQ(2u, p.info.variable_slots);
    EXPECT_EQ(p.info.states, p.info.instructions);
    EXPECT_EQ(p.info.states, p.info.expression_values);
    size_t bytes, alignment;
    ASSERT_EQ(TLV_OK, tlv_query_exec_size(p.get(), 1, &bytes, &alignment));
    std::vector<uint64_t> storage((bytes + 7) / 8);
    tlv_query_exec_t*     exec;
    ASSERT_EQ(TLV_OK, tlv_query_exec_init(p.get(), storage.data(), bytes, 1, 10, 1000, &exec));
    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_query_exec_finish(exec, &p.diagnostic));
    EXPECT_EQ(TLV_QUERY_ERROR_BINDING, p.diagnostic.kind);
    ASSERT_EQ(TLV_OK, tlv_query_exec_init(p.get(), storage.data(), bytes, 1, 10, 1000, &exec));
    const uint8_t invalid[] = {0xc0, 0x80};
    EXPECT_EQ(TLV_ERR_INVALID_VALUE, tlv_query_exec_bind(exec, "a", TLV_QUERY_RESULT_STRING, 0,
                                                         invalid, sizeof invalid, &p.diagnostic));
    const uint8_t text[] = {0, 0xc3, 0xa9};
    ASSERT_EQ(TLV_OK, tlv_query_exec_bind(exec, "a", TLV_QUERY_RESULT_STRING, 0, text, sizeof text,
                                          &p.diagnostic));
    ASSERT_EQ(TLV_OK, tlv_query_exec_bind(exec, "b", TLV_QUERY_RESULT_STRING, 0, text, sizeof text,
                                          &p.diagnostic));
    const uint8_t    tag = 0x5a;
    tlv_tree_event_t event{};
    event.kind = TLV_TREE_ELEMENT;
    event.element.tag = tlv_tag(&tag, 1);
    int matched;
    ASSERT_EQ(TLV_OK, tlv_query_exec_feed(exec, &event, &matched, &p.diagnostic));
    EXPECT_EQ(1, matched);
    ASSERT_EQ(TLV_OK, tlv_query_exec_finish(exec, &p.diagnostic));
    variables[1].type = TLV_QUERY_RESULT_BYTES;
    EXPECT_EQ(TLV_ERR_INVALID_ARG, p.compile("//5A[$a = $b]", &options));
    variables[1].name = "a";
    EXPECT_EQ(TLV_ERR_INVALID_ARG, p.compile("//5A[$a = $b]", &options));
    EXPECT_EQ(TLV_QUERY_ERROR_BINDING, p.diagnostic.kind);
}
TEST(Unit_Tlv_QueryProgram, MissingBindingsDoNotAdvanceReader) {
    tlv_query_variable_t        variable = {"min", TLV_QUERY_RESULT_INTEGER};
    tlv_query_compile_options_t options;
    tlv_query_compile_options_init(&options);
    options.variables = &variable;
    options.variable_count = 1;
    Program p;
    ASSERT_EQ(TLV_OK, p.compile("//5A[@len > $min]", &options));
    size_t bytes, alignment;
    ASSERT_EQ(TLV_OK, tlv_query_exec_size(p.get(), 2, &bytes, &alignment));
    std::vector<uint64_t> storage((bytes + 7) / 8);
    tlv_query_exec_t*     exec;
    ASSERT_EQ(TLV_OK, tlv_query_exec_init(p.get(), storage.data(), bytes, 2, 10, 1000, &exec));
    const uint8_t     data[] = {0x5a, 0};
    tlv_tree_frame_t  frames[2];
    tlv_tree_reader_t reader;
    ASSERT_EQ(TLV_OK, tlv_tree_reader_init(&reader, data, sizeof data, &controlled::format, frames,
                                           2, 2, 10));
    std::vector<size_t> matches;
    EXPECT_EQ(TLV_ERR_INVALID_ARG,
              tlv_query_program_visit(&reader, exec, collect_event, &matches, &p.diagnostic));
    tlv_tree_event_t event;
    EXPECT_EQ(TLV_OK, tlv_tree_reader_next_event(&reader, &event));
    EXPECT_EQ(0u, event.offset);
}
TEST(Unit_Tlv_QueryProgram, UnsupportedFeaturesHavePreciseDiagnostics) {
    Program p;
    EXPECT_EQ(TLV_OK, p.compile("//70[not(5A)] | //5A"));
    EXPECT_EQ(TLV_QUERY_D, p.info.level);
    size_t bytes, alignment;
    EXPECT_EQ(TLV_ERR_UNSUPPORTED_TYPE, tlv_query_exec_size(p.get(), 1, &bytes, &alignment));
    EXPECT_EQ(TLV_ERR_UNSUPPORTED_TYPE, p.compile("//5A[num(.) > $min]"));
    EXPECT_EQ(TLV_QUERY_ERROR_CAPABILITY, p.diagnostic.kind);
    EXPECT_EQ(TLV_ERR_INVALID_ARG, p.compile("//5A[@len > 1"));
    EXPECT_EQ(TLV_QUERY_ERROR_SYNTAX, p.diagnostic.kind);
    EXPECT_EQ(TLV_OK, p.compile("//5A[1]"));
    EXPECT_EQ(TLV_QUERY_D, p.info.level);
    EXPECT_EQ(TLV_ERR_INVALID_ARG, p.compile("//9F?"));
    EXPECT_EQ(TLV_ERR_INVALID_ARG, p.compile("//tag-mask(x'00', x'FFFF')"));
    EXPECT_EQ(TLV_ERR_INVALID_ARG, p.compile("//tag-range(x'FF', x'00')"));
    EXPECT_EQ(TLV_ERR_INVALID_ARG, p.compile("unknown::5A"));
    EXPECT_EQ(TLV_QUERY_ERROR_SYNTAX, p.diagnostic.kind);
    EXPECT_EQ(TLV_ERR_UNSUPPORTED_TYPE, p.compile("70/(//5A)"));
    EXPECT_EQ(TLV_QUERY_ERROR_CAPABILITY, p.diagnostic.kind);
    EXPECT_EQ(TLV_OK, p.compile("//5A[ancestor::70[@len=3]]"));
    EXPECT_EQ(TLV_QUERY_D, p.info.level);
}

TEST(Unit_Tlv_QueryProgram, CapacityAndNestingBoundariesPreserveStorage) {
    const std::string      text = "//5A[@len=1]";
    size_t                 size, alignment;
    tlv_query_diagnostic_t d{};
    ASSERT_EQ(TLV_OK,
              tlv_query_compile_scratch(text.data(), text.size(), nullptr, &size, &alignment, &d));
    std::vector<uint64_t>    scratch((size + 7) / 8);
    tlv_query_program_info_t info{};
    info.struct_size = sizeof info;
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
              tlv_query_compile(text.data(), text.size(), nullptr, scratch.data(), size - 1,
                                nullptr, 0, &info, &d));
    ASSERT_EQ(TLV_OK, tlv_query_compile(text.data(), text.size(), nullptr, scratch.data(), size,
                                        nullptr, 0, &info, &d));
    std::vector<uint64_t> storage((info.program_size + 7) / 8, UINT64_MAX);
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
              tlv_query_compile(text.data(), text.size(), nullptr, scratch.data(), size,
                                storage.data(), info.program_size - 1, &info, &d));
    EXPECT_EQ(UINT64_MAX, storage[0]);
    EXPECT_EQ(TLV_QUERY_ERROR_STORAGE, d.kind);
    tlv_query_compile_options_t options;
    tlv_query_compile_options_init(&options);
    options.max_nesting = 1;
    const std::string nested = "((5A))";
    ASSERT_EQ(TLV_OK, tlv_query_compile_scratch(nested.data(), nested.size(), &options, &size,
                                                &alignment, &d));
    scratch.resize((size + 7) / 8);
    EXPECT_EQ(TLV_ERR_LIMIT, tlv_query_compile(nested.data(), nested.size(), &options,
                                               scratch.data(), size, nullptr, 0, &info, &d));
    EXPECT_STREQ("nesting", d.limit);
    EXPECT_EQ(1u, d.begin);
}

TEST(Unit_Tlv_QueryProgram, CorruptInternalImagesAreRejectedBeforeExecutionOrFormatting) {
    Program original;
    ASSERT_EQ(TLV_OK, original.compile("//70/5A[@len=1]"));
    for (unsigned mutation = 0; mutation < 15; ++mutation) {
        auto  storage = original.storage;
        auto* p = reinterpret_cast<tlv_query_program_t*>(storage.data());
        auto* nodes = reinterpret_cast<query_node_t*>(p + 1);
        switch (mutation) {
            case 0: p->root = 1000000; break;
            case 1: ++p->version; break;
            case 2: p->count = 0; break;
            case 3: ++p->count; break;
            case 4: ++p->text_offset; break;
            case 5: ++p->text_size; break;
            case 6: ++p->reserved; break;
            case 7: nodes[0].left = 1000000; break;
            case 8: nodes[0].right = 0; break;
            case 9: nodes[0].predicate_guard = 1000000; break;
            case 10: nodes[0].path_guard = 0; break;
            case 11: nodes[0].end = p->text_size + 1; break;
            case 12: nodes[0].op = Q_ARGS + 1; break;
            case 13: nodes[0].axis = A_OTHER + 1; break;
            case 14:
                p = reinterpret_cast<tlv_query_program_t*>(reinterpret_cast<char*>(p) + 1);
                break;
        }
        size_t bytes = 777, alignment = 777, required = 777;
        EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_query_exec_size(p, 4, &bytes, &alignment)) << mutation;
        EXPECT_EQ(777u, bytes);
        uint64_t          workspace[4096];
        tlv_query_exec_t* exec = nullptr;
        EXPECT_EQ(TLV_ERR_INVALID_ARG,
                  tlv_query_exec_init(p, workspace, sizeof workspace, 4, 100, 10000, &exec))
            << mutation;
        EXPECT_EQ(nullptr, exec);
        char output[64] = "unchanged";
        EXPECT_EQ(TLV_ERR_INVALID_ARG,
                  tlv_query_program_format(p, output, sizeof output, &required))
            << mutation;
        EXPECT_STREQ("unchanged", output);
        EXPECT_EQ(777u, required);
    }
}

TEST(Unit_Tlv_QueryProgram, ExplicitNumericAxesRemainTagTests) {
    for (const auto& text : {std::string("//70[50]"), std::string("//70[child::50]"),
                             std::string("//70[child:: 50]")}) {
        Program p;
        ASSERT_EQ(TLV_OK, p.compile(text));
        EXPECT_EQ(TLV_QUERY_D, p.info.level);
        const query_node_t* nodes = query_nodes(p.get());
        int                 literal = 0;
        for (size_t i = 0; i < p.info.states; ++i)
            if (nodes[i].op == Q_LITERAL) literal = 1;
        EXPECT_EQ(text.find("::") == std::string::npos, literal != 0);
    }
}

TEST(Unit_Tlv_QueryProgram, StopResumeAndNeedMoreDataDoNotRepeatMatches) {
    Program p;
    ASSERT_EQ(TLV_OK, p.compile("//5A"));
    size_t bytes, alignment;
    ASSERT_EQ(TLV_OK, tlv_query_exec_size(p.get(), 4, &bytes, &alignment));
    std::vector<uint64_t> workspace((bytes + 7) / 8);
    tlv_query_exec_t*     exec;
    ASSERT_EQ(TLV_OK, tlv_query_exec_init(p.get(), workspace.data(), bytes, 4, 100, 10000, &exec));
    auto format = controlled::format;
    format.is_constructed = constructed;
    const uint8_t     first[] = {0x5A, 1, 0x12};
    const uint8_t     whole[] = {0x5A, 1, 0x12, 0x70, 3, 0x5A, 1, 0x34};
    tlv_tree_frame_t  frames[4];
    tlv_tree_reader_t reader;
    ASSERT_EQ(TLV_OK, tlv_tree_reader_init_incremental(&reader, first, sizeof first, &format,
                                                       frames, 4, 4, 100));
    std::vector<size_t> matches;
    auto                stop = [](const tlv_tree_event_t* event, void* context) {
        static_cast<std::vector<size_t>*>(context)->push_back(event->offset);
        return TLV_VISIT_STOP;
    };
    ASSERT_EQ(TLV_OK, tlv_query_program_visit(&reader, exec, stop, &matches, &p.diagnostic));
    EXPECT_EQ(TLV_NEED_MORE_DATA,
              tlv_query_program_visit(&reader, exec, collect_event, &matches, &p.diagnostic));
    ASSERT_EQ(TLV_OK, tlv_tree_reader_set_input(&reader, whole, sizeof whole, 0, 1));
    ASSERT_EQ(TLV_OK,
              tlv_query_program_visit(&reader, exec, collect_event, &matches, &p.diagnostic));
    EXPECT_EQ((std::vector<size_t>{0, 5}), matches);
    EXPECT_EQ(TLV_OK,
              tlv_query_program_visit(&reader, exec, collect_event, &matches, &p.diagnostic));
    EXPECT_EQ(2u, matches.size());
}
TEST(Unit_Tlv_QueryProgram, MasksRangesAndWildcardsCompareRawBytes) {
    Program p;
    ASSERT_EQ(TLV_OK, p.compile("//??"));
    EXPECT_EQ((std::vector<size_t>{0, 3}), run(p, {0x5A, 1, 0, 0x70, 0}));
    ASSERT_EQ(TLV_OK, p.compile("//tag-mask(x'50', x'F0')"));
    EXPECT_EQ((std::vector<size_t>{0}), run(p, {0x5A, 1, 0, 0x70, 0}));
    ASSERT_EQ(TLV_OK, p.compile("//tag-range(x'50', x'60')"));
    EXPECT_EQ((std::vector<size_t>{0}), run(p, {0x5A, 1, 0, 0x70, 0}));
}
TEST(Unit_Tlv_QueryProgram, ValidationAndWorkLimitsAreExplicit) {
    Program p;
    ASSERT_EQ(TLV_OK, p.compile("//5A"));
    tlv_result_t result;
    EXPECT_EQ((std::vector<size_t>{0}), run(p, {0x5A, 1, 0, 0x5A}, &result));
    EXPECT_NE(TLV_OK, result);
    EXPECT_EQ(TLV_QUERY_ERROR_READER, p.diagnostic.kind);
    run(p, {0x5A, 1, 0}, &result, 1);
    EXPECT_EQ(TLV_ERR_LIMIT, result);
    ASSERT_NE(nullptr, p.diagnostic.limit);
    EXPECT_STREQ("work", p.diagnostic.limit);
}
TEST(Unit_Tlv_QueryProgram, EventFeedRejectsUnbalancedEventsAndMissingSource) {
    Program p;
    ASSERT_EQ(TLV_OK, p.compile("//5A[@offset = 0]"));
    size_t bytes, alignment;
    ASSERT_EQ(TLV_OK, tlv_query_exec_size(p.get(), 4, &bytes, &alignment));
    std::vector<uint64_t> workspace((bytes + 7) / 8);
    tlv_query_exec_t*     exec;
    ASSERT_EQ(TLV_OK, tlv_query_exec_init(p.get(), workspace.data(), bytes, 4, 100, 1000, &exec));
    tlv_tree_event_t event{};
    event.kind = TLV_TREE_ELEMENT;
    uint8_t tag = 0x5A;
    event.element.tag = tlv_tag(&tag, 1);
    int matched = 9;
    tag = 0x84;
    EXPECT_EQ(TLV_OK, tlv_query_exec_feed(exec, &event, &matched, &p.diagnostic));
    EXPECT_EQ(0, matched);
    ASSERT_EQ(TLV_OK, tlv_query_exec_init(p.get(), workspace.data(), bytes, 4, 100, 1000, &exec));
    tag = 0x5A;
    matched = 9;
    EXPECT_EQ(TLV_ERR_INVALID_VALUE, tlv_query_exec_feed(exec, &event, &matched, &p.diagnostic));
    EXPECT_EQ(9, matched);
    EXPECT_EQ(TLV_QUERY_ERROR_SOURCE, p.diagnostic.kind);
    ASSERT_EQ(TLV_OK, tlv_query_exec_init(p.get(), workspace.data(), bytes, 4, 100, 1000, &exec));
    event.kind = TLV_TREE_END;
    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_query_exec_feed(exec, &event, &matched, &p.diagnostic));
}

TEST(Unit_Tlv_QueryProgram, CustomEventsPreserveTagWidthsAndSourceHeaderSemantics) {
    const uint8_t tag[] = {0x9F, 0x02};
    const uint8_t wire[] = {0, 0, 0, 0, 0, 0};
    for (const auto& example : std::vector<std::pair<std::string, std::vector<int>>>{
             {"//*", {1, 1, 1}},
             {"//??", {0, 0, 0}},
             {"//9F??", {0, 0, 1}},
             {"//9F02[@hlen=4 and @offset=0]", {0, 0, 1}}}) {
        Program p;
        ASSERT_EQ(TLV_OK, p.compile(example.first));
        size_t bytes, alignment;
        ASSERT_EQ(TLV_OK, tlv_query_exec_size(p.get(), 1, &bytes, &alignment));
        std::vector<uint64_t> workspace((bytes + 7) / 8);
        tlv_query_exec_t*     exec;
        ASSERT_EQ(TLV_OK,
                  tlv_query_exec_init(p.get(), workspace.data(), bytes, 1, 10, 1000, &exec));
        for (size_t i = 0; i < 3; ++i) {
            tlv_tree_event_t event{};
            event.kind = TLV_TREE_ELEMENT;
            event.element.tag = i == 0 ? tlv_tag(nullptr, 0) : tlv_tag(tag, i == 1 ? 0 : 2);
            event.source.data = wire;
            event.source.size = sizeof wire;
            event.source.header.present = 1;
            event.source.header.size = 4;
            int matched = -1;
            ASSERT_EQ(TLV_OK, tlv_query_exec_feed(exec, &event, &matched, &p.diagnostic));
            EXPECT_EQ(example.second[i], matched) << example.first;
        }
        EXPECT_EQ(TLV_OK, tlv_query_exec_finish(exec, &p.diagnostic));
    }
}

TEST(Unit_Tlv_QueryProgram, RelativeContextAndSelfPreserveAbsoluteRoot) {
    const uint8_t input[] = {0x70, 3, 0x5A, 1, 0x12, 0x5A, 1, 0x34};
    for (const auto& example :
         std::vector<std::pair<std::string, std::vector<size_t>>>{{"5A", {2}},
                                                                  {"/5A", {5}},
                                                                  {".//5A", {2}},
                                                                  {".", {0}},
                                                                  {"self::70", {0}},
                                                                  {"descendant::5A", {2}},
                                                                  {"/70/./5A", {2}}}) {
        Program p;
        ASSERT_EQ(TLV_OK, p.compile(example.first));
        size_t bytes, alignment;
        ASSERT_EQ(TLV_OK, tlv_query_exec_size(p.get(), 8, &bytes, &alignment));
        std::vector<uint64_t> workspace((bytes + 7) / 8);
        tlv_query_exec_t*     exec;
        ASSERT_EQ(TLV_OK,
                  tlv_query_exec_init(p.get(), workspace.data(), bytes, 8, 100, 10000, &exec));
        ASSERT_EQ(TLV_OK, tlv_query_exec_context(exec, 0));
        auto format = controlled::format;
        format.is_constructed = constructed;
        tlv_tree_reader_t reader;
        tlv_tree_frame_t  frames[8];
        ASSERT_EQ(TLV_OK,
                  tlv_tree_reader_init(&reader, input, sizeof input, &format, frames, 8, 8, 100));
        std::vector<size_t> matches;
        ASSERT_EQ(TLV_OK,
                  tlv_query_program_visit(&reader, exec, collect_event, &matches, &p.diagnostic));
        EXPECT_EQ(example.second, matches) << example.first;
    }
}

TEST(Unit_Tlv_QueryProgram, PruningAndExistsExposePartialCoverage) {
    const uint8_t input[] = {0x70, 1, 0x5A, 0x5A, 1, 0x12}; // Malformed unmatched 70 subtree.
    Program       p;
    ASSERT_EQ(TLV_OK, p.compile("5A"));
    size_t bytes, alignment;
    ASSERT_EQ(TLV_OK, tlv_query_exec_size(p.get(), 8, &bytes, &alignment));
    std::vector<uint64_t> workspace((bytes + 7) / 8);
    tlv_query_exec_t*     exec;
    auto                  format = controlled::format;
    format.is_constructed = constructed;
    tlv_tree_reader_t reader;
    tlv_tree_frame_t  frames[8];
    ASSERT_EQ(TLV_OK, tlv_query_exec_init(p.get(), workspace.data(), bytes, 8, 100, 10000, &exec));
    ASSERT_EQ(TLV_OK,
              tlv_tree_reader_init(&reader, input, sizeof input, &format, frames, 8, 8, 100));
    int found = 9;
    EXPECT_NE(TLV_OK, tlv_query_program_exists(&reader, exec, 0, &found, &p.diagnostic));
    EXPECT_EQ(9, found);
    ASSERT_EQ(TLV_OK, tlv_query_exec_init(p.get(), workspace.data(), bytes, 8, 100, 10000, &exec));
    ASSERT_EQ(TLV_OK, tlv_query_exec_pruning(exec, 1));
    ASSERT_EQ(TLV_OK,
              tlv_tree_reader_init(&reader, input, sizeof input, &format, frames, 8, 8, 100));
    ASSERT_EQ(TLV_OK, tlv_query_program_exists(&reader, exec, 0, &found, &p.diagnostic));
    EXPECT_EQ(1, found);
    tlv_query_exec_info_t info{};
    info.struct_size = sizeof info;
    ASSERT_EQ(TLV_OK, tlv_query_exec_info(exec, &info));
    EXPECT_EQ(1u, info.skipped_subtrees);
    EXPECT_EQ(1, info.finished);
    EXPECT_EQ(0, info.full_validation);
    const uint8_t suffix[] = {0x5A, 1, 0x12, 0x5A};
    ASSERT_EQ(TLV_OK, tlv_query_exec_init(p.get(), workspace.data(), bytes, 8, 100, 10000, &exec));
    ASSERT_EQ(TLV_OK,
              tlv_tree_reader_init(&reader, suffix, sizeof suffix, &format, frames, 8, 8, 100));
    ASSERT_EQ(TLV_OK, tlv_query_program_exists(&reader, exec, 1, &found, &p.diagnostic));
    EXPECT_EQ(1, found);
    ASSERT_EQ(TLV_OK, tlv_query_exec_info(exec, &info));
    EXPECT_EQ(0, info.finished);
    EXPECT_EQ(0, info.full_validation);
    EXPECT_NE(TLV_OK, tlv_query_program_exists(&reader, exec, 0, &found, &p.diagnostic));
}
TEST(Unit_Tlv_QueryProgram, CanonicalFormatRecompilesAndShortWritesAreAtomic) {
    Program p;
    ASSERT_EQ(TLV_OK, p.compile("  //5a [ @len = 1 ]  "));
    size_t required;
    ASSERT_EQ(TLV_OK, tlv_query_program_format(p.get(), nullptr, 0, &required));
    std::vector<char> output(required, '?');
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
              tlv_query_program_format(p.get(), output.data(), required - 1, &required));
    EXPECT_EQ('?', output[0]);
    ASSERT_EQ(TLV_OK, tlv_query_program_format(p.get(), output.data(), required, &required));
    Program copy;
    ASSERT_EQ(TLV_OK, copy.compile(output.data()));
    std::vector<char> second(required);
    ASSERT_EQ(TLV_OK, tlv_query_program_format(copy.get(), second.data(), required, &required));
    EXPECT_EQ(output, second);
}

TEST(Unit_Tlv_Query, BoundedParsingFormattingAndCorruptAccess) {
    tlv_query_t query{};
    const char  slice[] = {'6', 'f', '/', '5', '0'};
    ASSERT_EQ(TLV_OK, tlv_query_parse_n(slice, sizeof slice, &query, nullptr));
    size_t required;
    ASSERT_EQ(TLV_OK, tlv_query_format(&query, nullptr, 0, &required));
    EXPECT_EQ(6u, required);
    char output[6] = {'?', '?', '?', '?', '?', '?'};
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_query_format(&query, output, 5, &required));
    EXPECT_EQ('?', output[0]);
    ASSERT_EQ(TLV_OK, tlv_query_format(&query, output, sizeof output, &required));
    EXPECT_STREQ("6F/50", output);
    auto   copy = query;
    size_t offset = 99;
    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_query_parse_n("6F\0/50", 6, &query, &offset));
    EXPECT_EQ(2u, offset);
    EXPECT_EQ(0, std::memcmp(&query, &copy, sizeof query));
    std::memset(&copy, 0xFF, sizeof copy);
    EXPECT_EQ(0u, tlv_query_count(&copy));
    EXPECT_EQ(0u, tlv_query_step(&copy, 0).size);
    EXPECT_EQ(648u, sizeof(tlv_query_t));
    EXPECT_EQ(16u, sizeof(tlv_query_matcher_t));
}
