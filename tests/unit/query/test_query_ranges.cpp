// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "controlled_format.h"
#include "tlv++/query/query.hpp"
#include "tlv++/query/program.hpp"
#include "tlv++/query/builder.hpp"
#include "tlv/schema/query.h"
#include "tlv/config.h"
#if OPENTLV_DOCUMENT
#include "tlv++/document/document.hpp"
#include "tlv++/document/diff.hpp"
#endif
#include <gtest/gtest.h>
#include <vector>
#include <cstdlib>

namespace {
int constructed(const void*, const tlv_tag_t* tag) {
    return tag->size == 1 && (tag->data[0] == 0x6F || tag->data[0] == 0xA5);
}
tlv_format_t make_format() {
    auto result = controlled::format;
    result.is_constructed = constructed;
    return result;
}
const tlv_format_t format = make_format();
// A dead-end root followed by two matching branches and an unrelated root.
const uint8_t input[] = {0x6F, 2, 0x84, 0, 0x6F, 8, 0xA5, 6, 0x50, 1, 1, 0x50, 1, 2, 0x50, 1, 9};
tlv::bytes    bytes(const uint8_t* data, size_t size) {
    return {reinterpret_cast<const tlv::byte*>(data), size};
}
} // namespace

TEST(Unit_Tlvpp_FullQuery, TypedBuilderAndResumablePull) {
    auto expression =
        tlv::where(tlv::query_nodes("//50"), tlv::query_integer("@len") > tlv::integer(0));
    auto program = expression.compile();
    ASSERT_TRUE(program);
    auto execution = tlv::query_execution::create(*program, 3, 100, 100000);
    ASSERT_TRUE(execution);
    tlv::tree_frame  frames[3]{};
    tlv::tree_reader reader(bytes(input, sizeof input), format, {frames, 3}, 3, 100);
    size_t           matches = 0;
    for (;;) {
        auto node = execution->next(reader);
        if (!node) {
            EXPECT_EQ(TLV_ERR_END_OF_BUFFER, node.error().code);
            break;
        }
        ++matches;
    }
    EXPECT_EQ(3u, matches);
    auto scalar = (tlv::count(tlv::query_nodes("//50")) > tlv::integer(2)).compile();
    ASSERT_TRUE(scalar);
    EXPECT_EQ(TLV_QUERY_RESULT_BOOL, scalar->info().result_kind);
    auto wrong = tlv::query_integer("//50").compile();
    ASSERT_FALSE(wrong);
    EXPECT_EQ(TLV_ERR_INVALID_ARG, wrong.error().code);
}

TEST(Unit_Tlvpp_QueryRanges, OrderedMatchesAndOwnedQuery) {
    tlv::tree_frame     frames[3]{};
    tlv::tree_reader    reader(bytes(input, sizeof(input)), format, {frames, 3}, 3, 100);
    auto                selected = reader.select("6F/A5/50");
    auto                moved = std::move(selected);
    std::vector<size_t> offsets;
    for (const auto& item : moved) {
        offsets.push_back(item.offset);
        EXPECT_EQ(2u, item.depth);
        EXPECT_EQ(tlv::tag_bytes<0x50>(), item.element.tag());
    }
    EXPECT_EQ((std::vector<size_t>{8, 11}), offsets);
}

TEST(Unit_Tlvpp_FullQuery, ScalarsVariablesAndStopResume) {
    tlv_query_variable_t        variable{"minimum", TLV_QUERY_RESULT_INTEGER};
    tlv_query_compile_options_t options;
    tlv_query_compile_options_init(&options);
    options.variables = &variable;
    options.variable_count = 1;
    auto query = tlv::query_program::compile("count(//50[@len >= $minimum])", &options);
    ASSERT_TRUE(query);
    auto execution = tlv::query_execution::create(*query, 3, 100, 100000);
    ASSERT_TRUE(execution);
    ASSERT_TRUE(execution->bind("minimum", int64_t(1)));
    tlv::tree_frame  frames[4]{};
    tlv::tree_reader reader(bytes(input, sizeof input), format, {frames, 4}, 3, 100);
    auto             visited =
        execution->visit(reader, [](const tlv::tree_event&) { return TLV_VISIT_CONTINUE; });
    ASSERT_TRUE(visited);
    auto result = execution->result();
    ASSERT_TRUE(result);
    EXPECT_EQ(TLV_QUERY_RESULT_INTEGER, result->kind);
    EXPECT_EQ(3, result->integer);
    auto selector = tlv::query_program::compile("//50");
    ASSERT_TRUE(selector);
    auto selected = tlv::query_execution::create(*selector, 3, 100, 100000);
    ASSERT_TRUE(selected);
    tlv::tree_reader second(bytes(input, sizeof input), format, {frames, 4}, 3, 100);
    size_t           calls = 0;
    auto             stop = [&](const tlv::tree_event&) {
        ++calls;
        return TLV_VISIT_STOP;
    };
    ASSERT_TRUE(selected->visit(second, stop));
    EXPECT_EQ(1u, calls);
    ASSERT_TRUE(selected->visit(second, stop));
    EXPECT_EQ(2u, calls);
    ASSERT_TRUE(selected->visit(second, stop));
    EXPECT_EQ(3u, calls);
    ASSERT_TRUE(selected->visit(second, stop));
    EXPECT_EQ(3u, calls);
}

TEST(Unit_Tlvpp_FullQuery, EmbeddedNulPreservesNativeSpan) {
    auto query = tlv::query_program::compile(std::string("//50\0", 5));
    ASSERT_FALSE(query);
    EXPECT_EQ(TLV_QUERY_ERROR_SYNTAX, query.error().diagnostic.kind);
    EXPECT_EQ(4u, query.error().diagnostic.begin);
}

TEST(Unit_Tlvpp_FullQuery, CallerStorageAndRepeatedNeedMoreData) {
    alignas(16) unsigned char scratch[4096], program_storage[4096], workspace[16384];
    const char                text[] = "//50";
    auto                      query =
        tlv::query_program::compile_into(text, sizeof text - 1, nullptr, scratch, sizeof scratch,
                                         program_storage, sizeof program_storage);
    ASSERT_TRUE(query);
    auto execution = tlv::query_execution::external(*query, workspace, sizeof workspace, 3, 100,
                                                    100000, nullptr, false);
    ASSERT_TRUE(execution);
    tlv::tree_frame  frames[4]{};
    tlv::tree_reader reader(bytes(input, 10), format, {frames, 4}, 3, 100,
                            tlv::input_mode::incremental);
    size_t           calls = 0;
    auto             visitor = [&](const tlv::tree_event&) {
        ++calls;
        return TLV_VISIT_CONTINUE;
    };
    auto first = execution->visit(reader, visitor);
    ASSERT_FALSE(first);
    EXPECT_EQ(TLV_NEED_MORE_DATA, first.error().code);
    auto second = execution->visit(reader, visitor);
    ASSERT_FALSE(second);
    EXPECT_EQ(TLV_NEED_MORE_DATA, second.error().code);
    ASSERT_TRUE(reader.set_input(bytes(input, sizeof input), 0, tlv::input_mode::final));
    auto moved = std::move(*execution);
    ASSERT_TRUE(moved.visit(reader, visitor));
    EXPECT_EQ(3u, calls);
    EXPECT_FALSE(execution->visit(reader, visitor));
}

TEST(Unit_Tlvpp_FullQuery, ContextualSchemaAssertionsPreserveReaderFailures) {
    auto contexts = tlv::query_program::compile("//6F");
    ASSERT_TRUE(contexts);
    auto condition = tlv::query_program::compile("not(exists(.//50)) or exists(.//84)");
    ASSERT_TRUE(condition);
    tlv_schema_query_rule_t rule{contexts->c_program(), condition->c_program(), nullptr,
                                 "label-requires-name"};
    size_t                  a, b, alignment;
    ASSERT_EQ(TLV_OK, tlv_schema_query_size(&rule, 1, 3, 100, &a, &b, &alignment));
    tlv::detail::query_memory     selector(a), assertion(b);
    tlv_schema_query_context_t    selected[4]{};
    tlv_tree_frame_t              frames[4]{};
    tlv_schema_query_workspace_t  workspace{selector.data(), a, assertion.data(), b,
                                            selected,        4, frames,           4};
    tlv_schema_query_diagnostic_t diagnostic{};
    EXPECT_EQ(TLV_ERR_SCHEMA,
              tlv_schema_query_validate_buffer(input, sizeof input, &format, &rule, 1, 3, 100,
                                               100000, &workspace, &diagnostic));
    EXPECT_EQ(0u, diagnostic.rule);
    EXPECT_STREQ("label-requires-name", diagnostic.schema.field);
    EXPECT_EQ(4u, diagnostic.schema.diagnostic.offset);
    EXPECT_EQ(TLV_OK, tlv_schema_query_validate_buffer(input, 4, &format, &rule, 1, 3, 100, 100000,
                                                       &workspace, &diagnostic));
    std::vector<uint8_t> malformed(input, input + sizeof input);
    malformed.push_back(0x50);
    malformed.push_back(10);
    EXPECT_NE(TLV_ERR_SCHEMA,
              tlv_schema_query_validate_buffer(malformed.data(), malformed.size(), &format, &rule,
                                               1, 3, 100, 100000, &workspace, &diagnostic));
    EXPECT_EQ(TLV_QUERY_ERROR_READER, diagnostic.query.kind);
    EXPECT_EQ(TLV_OK, tlv_schema_query_validate_buffer(nullptr, 0, nullptr, nullptr, 0, 0, 0, 0,
                                                       nullptr, nullptr));
    workspace.context_capacity = 1;
    EXPECT_EQ(TLV_ERR_LIMIT,
              tlv_schema_query_validate_buffer(input, sizeof input, &format, &rule, 1, 3, 100,
                                               100000, &workspace, &diagnostic));
    EXPECT_STREQ("schema-contexts", diagnostic.query.limit);
    auto nested = tlv::query_program::compile("//A5");
    ASSERT_TRUE(nested);
    rule.context = nested->c_program();
    EXPECT_EQ(TLV_ERR_SCHEMA,
              tlv_schema_query_validate_buffer(input, sizeof input, &format, &rule, 1, 3, 100,
                                               100000, &workspace, &diagnostic));
    ASSERT_EQ(1u, diagnostic.schema.path.length);
    EXPECT_EQ(0x6F, diagnostic.schema.path.tags[0].data[0]);
    EXPECT_STREQ("assertion", tlv_schema_issue_kind_string(diagnostic.schema.kind));
}

#if OPENTLV_DOCUMENT
TEST(Unit_Tlvpp_FullQuery, DocumentSnapshotsAndCompletedRemove) {
    auto doc = tlv::document::parse(bytes(input, sizeof input), tlv::document_format(format));
    ASSERT_TRUE(doc);
    auto query = tlv::query_program::compile("//50");
    ASSERT_TRUE(query);
    auto snapshot = doc->select(*query);
    ASSERT_TRUE(snapshot);
    ASSERT_EQ(3u, snapshot->size());
    auto removed = doc->query_remove(*query);
    ASSERT_TRUE(removed);
    EXPECT_EQ(3u, *removed);
    for (const auto& handle : *snapshot) EXPECT_FALSE(handle);
    auto roots = tlv::query_program::compile("//6F | //50");
    ASSERT_TRUE(roots);
    auto removed_roots = doc->query_remove(*roots);
    ASSERT_TRUE(removed_roots);
    EXPECT_EQ(2u, *removed_roots);
    EXPECT_TRUE(doc->empty());
}

TEST(Unit_Tlvpp_FullQuery, NativeRevisionAndCallbackGuard) {
    auto doc = tlv::document::parse(bytes(input, sizeof input), tlv::document_format(format));
    ASSERT_TRUE(doc);
    auto query = tlv::query_program::compile("//50");
    ASSERT_TRUE(query);
    auto execution = tlv::query_execution::create(*query, 3, 100, 100000);
    ASSERT_TRUE(execution);
    ASSERT_TRUE(doc->evaluate(*execution, nullptr, 0, nullptr));
    auto revision = tlv_document_revision(doc->c_document());
    auto callback = [](tlv_node_t* node, void*) {
        tlv_node_erase(node);
        EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_node_set_value(node, nullptr, 0));
        return TLV_VISIT_STOP;
    };
    EXPECT_EQ(TLV_OK, tlv_document_query_program_visit(execution->c_exec(), callback, nullptr));
    EXPECT_EQ(revision, tlv_document_revision(doc->c_document()));
    doc->first().erase();
    EXPECT_FALSE(doc->next(*execution));
}

TEST(Unit_Tlvpp_FullQuery, NativeEditsInvalidateCheckedHandlesAndKeepUnaffectedNodes) {
    auto doc = tlv::document::parse(bytes(input, sizeof input), tlv::document_format(format));
    ASSERT_TRUE(doc);
    auto root = doc->first();
    auto untouched = root.next();
    auto raw = root.c_node();
    auto identity = tlv_document_node_identity(doc->c_document(), raw);
    tlv_node_erase(raw);
    EXPECT_FALSE(root);
    EXPECT_TRUE(untouched);
    EXPECT_EQ(0u, tlv_document_node_identity(doc->c_document(), raw));
    auto replacement = doc->insert(tlv::tag_bytes<0x6F>(), bytes(nullptr, 0));
    ASSERT_TRUE(replacement);
    EXPECT_NE(identity, tlv_document_node_identity(doc->c_document(), replacement->c_node()));
    EXPECT_FALSE(root);
}

TEST(Unit_Tlvpp_FullQuery, ReplaceAndInsertUseInitialSelectionAndCopyAliasedValue) {
    auto doc = tlv::document::parse(bytes(input, sizeof input), tlv::document_format(format));
    ASSERT_TRUE(doc);
    auto query = tlv::query_program::compile("//50");
    ASSERT_TRUE(query);
    auto before = doc->select(*query);
    ASSERT_TRUE(before);
    ASSERT_EQ(3u, before->size());
    auto value = before->front().value().as_bytes();
    auto replace = doc->query_replace(*query, value);
    ASSERT_TRUE(replace);
    EXPECT_EQ(3u, *replace);
    for (const auto& node : *before) {
        EXPECT_TRUE(node);
        EXPECT_EQ(1, static_cast<int>(node.value().as_bytes()[0]));
    }
    auto inserted =
        doc->query_insert_after(*query, tlv::tag_bytes<0x50>(), before->front().value().as_bytes());
    ASSERT_TRUE(inserted);
    EXPECT_EQ(3u, *inserted);
    auto after = doc->select(*query);
    ASSERT_TRUE(after);
    EXPECT_EQ(6u, after->size());
    for (const auto& node : *before) EXPECT_TRUE(node);
}

TEST(Unit_Tlvpp_FullQuery, NativeEditCapacityAndAncestorDominance) {
    auto doc = tlv::document::parse(bytes(input, sizeof input), tlv::document_format(format));
    ASSERT_TRUE(doc);
    auto query = tlv::query_program::compile("//6F | //50");
    ASSERT_TRUE(query);
    auto execution = tlv::query_execution::create(*query, 3, 100, 100000);
    ASSERT_TRUE(execution);
    ASSERT_TRUE(doc->evaluate(*execution, nullptr, 0, nullptr));
    size_t      applied = 99;
    tlv_node_t* targets[5]{};
    auto        original = tlv_document_revision(doc->c_document());
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
              tlv_document_query_edit(doc->c_document(), execution->c_exec(),
                                      TLV_DOCUMENT_QUERY_REMOVE, tlv_tag(nullptr, 0), nullptr, 0,
                                      targets, 1, &applied));
    EXPECT_EQ(0u, applied);
    EXPECT_EQ(original, tlv_document_revision(doc->c_document()));
    auto second = tlv::query_execution::create(*query, 3, 100, 100000);
    ASSERT_TRUE(second);
    ASSERT_TRUE(doc->evaluate(*second, nullptr, 0, nullptr));
    EXPECT_EQ(TLV_OK, tlv_document_query_edit(doc->c_document(), second->c_exec(),
                                              TLV_DOCUMENT_QUERY_REMOVE, tlv_tag(nullptr, 0),
                                              nullptr, 0, targets, 5, &applied));
    EXPECT_EQ(3u, applied);
    EXPECT_TRUE(doc->empty());
}

TEST(Unit_Tlvpp_FullQuery, DiffUsesOriginalPositionsAndExcludesUnselectedDescendants) {
    auto left = tlv::document::parse(bytes(input, sizeof input), tlv::document_format(format));
    ASSERT_TRUE(left);
    auto right = tlv::document::parse(bytes(input, sizeof input), tlv::document_format(format));
    ASSERT_TRUE(right);
    auto selector = tlv::query_program::compile("//50[2]");
    ASSERT_TRUE(selector);
    auto selected = right->select(*selector);
    ASSERT_TRUE(selected);
    ASSERT_EQ(1u, selected->size());
    const uint8_t changed[] = {3};
    ASSERT_TRUE(selected->front().set(bytes(changed, 1)));
    auto diff = tlv::semantic_diff(*left, *right, &*selector);
    ASSERT_TRUE(diff);
    ASSERT_EQ(1u, diff->size());
    EXPECT_EQ(tlv::diff_kind::changed, diff->front().kind);
    EXPECT_EQ("/6F[2]/A5[1]/50[2]", diff->front().path);
    auto ancestors = tlv::query_program::compile("//6F");
    ASSERT_TRUE(ancestors);
    auto ancestor_diff = tlv::semantic_diff(*left, *right, &*ancestors);
    ASSERT_TRUE(ancestor_diff);
    EXPECT_TRUE(ancestor_diff->empty());
    auto first = tlv::query_program::compile("(//50)[1]");
    ASSERT_TRUE(first);
    auto unselected = tlv::semantic_diff(*left, *right, &*first);
    ASSERT_TRUE(unselected);
    EXPECT_TRUE(unselected->empty());
    const uint8_t prefix[] = {0};
    ASSERT_TRUE(
        right->insert(tlv::tag_bytes<0x51>(), bytes(prefix, 1), tlv::node(), right->first()));
    auto moved = tlv::semantic_diff(*left, *right, &*selector);
    ASSERT_TRUE(moved);
    EXPECT_EQ(1u, moved->size());
    selected->front().erase();
    auto missing = tlv::semantic_diff(*left, *right, &*selector);
    ASSERT_TRUE(missing);
    ASSERT_EQ(1u, missing->size());
    EXPECT_EQ(tlv::diff_kind::removed, missing->front().kind);
}

TEST(Unit_Tlvpp_FullQuery, InvalidConstructedReplacementReportsPartialProgress) {
    const uint8_t fixture[] = {0x50, 1, 9, 0x6F, 0};
    auto doc = tlv::document::parse(bytes(fixture, sizeof fixture), tlv::document_format(format));
    ASSERT_TRUE(doc);
    auto all = tlv::query_program::compile("//50 | //6F");
    ASSERT_TRUE(all);
    const uint8_t replacement[] = {0x50, 3};
    size_t        applied = 99;
    auto changed = doc->query_replace(*all, bytes(replacement, sizeof replacement), &applied);
    EXPECT_FALSE(changed);
    EXPECT_EQ(1u, applied);
    EXPECT_EQ(2u, doc->size());
    EXPECT_EQ(2u, doc->first().value().size());
    EXPECT_TRUE(doc->first().next());
    EXPECT_FALSE(doc->first().next().first_child());
    ASSERT_TRUE(doc->encode());
}

TEST(Unit_Tlvpp_FullQuery, DocumentExecutionDetectsDestructionBeforeResultAccess) {
    auto selector = tlv::query_program::compile("count(//50)");
    ASSERT_TRUE(selector);
    auto execution = tlv::query_execution::create(*selector, 3, 100, 100000);
    ASSERT_TRUE(execution);
    {
        auto doc = tlv::document::parse(bytes(input, sizeof input), tlv::document_format(format));
        ASSERT_TRUE(doc);
        ASSERT_TRUE(doc->evaluate(*execution, nullptr, 0, nullptr));
        ASSERT_TRUE(execution->result());
    }
    auto result = execution->result();
    ASSERT_FALSE(result);
    EXPECT_EQ(TLV_ERR_INVALID_ARG, result.error().code);
}

TEST(Unit_Tlvpp_FullQuery, DocumentSchemaRunsTheSameContextualPrograms) {
    auto doc = tlv::document::parse(bytes(input, sizeof input), tlv::document_format(format));
    ASSERT_TRUE(doc);
    auto contexts = tlv::query_program::compile("//6F");
    ASSERT_TRUE(contexts);
    auto condition = tlv::query_program::compile("not(exists(.//50)) or exists(.//84)");
    ASSERT_TRUE(condition);
    tlv_schema_query_rule_t rule{contexts->c_program(), condition->c_program(), nullptr, "name"};
    size_t                  a, b, alignment;
    ASSERT_EQ(TLV_OK, tlv_schema_query_size(&rule, 1, 3, 100, &a, &b, &alignment));
    tlv::detail::query_memory     selector(a), assertion(b);
    tlv_schema_query_context_t    selected[4]{};
    tlv_schema_query_workspace_t  w{selector.data(), a, assertion.data(), b,
                                    selected,        4, nullptr,          0};
    tlv_schema_query_diagnostic_t diagnostic{};
    EXPECT_EQ(TLV_ERR_SCHEMA,
              tlv_schema_query_validate_document(doc->c_document(), &rule, 1, 3, 100, 100000, &w,
                                                 nullptr, 0, nullptr, &diagnostic));
    EXPECT_EQ(TLV_SCHEMA_ISSUE_ASSERTION, diagnostic.schema.kind);
    EXPECT_STREQ("name", diagnostic.schema.field);
}

TEST(Unit_Tlvpp_FullQuery, DocumentEnvironmentAcceptsCopiedDescriptorAndRejectsForeignPolicy) {
    auto doc = tlv::document::parse(bytes(input, sizeof input), tlv::document_format(format));
    ASSERT_TRUE(doc);
    tlv_query_environment_t environment{};
    environment.format = &format;
    auto query = tlv::query_program::compile("//50");
    ASSERT_TRUE(query);
    auto results = doc->select(*query, &environment);
    ASSERT_TRUE(results);
    EXPECT_EQ(3u, results->size());
    auto foreign = format;
    foreign.is_constructed = nullptr;
    environment.format = &foreign;
    auto rejected = doc->select(*query, &environment);
    ASSERT_FALSE(rejected);
    EXPECT_EQ(TLV_ERR_INVALID_ARG, rejected.error().code);
}

TEST(Unit_Tlvpp_FullQuery, AllocatorFailurePreservesUneditedTargetsAndReportsPartialCount) {
    struct allocator_state {
        int          remaining = -1;
        static void* allocate(void* context, size_t size) {
            auto& state = *static_cast<allocator_state*>(context);
            if (!state.remaining) return nullptr;
            if (state.remaining > 0) --state.remaining;
            return std::malloc(size);
        }
        static void release(void*, void* pointer) {
            std::free(pointer);
        }
    } state;
    tlv_allocator_t        allocator{&state, allocator_state::allocate, allocator_state::release};
    tlv_document_options_t options;
    ASSERT_EQ(TLV_OK, tlv_document_options_init(&options, &format));
    options.allocator = &allocator;
    tlv_document_t* raw = nullptr;
    ASSERT_EQ(TLV_OK, tlv_document_parse(input, sizeof input, &options, &raw, nullptr));
    auto query = tlv::query_program::compile("//50");
    ASSERT_TRUE(query);
    auto execution = tlv::query_execution::create(*query, 3, 100, 100000);
    ASSERT_TRUE(execution);
    ASSERT_EQ(TLV_OK, tlv_document_query_evaluate(raw, execution->c_exec(), nullptr, nullptr, 0,
                                                  nullptr, nullptr));
    tlv_node_t*   targets[3]{};
    const uint8_t replacement[] = {7};
    size_t        applied;
    state.remaining = 2; // Copy the shared replacement, then replace the first target.
    EXPECT_EQ(TLV_ERR_OUT_OF_MEMORY,
              tlv_document_query_edit(raw, execution->c_exec(), TLV_DOCUMENT_QUERY_REPLACE,
                                      tlv_tag(nullptr, 0), replacement, 1, targets, 3, &applied));
    EXPECT_EQ(1u, applied);
    EXPECT_EQ(7, tlv_node_value_data(targets[0])[0]);
    EXPECT_EQ(2, tlv_node_value_data(targets[1])[0]);
    EXPECT_EQ(9, tlv_node_value_data(targets[2])[0]);
    tlv_document_free(raw);
}
#endif

TEST(Unit_Tlvpp_QueryRanges, EmptyAndCompilationErrors) {
    tlv::tree_frame  frames[3]{};
    tlv::tree_reader reader(bytes(input, sizeof(input)), format, {frames, 3}, 3, 100);
    auto             selected = reader.select("6F/A5/51");
    EXPECT_EQ(selected.end(), selected.begin());
    try {
        reader.select("6F//50");
        FAIL();
    } catch (const tlv::query_error& error) {
        EXPECT_EQ(TLV_ERR_INVALID_ARG, error.code());
        EXPECT_EQ(3u, error.offset());
    }
    size_t offset = 0;
    EXPECT_FALSE(tlv::query::parse("6F//50", &offset));
    EXPECT_EQ(3u, offset);
}

TEST(Unit_Tlvpp_QueryRanges, MalformedTailIsNotEnd) {
    const uint8_t    broken[] = {0x50, 0, 0x51, 2};
    tlv::tree_frame  frames[1]{};
    tlv::tree_reader reader(bytes(broken, sizeof(broken)), format, {frames, 1}, 1, 10);
    auto             selected = reader.select("50");
    auto             it = selected.begin();
    ASSERT_NE(it, selected.end());
    try {
        ++it;
        FAIL();
    } catch (const tlv::parse_error& error) {
        EXPECT_NE(TLV_ERR_END_OF_BUFFER, error.code());
        EXPECT_EQ(2u, error.offset());
    }
}

TEST(Unit_Tlvpp_QueryRanges, IncrementalResumeAndIteratorCopies) {
    const uint8_t    flat[] = {0x50, 1, 1, 0x50, 1, 2};
    tlv::tree_frame  frames[1]{};
    tlv::tree_reader reader(bytes(flat, 3), format, {frames, 1}, 1, 10,
                            tlv::input_mode::incremental);
    auto             selected = reader.select("50");
    auto             it = selected.begin();
    auto             copy = it;
    EXPECT_EQ(0u, it->offset);
    EXPECT_THROW(++it, tlv::parse_error);
    EXPECT_EQ(copy, selected.end());
    ASSERT_TRUE(reader.set_input(bytes(flat, sizeof(flat)), 0, tlv::input_mode::final));
    auto next = selected.next();
    ASSERT_TRUE(next);
    EXPECT_EQ(3u, next->offset);
    auto end = selected.next();
    ASSERT_FALSE(end);
    EXPECT_EQ(TLV_ERR_END_OF_BUFFER, end.error().code);
}

TEST(Unit_Tlvpp_QueryRanges, LimitsApplyToUnmatchedItems) {
    tlv::tree_frame  frames[3]{};
    tlv::tree_reader reader(bytes(input, sizeof(input)), format, {frames, 3}, 3, 1);
    auto             selected = reader.select("51");
    auto             result = selected.next();
    ASSERT_FALSE(result);
    EXPECT_EQ(TLV_ERR_LIMIT, result.error().code);
}

#if OPENTLV_DOCUMENT
TEST(Unit_Tlvpp_QueryRanges, DocumentSnapshotHandlesSurviveMoveAndInvalidateSafely) {
    auto parsed = tlv::document::parse(bytes(input, sizeof(input)), tlv::document_format(format));
    ASSERT_TRUE(parsed);
    auto selected = parsed->select("6F/A5/50");
    ASSERT_EQ(2u, selected.size());
    EXPECT_EQ(1u, static_cast<unsigned>(selected[0].value()[0]));
    EXPECT_EQ(2u, static_cast<unsigned>(selected[1].value()[0]));
    EXPECT_TRUE(parsed->select("6F/A5/51").empty());
    auto moved = std::move(*parsed);
    EXPECT_TRUE(selected[0]);
    selected[0].erase();
    EXPECT_FALSE(selected[0]);
    EXPECT_TRUE(selected[1]);
    EXPECT_EQ(1u, moved.select(tlv::query::compile("6F/A5/50")).size());
    EXPECT_THROW(moved.select("6F/"), tlv::query_error);
}

TEST(Unit_Tlvpp_QueryRanges, DocumentDestructionInvalidatesResults) {
    std::vector<tlv::node> selected;
    {
        auto parsed =
            tlv::document::parse(bytes(input, sizeof(input)), tlv::document_format(format));
        ASSERT_TRUE(parsed);
        selected = parsed->select("6F/A5/50");
    }
    ASSERT_EQ(2u, selected.size());
    EXPECT_FALSE(selected[0]);
    EXPECT_FALSE(selected[1]);
}

TEST(Unit_Tlvpp_QueryRanges, DocumentSnapshotExcludesInsertionAndInvalidatesReplacedChildren) {
    auto parsed = tlv::document::parse(bytes(input, sizeof(input)), tlv::document_format(format));
    ASSERT_TRUE(parsed);
    auto selected = parsed->select("6F/A5/50");
    auto parent = parsed->find(tlv::query::compile("6F/A5"));
    ASSERT_TRUE(parent);
    ASSERT_TRUE(parent.insert(tlv::tag_bytes<0x50>(), tlv::bytes()));
    EXPECT_EQ(2u, selected.size());
    EXPECT_EQ(3u, parsed->select("6F/A5/50").size());
    const uint8_t replacement[] = {0x50, 0};
    ASSERT_TRUE(parent.set(bytes(replacement, sizeof(replacement))));
    EXPECT_FALSE(selected[0]);
    EXPECT_FALSE(selected[1]);
    EXPECT_TRUE(parent);
    EXPECT_EQ(1u, parsed->select("6F/A5/50").size());
}
#endif
