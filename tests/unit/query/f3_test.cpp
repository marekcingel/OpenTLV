// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#include "../../diagnostic_assertions.h"
#include "tlv/query/adapters.h"
#include "tlv/document/document.h"
#include "tlv/writer/tree.h"
#include "tlv/builtins/emv/query.h"
#include "tlv/builtins/asn1/query.h"
#include "tlv/builtins/asn1/ber.h"
#include "tlv/builtins/asn1/cer.h"
#include "tlv/config.h"
#include "controlled_format.h"
#include <gtest/gtest.h>
#include <cstring>
#include <cstdlib>
#include <memory>
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

TEST(Unit_Tlv_QueryF3, WholePlanRequirementsAndDocumentRejection) {
    for (const auto& c : std::vector<std::pair<const char*, tlv_query_level_t>>{
             {"//50[preceding-sibling::5A]", TLV_QUERY_S0},
             {"70[not(5A)]", TLV_QUERY_S1},
             {"70[count(descendant::5A)>1]", TLV_QUERY_S1},
             {"//70[not(5A)] | //50", TLV_QUERY_S2},
             {"//70/5A[last()]", TLV_QUERY_S2},
             {"//5A/..", TLV_QUERY_S2},
             {"//5A/following::50", TLV_QUERY_D}}) {
        Evaluation e;
        ASSERT_EQ(e.compile(c.first), TLV_OK) << c.first;
        EXPECT_EQ(e.info.level, c.second) << c.first;
        EXPECT_EQ(e.info.stable_input_required, c.second != TLV_QUERY_S0);
        if (c.second >= TLV_QUERY_S2) {
            EXPECT_GT(e.info.candidate_size, 0u);
            EXPECT_EQ(e.info.decision_timing, TLV_QUERY_DECISION_EOF);
        }
    }
    Evaluation e;
    ASSERT_EQ(e.compile("//5A/following::50"), TLV_OK);
    ASSERT_EQ(e.init(), TLV_OK);
    const uint8_t     wire[] = {0x5a, 0, 0x50, 0};
    tlv_tree_frame_t  frames[16];
    tlv_tree_reader_t reader;
    ASSERT_EQ(tlv_tree_reader_init(&reader, wire, sizeof wire, &e.format, frames, 16, 16, 100),
              TLV_OK);
    EXPECT_EQ(TLV_DIAGNOSTIC_RESULT(e.diagnostic, tlv_query_program_visit(&reader, e.exec, noop,
                                                                          nullptr, &e.diagnostic)),
              TLV_ERR_UNSUPPORTED_TYPE);
    EXPECT_EQ(e.diagnostic.kind, TLV_QUERY_ERROR_CAPABILITY);
    tlv_tree_event_t event{};
    ASSERT_EQ(tlv_tree_reader_next_event(&reader, &event), TLV_OK);
    EXPECT_EQ(event.offset, 0u);
}
TEST(Unit_Tlv_QueryF3, DocumentOnlyFeedFailureRequiresReset) {
    Evaluation e;
    ASSERT_EQ(e.compile("following::27"), TLV_OK);
    ASSERT_EQ(e.info.level, TLV_QUERY_D);
    ASSERT_EQ(e.init(), TLV_OK);
    const uint8_t    tag = 0x27;
    tlv_tree_event_t event{};
    event.kind = TLV_TREE_ELEMENT;
    event.element.tag = tlv_tag(&tag, 1);
    tlv_query_exec_info_t info{};
    info.struct_size = sizeof info;
    for (int attempt = 0; attempt < 2; ++attempt) {
        SCOPED_TRACE(attempt);
        int matched = 9;
        ASSERT_EQ(tlv_query_exec_info(e.exec, &info), TLV_OK);
        EXPECT_FALSE(info.invalid);
        EXPECT_EQ(TLV_DIAGNOSTIC_RESULT(
                      e.diagnostic, tlv_query_exec_feed(e.exec, &event, &matched, &e.diagnostic)),
                  TLV_ERR_UNSUPPORTED_TYPE);
        EXPECT_EQ(e.diagnostic.kind, TLV_QUERY_ERROR_CAPABILITY);
        EXPECT_EQ(matched, 9);
        ASSERT_EQ(tlv_query_exec_info(e.exec, &info), TLV_OK);
        EXPECT_TRUE(info.invalid);
        EXPECT_FALSE(info.finished);
        EXPECT_FALSE(info.full_validation);
        EXPECT_EQ(info.elements, 0u);
        EXPECT_EQ(tlv_query_exec_feed(e.exec, &event, &matched, nullptr), TLV_ERR_INVALID_ARG);
        EXPECT_EQ(matched, 9);
        EXPECT_EQ(TLV_DIAGNOSTIC_RESULT(e.diagnostic, tlv_query_exec_finish(e.exec, &e.diagnostic)),
                  TLV_ERR_INVALID_ARG);
        ASSERT_EQ(e.init(), TLV_OK);
    }
}
TEST(Unit_Tlv_QueryF3, S1ScopePublicationStopResumeAndMalformedSuffix) {
    Evaluation e;
    ASSERT_EQ(e.compile("70[not(5A)]"), TLV_OK);
    size_t size, alignment;
    ASSERT_EQ(tlv_query_exec_size(e.program, 16, &size, &alignment), TLV_OK);
    Buffer workspace(size, alignment);
    ASSERT_EQ(tlv_query_exec_init(e.program, workspace.data, size, 16, 100, 100000, &e.exec),
              TLV_OK);
    const std::vector<uint8_t> wire = {0x70, 2, 0x50, 0, 0x70, 0, 0x70, 2, 0x5a, 0};
    tlv_tree_frame_t           frames[16];
    tlv_tree_reader_t          reader;
    ASSERT_EQ(
        tlv_tree_reader_init(&reader, wire.data(), wire.size(), &e.format, frames, 16, 16, 100),
        TLV_OK);
    std::vector<size_t> selected;
    auto                stop = [](const tlv_tree_event_t* event, void* state) {
        EXPECT_EQ(event->kind, TLV_TREE_BEGIN);
        EXPECT_EQ(event->element.tag.data[0], 0x70);
        static_cast<std::vector<size_t>*>(state)->push_back(event->offset);
        return TLV_VISIT_STOP;
    };
    ASSERT_EQ(tlv_query_program_visit(&reader, e.exec, stop, &selected, &e.diagnostic), TLV_OK);
    EXPECT_EQ(selected, std::vector<size_t>({0}));
    ASSERT_EQ(tlv_query_program_visit(&reader, e.exec, noop, &selected, &e.diagnostic), TLV_OK);
    EXPECT_EQ(selected, std::vector<size_t>({0, 4}));
    tlv_query_exec_info_t info{};
    info.struct_size = sizeof info;
    ASSERT_EQ(tlv_query_exec_info(e.exec, &info), TLV_OK);
    EXPECT_TRUE(info.full_validation);
    ASSERT_EQ(tlv_query_exec_init(e.program, workspace.data, size, 16, 100, 100000, &e.exec),
              TLV_OK);
    const uint8_t malformed[] = {0x70, 0, 0x70, 1, 0x5a};
    ASSERT_EQ(
        tlv_tree_reader_init(&reader, malformed, sizeof malformed, &e.format, frames, 16, 16, 100),
        TLV_OK);
    selected.clear();
    EXPECT_NE(
        TLV_DIAGNOSTIC_RESULT(
            e.diagnostic, tlv_query_program_visit(&reader, e.exec, noop, &selected, &e.diagnostic)),
        TLV_OK);
    EXPECT_EQ(e.diagnostic.kind, TLV_QUERY_ERROR_READER);
    EXPECT_EQ(selected, std::vector<size_t>({0})); // previous callback remains observable
}
TEST(Unit_Tlv_QueryF3, S1RawFeedDecidesOnlyAtEndAndReportsOriginalNode) {
    Evaluation e;
    ASSERT_EQ(e.compile("70[count(5A)=1]"), TLV_OK);
    size_t size, alignment;
    ASSERT_EQ(tlv_query_exec_size(e.program, 3, &size, &alignment), TLV_OK);
    Buffer workspace(size, alignment);
    ASSERT_EQ(tlv_query_exec_init(e.program, workspace.data, size, 3, 100, 10000, &e.exec), TLV_OK);
    uint8_t          tags[] = {0x70, 0x5a};
    tlv_tree_event_t event{};
    event.kind = TLV_TREE_BEGIN;
    event.element.tag = tlv_tag(tags, 1);
    int matched = 77;
    ASSERT_EQ(tlv_query_exec_feed(e.exec, &event, &matched, &e.diagnostic), TLV_OK);
    EXPECT_FALSE(matched);
    event.kind = TLV_TREE_ELEMENT;
    event.depth = 1;
    event.element.tag = tlv_tag(tags + 1, 1);
    ASSERT_EQ(tlv_query_exec_feed(e.exec, &event, &matched, &e.diagnostic), TLV_OK);
    EXPECT_FALSE(matched);
    event = {};
    event.kind = TLV_TREE_END;
    ASSERT_EQ(tlv_query_exec_feed(e.exec, &event, &matched, &e.diagnostic), TLV_OK);
    EXPECT_TRUE(matched);
    tlv_tree_event_t selected{};
    ASSERT_EQ(tlv_query_exec_selected(e.exec, &selected), TLV_OK);
    EXPECT_EQ(selected.kind, TLV_TREE_BEGIN);
    EXPECT_EQ(selected.element.tag.data, tags);
    EXPECT_FALSE(selected.source.data);
    ASSERT_EQ(tlv_query_exec_finish(e.exec, &e.diagnostic), TLV_OK);
}
TEST(Unit_Tlv_QueryF3, CandidatesExactCapacityOverflowAndSourceLessIdentity) {
    Evaluation e;
    ASSERT_EQ(e.compile("//5A/.. | //70"), TLV_OK);
    ASSERT_EQ(e.init(3), TLV_OK);
    const std::vector<uint8_t> wire = {0x70, 4, 0x5a, 0, 0x5a, 0};
    std::vector<size_t>        selected;
    ASSERT_EQ(e.run(wire, &selected), TLV_OK);
    EXPECT_EQ(selected, std::vector<size_t>({0}));
    ASSERT_EQ(e.init(2), TLV_OK);
    selected.clear();
    EXPECT_EQ(e.run(wire, &selected), TLV_ERR_LIMIT);
    EXPECT_STREQ(e.diagnostic.limit, "candidates");
    EXPECT_EQ(e.diagnostic.configured, 2u);
    EXPECT_TRUE(selected.empty());
    EXPECT_EQ(TLV_DIAGNOSTIC_RESULT(e.diagnostic, tlv_query_exec_finish(e.exec, &e.diagnostic)),
              TLV_ERR_INVALID_ARG);
    ASSERT_EQ(e.compile("//5A[last()] | //5A"), TLV_OK);
    ASSERT_EQ(e.init(2), TLV_OK);
    uint8_t          tag = 0x5a;
    tlv_tree_event_t event{};
    event.kind = TLV_TREE_ELEMENT;
    event.element.tag = tlv_tag(&tag, 1);
    int matched;
    for (int i = 0; i < 2; ++i)
        ASSERT_EQ(tlv_query_exec_feed(e.exec, &event, &matched, &e.diagnostic), TLV_OK);
    ASSERT_EQ(tlv_query_exec_finish(e.exec, &e.diagnostic), TLV_OK);
    EXPECT_EQ(tlv_query_result_next(e.exec, &event), TLV_OK);
    EXPECT_EQ(tlv_query_result_next(e.exec, &event), TLV_OK);
    EXPECT_EQ(tlv_query_result_next(e.exec, &event), TLV_ERR_END_OF_BUFFER);
}
TEST(Unit_Tlv_QueryF3, NestedDeferredOrderAndReverseContexts) {
    struct Case {
        const char*         text;
        std::vector<size_t> expected;
    };
    for (const auto& c : std::vector<Case>{{"//70[not(5A)] | //50", {0, 2, 4}},
                                           {"//50/ancestor-or-self::70[1]", {2}},
                                           {"//50/.. | //50/ancestor::70", {0, 2}},
                                           {"//70/descendant-or-self::*[last()]", {4}}}) {
        Evaluation e;
        ASSERT_EQ(e.compile(c.text), TLV_OK);
        ASSERT_EQ(e.init(), TLV_OK);
        std::vector<size_t> selected;
        ASSERT_EQ(e.run({0x70, 4, 0x70, 2, 0x50, 0}, &selected), TLV_OK) << c.text;
        EXPECT_EQ(selected, c.expected) << c.text;
    }
}

TEST(Unit_Tlv_QueryF3, DeferredWindowsRetainStablePayloadAndResume) {
    Evaluation e;
    ASSERT_EQ(e.compile("70[not(5A)]"), TLV_OK);
    size_t size, alignment;
    ASSERT_EQ(tlv_query_exec_size(e.program, 16, &size, &alignment), TLV_OK);
    Buffer workspace(size, alignment);
    ASSERT_EQ(tlv_query_exec_init(e.program, workspace.data, size, 16, 100, 100000, &e.exec),
              TLV_OK);
    const uint8_t     first[] = {0x70, 2, 0x50, 0};
    const uint8_t     second[] = {0x70, 0};
    tlv_tree_frame_t  frames[16];
    tlv_tree_reader_t reader;
    ASSERT_EQ(tlv_tree_reader_init_incremental(&reader, first, sizeof first, &e.format, frames, 16,
                                               16, 100),
              TLV_OK);
    std::vector<size_t> selected;
    EXPECT_EQ(
        TLV_DIAGNOSTIC_RESULT(
            e.diagnostic, tlv_query_program_visit(&reader, e.exec, noop, &selected, &e.diagnostic)),
        TLV_NEED_MORE_DATA);
    EXPECT_EQ(selected, std::vector<size_t>({0}));
    EXPECT_EQ(
        TLV_DIAGNOSTIC_RESULT(
            e.diagnostic, tlv_query_program_visit(&reader, e.exec, noop, &selected, &e.diagnostic)),
        TLV_NEED_MORE_DATA);
    ASSERT_EQ(tlv_tree_reader_set_input(&reader, second, sizeof second, sizeof first, 1), TLV_OK);
    ASSERT_EQ(tlv_query_program_visit(&reader, e.exec, noop, &selected, &e.diagnostic), TLV_OK);
    EXPECT_EQ(selected, std::vector<size_t>({0, 4}));
    ASSERT_EQ(e.compile("//70[not(5A)] | //50"), TLV_OK);
    ASSERT_EQ(e.init(), TLV_OK);
    ASSERT_EQ(tlv_tree_reader_init_incremental(&reader, first, sizeof first, &e.format, frames, 16,
                                               16, 100),
              TLV_OK);
    selected.clear();
    EXPECT_EQ(
        TLV_DIAGNOSTIC_RESULT(
            e.diagnostic, tlv_query_program_visit(&reader, e.exec, noop, &selected, &e.diagnostic)),
        TLV_NEED_MORE_DATA);
    EXPECT_TRUE(selected.empty());
    ASSERT_EQ(tlv_tree_reader_set_input(&reader, second, sizeof second, sizeof first, 1), TLV_OK);
    ASSERT_EQ(tlv_query_program_visit(&reader, e.exec, noop, &selected, &e.diagnostic), TLV_OK);
    EXPECT_EQ(selected, std::vector<size_t>({0, 2, 4}));
}
TEST(Unit_Tlv_QueryF3, DeepAndWideInputsHaveIndependentResourceBounds) {
    Evaluation e;
    ASSERT_EQ(e.compile("//5A[last()]"), TLV_OK);
    std::vector<uint8_t> wide;
    for (size_t i = 0; i < 100; ++i) {
        wide.push_back(0x5a);
        wide.push_back(0);
    }
    ASSERT_EQ(e.init(100, 10000000), TLV_OK);
    std::vector<size_t> selected;
    ASSERT_EQ(e.run(wide, &selected), TLV_OK);
    EXPECT_EQ(selected, std::vector<size_t>({198}));
    ASSERT_EQ(e.init(99, 10000000), TLV_OK);
    EXPECT_EQ(e.run(wide), TLV_ERR_LIMIT);
    EXPECT_STREQ(e.diagnostic.limit, "candidates");
    std::vector<uint8_t> deep = {0x5a, 0};
    for (size_t i = 0; i < 17; ++i) {
        deep.insert(deep.begin(), static_cast<uint8_t>(deep.size()));
        deep.insert(deep.begin(), 0x70);
    }
    ASSERT_EQ(e.init(100, 10000000), TLV_OK);
    EXPECT_EQ(e.run(deep), TLV_ERR_LIMIT);
    // The Reader and Query share the configured depth bound; Reader may reject first.
    EXPECT_TRUE(e.diagnostic.kind == TLV_QUERY_ERROR_READER ||
                e.diagnostic.kind == TLV_QUERY_ERROR_LIMIT);
}
#if OPENTLV_DOCUMENT
TEST(Unit_Tlv_QueryF3, DocumentInitializationFailuresCarryDetail) {
    Evaluation e;
    ASSERT_EQ(TLV_OK, e.compile("//*"));
    ASSERT_EQ(TLV_OK, e.init());
    EXPECT_EQ(TLV_ERR_NULL_ARG,
              TLV_DIAGNOSTIC_RESULT(e.diagnostic,
                                    tlv_document_query_evaluate(nullptr, e.exec, nullptr, nullptr,
                                                                0, nullptr, &e.diagnostic)));
    tlv_document_options_t options;
    ASSERT_EQ(TLV_OK, tlv_document_options_init(&options, &e.format));
    const uint8_t   wire[] = {0x5a, 0};
    tlv_document_t* document = nullptr;
    ASSERT_EQ(TLV_OK, tlv_document_parse(wire, sizeof wire, &options, &document, nullptr));
    ASSERT_EQ(TLV_OK, tlv_document_query_evaluate(document, e.exec, nullptr, nullptr, 0, nullptr,
                                                  &e.diagnostic));
    EXPECT_EQ(TLV_ERR_INVALID_ARG,
              TLV_DIAGNOSTIC_RESULT(e.diagnostic,
                                    tlv_document_query_evaluate(document, e.exec, nullptr, nullptr,
                                                                0, nullptr, &e.diagnostic)));
    EXPECT_EQ(TLV_QUERY_ERROR_EVENTS, e.diagnostic.kind);
    tlv_format_t incompatible = e.format;
    incompatible.is_constructed = nullptr;
    e.environment.format = &incompatible;
    ASSERT_EQ(TLV_OK, e.init());
    EXPECT_EQ(TLV_ERR_INVALID_ARG,
              TLV_DIAGNOSTIC_RESULT(e.diagnostic,
                                    tlv_document_query_evaluate(document, e.exec, nullptr, nullptr,
                                                                0, nullptr, &e.diagnostic)));
    EXPECT_EQ(TLV_QUERY_ERROR_CAPABILITY, e.diagnostic.kind);
    tlv_document_free(document);
}

TEST(Unit_Tlv_QueryF3, DocumentAxesContextMutationValuesAndScalar) {
    Evaluation             e;
    tlv_document_options_t options;
    ASSERT_EQ(tlv_document_options_init(&options, &e.format), TLV_OK);
    const uint8_t               wire[] = {0x70, 4, 0x5a, 0, 0x50, 0, 0x50, 0};
    tlv_tree_writer_frame_t     writer_frames[16];
    uint8_t                     staged[64], scratch[64];
    tlv_tree_writer_workspace_t staging{};
    staging.frames = writer_frames;
    staging.frame_capacity = 16;
    staging.data = staged;
    staging.data_capacity = sizeof staged;
    staging.scratch = scratch;
    staging.scratch_capacity = sizeof scratch;
    tlv_document_t* document = nullptr;
    ASSERT_EQ(tlv_document_parse(wire, sizeof wire, &options, &document, nullptr), TLV_OK);
    auto root = tlv_document_first(document);
    auto child = tlv_node_first_child(root);
    ASSERT_EQ(e.compile("//5A/following::50"), TLV_OK);
    ASSERT_EQ(e.init(), TLV_OK);
    size_t bytes;
    ASSERT_EQ(tlv_document_query_value_size(document, &staging, &bytes), TLV_OK);
    EXPECT_EQ(bytes, sizeof wire);
    std::vector<uint8_t> values(bytes);
    ASSERT_EQ(tlv_document_query_evaluate(document, e.exec, nullptr, values.data(), bytes, &staging,
                                          &e.diagnostic),
              TLV_OK);
    tlv_node_t* found = nullptr;
    EXPECT_EQ(tlv_document_query_next(e.exec, &found), TLV_OK);
    EXPECT_EQ(found, tlv_node_next(child));
    EXPECT_EQ(tlv_document_query_next(e.exec, &found), TLV_OK);
    EXPECT_EQ(found, tlv_node_next(root));
    EXPECT_EQ(tlv_document_query_next(e.exec, &found), TLV_ERR_END_OF_BUFFER);
    uint8_t     tag = 0x5a;
    tlv_node_t* inserted;
    ASSERT_EQ(tlv_document_insert(document, root, child, tlv_tag(&tag, 1), nullptr, 0, &inserted),
              TLV_OK);
    tlv_node_erase(child);
    ASSERT_EQ(e.compile("../5A[1]"), TLV_OK);
    ASSERT_EQ(e.init(), TLV_OK);
    ASSERT_EQ(tlv_document_query_evaluate(document, e.exec, inserted, values.data(), values.size(),
                                          &staging, &e.diagnostic),
              TLV_OK);
    ASSERT_EQ(tlv_document_query_next(e.exec, &found), TLV_OK);
    EXPECT_EQ(found, inserted);
    ASSERT_EQ(e.compile("value(/70)"), TLV_OK);
    ASSERT_EQ(e.init(), TLV_OK);
    ASSERT_EQ(tlv_document_query_evaluate(document, e.exec, nullptr, values.data(), values.size(),
                                          &staging, &e.diagnostic),
              TLV_OK);
    ASSERT_EQ(tlv_query_exec_result(e.exec, &e.result), TLV_OK);
    EXPECT_EQ(e.result.size, 4u);
    EXPECT_EQ(std::vector<uint8_t>(e.result.data, e.result.data + e.result.size),
              std::vector<uint8_t>({0x5a, 0, 0x50, 0}));
    ASSERT_EQ(e.compile("count(//*)"), TLV_OK);
    ASSERT_EQ(e.init(), TLV_OK);
    ASSERT_EQ(tlv_document_query_evaluate(document, e.exec, nullptr, values.data(), values.size(),
                                          &staging, &e.diagnostic),
              TLV_OK);
    ASSERT_EQ(tlv_query_exec_result(e.exec, &e.result), TLV_OK);
    EXPECT_EQ(e.result.integer, 4);
    tlv_document_free(document);
}
TEST(Unit_Tlv_QueryF3, DocumentStopResumeSourceErrorsAndResourceLimits) {
    Evaluation             e;
    tlv_document_options_t options;
    ASSERT_EQ(tlv_document_options_init(&options, &e.format), TLV_OK);
    const uint8_t               wire[] = {0x70, 2, 0x5a, 0, 0x50, 0};
    tlv_tree_writer_frame_t     writer_frames[16];
    uint8_t                     staged[64], scratch[64];
    tlv_tree_writer_workspace_t staging{};
    staging.frames = writer_frames;
    staging.frame_capacity = 16;
    staging.data = staged;
    staging.data_capacity = sizeof staged;
    staging.scratch = scratch;
    staging.scratch_capacity = sizeof scratch;
    tlv_document_t* document = nullptr;
    ASSERT_EQ(tlv_document_parse(wire, sizeof wire, &options, &document, nullptr), TLV_OK);
    std::vector<uint8_t> values(2);
    ASSERT_EQ(e.compile("//*"), TLV_OK);
    ASSERT_EQ(e.init(), TLV_OK);
    ASSERT_EQ(tlv_document_query_evaluate(document, e.exec, nullptr, values.data(), values.size(),
                                          &staging, &e.diagnostic),
              TLV_OK);
    std::vector<tlv_node_t*> selected;
    auto                     stop = [](tlv_node_t* node, void* state) {
        static_cast<std::vector<tlv_node_t*>*>(state)->push_back(node);
        return TLV_VISIT_STOP;
    };
    ASSERT_EQ(tlv_document_query_program_visit(e.exec, stop, &selected), TLV_OK);
    ASSERT_EQ(tlv_document_query_program_visit(e.exec, stop, &selected), TLV_OK);
    ASSERT_EQ(tlv_document_query_program_visit(e.exec, stop, &selected), TLV_OK);
    ASSERT_EQ(tlv_document_query_program_visit(e.exec, stop, &selected), TLV_OK);
    EXPECT_EQ(selected.size(), 3u);
    ASSERT_EQ(e.compile("//5A[@offset=0]"), TLV_OK);
    ASSERT_EQ(e.init(), TLV_OK);
    EXPECT_EQ(TLV_DIAGNOSTIC_RESULT(e.diagnostic, tlv_document_query_evaluate(
                                                      document, e.exec, nullptr, values.data(),
                                                      values.size(), &staging, &e.diagnostic)),
              TLV_ERR_INVALID_VALUE);
    EXPECT_EQ(e.diagnostic.kind, TLV_QUERY_ERROR_SOURCE);
    EXPECT_FALSE(e.diagnostic.has_source_offset);
    ASSERT_EQ(e.compile("//*"), TLV_OK);
    ASSERT_EQ(e.init(), TLV_OK);
    ASSERT_EQ(e.compile("value(/70)"), TLV_OK);
    ASSERT_EQ(e.init(), TLV_OK);
    EXPECT_EQ(TLV_DIAGNOSTIC_RESULT(e.diagnostic,
                                    tlv_document_query_evaluate(document, e.exec, nullptr, nullptr,
                                                                0, &staging, &e.diagnostic)),
              TLV_ERR_LIMIT);
    EXPECT_STREQ(e.diagnostic.limit, "document-values");
    ASSERT_EQ(e.compile("//*"), TLV_OK);
    ASSERT_EQ(e.init(2), TLV_OK);
    EXPECT_EQ(TLV_DIAGNOSTIC_RESULT(e.diagnostic, tlv_document_query_evaluate(
                                                      document, e.exec, nullptr, values.data(),
                                                      values.size(), &staging, &e.diagnostic)),
              TLV_ERR_LIMIT);
    EXPECT_STREQ(e.diagnostic.limit, "candidates");
    ASSERT_EQ(e.init(4, 1), TLV_OK);
    EXPECT_EQ(TLV_DIAGNOSTIC_RESULT(e.diagnostic, tlv_document_query_evaluate(
                                                      document, e.exec, nullptr, values.data(),
                                                      values.size(), &staging, &e.diagnostic)),
              TLV_ERR_LIMIT);
    EXPECT_STREQ(e.diagnostic.limit, "work");
    tlv_document_free(document);
}

TEST(Unit_Tlv_QueryF3, RetainedDocumentLocationsMatchStreamingAndSupportDocumentAxes) {
    Evaluation             e;
    tlv_document_options_t options;
    ASSERT_EQ(tlv_document_options_init(&options, &e.format), TLV_OK);
    options.retain_source_locations = 1;
    const std::vector<uint8_t> wire = {0x70, 5, 0x50, 0, 0x57, 1, 9, 0x50, 0};
    auto                       input = wire;
    tlv_document_t*            raw = nullptr;
    ASSERT_EQ(tlv_document_parse(input.data(), input.size(), &options, &raw, nullptr), TLV_OK);
    std::unique_ptr<tlv_document_t, decltype(&tlv_document_free)> doc(raw, tlv_document_free);
    input.assign(input.size(), 0);
    for (const char* text : {"//*[@offset = 0 and @hlen = 2]", "//57[@offset = 4]",
                             "//50[@offset > 0 and @hlen = 2]", "//57/..[@offset = 0]"}) {
        SCOPED_TRACE(text);
        ASSERT_EQ(e.compile(text), TLV_OK);
        ASSERT_EQ(e.init(), TLV_OK);
        std::vector<size_t> retained;
        ASSERT_EQ(e.run(wire, &retained), TLV_OK);
        if (e.info.level <= TLV_QUERY_S1) {
            size_t bytes, alignment;
            ASSERT_EQ(tlv_query_exec_size(e.program, 16, &bytes, &alignment), TLV_OK);
            Buffer storage(bytes, alignment);
            ASSERT_EQ(tlv_query_exec_init(e.program, storage.data, bytes, 16, 64, 1000000, &e.exec),
                      TLV_OK);
            std::vector<size_t> streaming;
            tlv_tree_frame_t    frames[16];
            tlv_tree_reader_t   reader;
            ASSERT_EQ(tlv_tree_reader_init(&reader, wire.data(), wire.size(), &e.format, frames, 16,
                                           16, 64),
                      TLV_OK);
            ASSERT_EQ(tlv_query_program_visit(&reader, e.exec, noop, &streaming, &e.diagnostic),
                      TLV_OK);
            EXPECT_EQ(retained, streaming);
        }
        ASSERT_EQ(e.init(), TLV_OK);
        ASSERT_EQ(tlv_document_query_evaluate(doc.get(), e.exec, nullptr, nullptr, 0, nullptr,
                                              &e.diagnostic),
                  TLV_OK);
        std::vector<size_t> locations;
        tlv_node_t*         node;
        while (tlv_document_query_next(e.exec, &node) == TLV_OK) {
            auto location = tlv_node_source_location(node);
            EXPECT_TRUE(location.has_offset);
            locations.push_back(location.offset);
        }
        EXPECT_EQ(retained, locations);
    }
    for (const auto& c : std::vector<std::pair<const char*, std::vector<size_t>>>{
             {"//50[1]/following::*[@offset > 0 and @hlen = 2]", {4, 7}},
             {"//57/preceding::*[@offset = 2 and @hlen = 2]", {2}}}) {
        ASSERT_EQ(e.compile(c.first), TLV_OK);
        EXPECT_EQ(e.info.level, TLV_QUERY_D);
        ASSERT_EQ(e.init(), TLV_OK);
        ASSERT_EQ(tlv_document_query_evaluate(doc.get(), e.exec, nullptr, nullptr, 0, nullptr,
                                              &e.diagnostic),
                  TLV_OK);
        std::vector<size_t> locations;
        tlv_node_t*         node;
        while (tlv_document_query_next(e.exec, &node) == TLV_OK)
            locations.push_back(tlv_node_source_location(node).offset);
        EXPECT_EQ(c.second, locations);
    }
    // An edit invalidates the touched node's provenance, never substitutes offset zero.
    auto leaf = tlv_node_next(tlv_node_first_child(tlv_document_first(doc.get())));
    ASSERT_EQ(tlv_node_set_value(leaf, nullptr, 0), TLV_OK);
    ASSERT_EQ(e.compile("//50[1]/following::57[@offset > 0]"), TLV_OK);
    ASSERT_EQ(e.init(), TLV_OK);
    EXPECT_EQ(TLV_DIAGNOSTIC_RESULT(e.diagnostic,
                                    tlv_document_query_evaluate(doc.get(), e.exec, nullptr, nullptr,
                                                                0, nullptr, &e.diagnostic)),
              TLV_ERR_INVALID_VALUE);
    EXPECT_EQ(e.diagnostic.kind, TLV_QUERY_ERROR_SOURCE);
    EXPECT_FALSE(e.diagnostic.has_source_offset);
}

TEST(Unit_Tlv_QueryF3, DocumentLocationPreservesEmptyHeaderAndZeroOffset) {
    Evaluation e;
    e.format = {};
    e.format.decode = [](const void*, const uint8_t* data, size_t size, tlv_decoded_t* decoded,
                         tlv_format_error_t*) -> tlv_result_t {
        if (!size) return TLV_ERR_BUFFER_TOO_SHORT;
        *decoded = {};
        decoded->element.value = {data, 1};
        decoded->source.data = data;
        decoded->source.size = 1;
        decoded->source.header = {0, 0, 1};
        decoded->source.value = {0, 1, 1};
        decoded->source.trailer = {1, 0, 1};
        decoded->source.element = decoded->element;
        return TLV_OK;
    };
    tlv_document_options_t options;
    ASSERT_EQ(tlv_document_options_init(&options, &e.format), TLV_OK);
    options.retain_source_locations = 1;
    const uint8_t   wire = 7;
    tlv_document_t* raw = nullptr;
    ASSERT_EQ(tlv_document_parse(&wire, 1, &options, &raw, nullptr), TLV_OK);
    std::unique_ptr<tlv_document_t, decltype(&tlv_document_free)> doc(raw, tlv_document_free);
    auto location = tlv_node_source_location(tlv_document_first(raw));
    EXPECT_TRUE(location.has_offset);
    EXPECT_TRUE(location.has_header_size);
    EXPECT_EQ(0u, location.offset);
    EXPECT_EQ(0u, location.header_size);
    ASSERT_EQ(e.compile("//*[@offset=0 and @hlen=0]"), TLV_OK);
    ASSERT_EQ(e.init(), TLV_OK);
    ASSERT_EQ(tlv_document_query_evaluate(raw, e.exec, nullptr, nullptr, 0, nullptr, &e.diagnostic),
              TLV_OK);
    tlv_node_t* node = nullptr;
    EXPECT_EQ(tlv_document_query_next(e.exec, &node), TLV_OK);
    EXPECT_EQ(node, tlv_document_first(raw));
}

#if OPENTLV_FORMAT_BER
TEST(Unit_Tlv_QueryF3, OriginalLocationsAreIndependentOfCanonicalValueSnapshot) {
    Evaluation e;
    e.format = tlv_format_ber;
    tlv_document_options_t options;
    ASSERT_EQ(tlv_document_options_init(&options, &e.format), TLV_OK);
    options.retain_source_locations = 1;
    const uint8_t   wire[] = {0x50, 0x81, 1, 0xaa, 0x57, 0};
    tlv_document_t* raw = nullptr;
    ASSERT_EQ(tlv_document_parse(wire, sizeof wire, &options, &raw, nullptr), TLV_OK);
    std::unique_ptr<tlv_document_t, decltype(&tlv_document_free)> doc(raw, tlv_document_free);
    ASSERT_EQ(
        e.compile("//50[@offset=0 and @hlen=3 and @len=1]/following::57[@offset=4 and @hlen=2]"),
        TLV_OK);
    ASSERT_EQ(e.init(), TLV_OK);
    tlv_tree_writer_frame_t     frames[16];
    uint8_t                     values[64], scratch[64];
    tlv_tree_writer_workspace_t staging{};
    staging.frames = frames;
    staging.frame_capacity = 16;
    staging.scratch = scratch;
    staging.scratch_capacity = sizeof scratch;
    ASSERT_EQ(tlv_document_query_evaluate(raw, e.exec, nullptr, values, sizeof values, &staging,
                                          &e.diagnostic),
              TLV_OK);
    tlv_node_t* node = nullptr;
    ASSERT_EQ(tlv_document_query_next(e.exec, &node), TLV_OK);
    EXPECT_EQ(node, tlv_node_next(tlv_document_first(raw)));
    EXPECT_EQ(tlv_document_query_next(e.exec, &node), TLV_ERR_END_OF_BUFFER);
}
#endif

TEST(Unit_Tlv_QueryF3, DocumentQueryNeverUsesOwningAllocator) {
    Evaluation             e;
    tlv_document_options_t options;
    ASSERT_EQ(tlv_document_options_init(&options, &e.format), TLV_OK);
    struct Allocations {
        size_t calls = 0;
        bool   reject = false;
    } allocations;
    tlv_allocator_t allocator{};
    allocator.context = &allocations;
    allocator.allocate = [](void* context, size_t size) -> void* {
        auto& state = *static_cast<Allocations*>(context);
        ++state.calls;
        return state.reject ? nullptr : std::malloc(size);
    };
    allocator.release = [](void*, void* memory) { std::free(memory); };
    options.allocator = &allocator;
    const uint8_t   wire[] = {0x70, 4, 0x70, 2, 0x5a, 0};
    tlv_document_t* document = nullptr;
    ASSERT_EQ(tlv_document_parse(wire, sizeof wire, &options, &document, nullptr), TLV_OK);
    allocations.reject = true;
    size_t                      calls = allocations.calls;
    tlv_tree_writer_frame_t     frames[4];
    uint8_t                     staged[32], scratch[32], values[32];
    tlv_tree_writer_workspace_t staging{};
    staging.frames = frames;
    staging.frame_capacity = 4;
    staging.data = staged;
    staging.data_capacity = sizeof staged;
    staging.scratch = scratch;
    staging.scratch_capacity = sizeof scratch;
    size_t bytes;
    ASSERT_EQ(tlv_document_query_value_size(document, &staging, &bytes), TLV_OK);
    ASSERT_EQ(e.compile("value(/70)"), TLV_OK);
    ASSERT_EQ(e.init(), TLV_OK);
    ASSERT_EQ(tlv_document_query_evaluate(document, e.exec, nullptr, values, sizeof values,
                                          &staging, &e.diagnostic),
              TLV_OK);
    EXPECT_EQ(allocations.calls, calls);
    EXPECT_EQ(bytes, sizeof wire);
    tlv_document_free(document);
}

TEST(Unit_Tlv_QueryF3, DocumentNavigationNeedsNoValueStorage) {
    Evaluation             e;
    tlv_document_options_t options;
    ASSERT_EQ(tlv_document_options_init(&options, &e.format), TLV_OK);
    const uint8_t   wire[] = {0x70, 4, 0x70, 2, 0x5a, 0};
    tlv_document_t* document = nullptr;
    ASSERT_EQ(tlv_document_parse(wire, sizeof wire, &options, &document, nullptr), TLV_OK);
    for (const char* text : {"//5A", "count(//70)", "//70[constructed()]", "//70[len()>0]",
                             "//70[@len>0]", "value(/70)"}) {
        ASSERT_EQ(e.compile(text), TLV_OK) << text;
        const bool needs = std::strstr(text, "len") || std::strstr(text, "value");
        EXPECT_EQ(e.info.constructed_values_required != 0, needs) << text;
        ASSERT_EQ(e.init(), TLV_OK);
        auto rc = tlv_document_query_evaluate(document, e.exec, nullptr, nullptr, 0, nullptr,
                                              &e.diagnostic);
        EXPECT_EQ(rc, needs ? TLV_ERR_NULL_ARG : TLV_OK) << text;
        if (!needs && std::strstr(text, "count")) {
            ASSERT_EQ(tlv_query_exec_result(e.exec, &e.result), TLV_OK);
            EXPECT_EQ(e.result.integer, 2);
        }
    }
    tlv_document_free(document);
}

TEST(Unit_Tlv_QueryF3, DocumentSnapshotSlicesAndWorkIgnoreStagingCapacity) {
    Evaluation             e;
    tlv_document_options_t options;
    ASSERT_EQ(tlv_document_options_init(&options, &e.format), TLV_OK);
    const uint8_t   wire[] = {0x70, 6, 0x70, 2, 0x5a, 0, 0x70, 0};
    tlv_document_t* document = nullptr;
    ASSERT_EQ(tlv_document_parse(wire, sizeof wire, &options, &document, nullptr), TLV_OK);
    tlv_tree_writer_frame_t     frames[16];
    uint8_t                     staged[4096], scratch[4096], values[4096];
    tlv_tree_writer_workspace_t staging{};
    staging.frames = frames;
    staging.frame_capacity = 16;
    staging.data = staged;
    staging.scratch = scratch;
    size_t bytes = 0;
    for (size_t capacity : {sizeof wire, sizeof staged}) {
        staging.data_capacity = staging.scratch_capacity = capacity;
        ASSERT_EQ(tlv_document_query_value_size(document, &staging, &bytes), TLV_OK);
        EXPECT_EQ(bytes, sizeof wire);
        for (const auto& item : {std::make_pair("value(/70)", size_t(2)),
                                 std::make_pair("value(/70/70[1])", size_t(4)),
                                 std::make_pair("value(/70/70[2])", size_t(8))}) {
            ASSERT_EQ(e.compile(item.first), TLV_OK);
            ASSERT_EQ(e.init(), TLV_OK);
            ASSERT_EQ(tlv_document_query_evaluate(document, e.exec, nullptr, values, sizeof values,
                                                  &staging, &e.diagnostic),
                      TLV_OK);
            ASSERT_EQ(tlv_query_exec_result(e.exec, &e.result), TLV_OK);
            EXPECT_EQ(e.result.data, values + item.second);
            EXPECT_EQ(std::memcmp(values, wire, sizeof wire), 0);
        }
    }
    // Locate the exact work threshold, then replay both roomy and exact storage.
    ASSERT_EQ(e.compile("value(/70)"), TLV_OK);
    size_t threshold = 0;
    staging.data_capacity = staging.scratch_capacity = sizeof wire;
    for (size_t work = 1; work < 2000; ++work) {
        ASSERT_EQ(e.init(4, work), TLV_OK);
        auto rc = tlv_document_query_evaluate(document, e.exec, nullptr, values, sizeof values,
                                              &staging, &e.diagnostic);
        if (rc == TLV_OK) {
            threshold = work;
            break;
        }
        ASSERT_EQ(rc, TLV_ERR_LIMIT);
        ASSERT_STREQ(e.diagnostic.limit, "work");
    }
    ASSERT_GT(threshold, 0u);
    for (size_t capacity : {sizeof wire, sizeof staged}) {
        staging.data_capacity = staging.scratch_capacity = capacity;
        ASSERT_EQ(e.init(4, threshold), TLV_OK);
        EXPECT_EQ(tlv_document_query_evaluate(document, e.exec, nullptr, values, capacity, &staging,
                                              &e.diagnostic),
                  TLV_OK);
        ASSERT_EQ(e.init(4, threshold - 1), TLV_OK);
        EXPECT_EQ(TLV_DIAGNOSTIC_RESULT(
                      e.diagnostic, tlv_document_query_evaluate(document, e.exec, nullptr, values,
                                                                capacity, &staging, &e.diagnostic)),
                  TLV_ERR_LIMIT);
        EXPECT_STREQ(e.diagnostic.limit, "work");
    }
    tlv_document_free(document);
}
#if OPENTLV_FORMAT_CER
TEST(Unit_Tlv_QueryF3, DocumentSnapshotClosesNestedIndefiniteValuesBeforeSibling) {
    Evaluation e;
    e.format = tlv_format_cer;
    tlv_document_options_t options;
    ASSERT_EQ(tlv_document_options_init(&options, &e.format), TLV_OK);
    const uint8_t   wire[] = {0x30, 0x80, 0x30, 0x80, 0x04, 0, 0, 0, 0, 0, 0x04, 1, 0x7f};
    tlv_document_t* document = nullptr;
    ASSERT_EQ(tlv_document_parse(wire, sizeof wire, &options, &document, nullptr), TLV_OK);
    tlv_tree_writer_frame_t     frames[16];
    uint8_t                     values[sizeof wire], scratch[sizeof wire];
    tlv_tree_writer_workspace_t staging{};
    staging.frames = frames;
    staging.frame_capacity = 16;
    staging.scratch = scratch;
    staging.scratch_capacity = sizeof scratch;
    // Evaluation needs no staging output. END must skip each enclosing trailer.
    for (const char* text : {"value(/30/30)", "value(/04)", "len(value(/30))"}) {
        ASSERT_EQ(e.compile(text), TLV_OK);
        ASSERT_EQ(e.init(), TLV_OK);
        ASSERT_EQ(tlv_document_query_evaluate(document, e.exec, nullptr, values, sizeof values,
                                              &staging, &e.diagnostic),
                  TLV_OK);
        ASSERT_EQ(tlv_query_exec_result(e.exec, &e.result), TLV_OK);
        EXPECT_EQ(std::memcmp(values, wire, sizeof wire), 0);
        if (e.result.kind == TLV_QUERY_RESULT_INTEGER)
            EXPECT_EQ(e.result.integer, 6);
        else {
            EXPECT_EQ(e.result.size, std::strstr(text, "30") ? 2u : 1u);
            EXPECT_EQ(e.result.data, values + (std::strstr(text, "30") ? 4 : 12));
        }
    }
    tlv_document_free(document);
}
#endif
#endif
