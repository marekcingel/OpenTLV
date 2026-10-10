// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#include "../../diagnostic_assertions.h"
#include "tlv/query/program.h"
#include "tlv/schema/query.h"
#include "../../../tlv/src/query/program_internal.h"
#include "controlled_format.h"
#include <gtest/gtest.h>
#include <cstring>
#include <string>
#include <vector>
#if OPENTLV_DOCUMENT && OPENTLV_READER && OPENTLV_WRITER
#include "tlv/document/document.h"
#include <memory>
#endif
#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

namespace {
struct Program {
    std::vector<uint64_t>    storage;
    tlv_query_program_info_t info{};
    tlv_query_diagnostic_t   diagnostic{};
    tlv_result_t             compile(const std::string&                 text,
                                     const tlv_query_compile_options_t* options = nullptr) {
        info.struct_size = sizeof info;
        size_t size, alignment;
        auto rc = TLV_DIAGNOSTIC_RESULT(diagnostic,
                                        tlv_query_compile_scratch(text.data(), text.size(), options,
                                                                  &size, &alignment, &diagnostic));
        if (rc != TLV_OK) return rc;
        std::vector<uint64_t> scratch((size + 7) / 8);
        rc = TLV_DIAGNOSTIC_RESULT(diagnostic, tlv_query_compile(text.data(), text.size(), options,
                                                                 scratch.data(), size, nullptr, 0,
                                                                 &info, &diagnostic));
        if (rc != TLV_OK) return rc;
        storage.resize((info.program_size + 7) / 8);
        return TLV_DIAGNOSTIC_RESULT(
            diagnostic, tlv_query_compile(text.data(), text.size(), options, scratch.data(), size,
                                          storage.data(), info.program_size, &info, &diagnostic));
    }
    const tlv_query_program_t* get() const {
        return reinterpret_cast<const tlv_query_program_t*>(storage.data());
    }
};
int constructed(const void*, const tlv_tag_t* tag) {
    return tag->size == 1 && tag->data[0] == 0x70;
}

TEST(Unit_Tlv_QueryProgram, LifecycleErrorsDifferFromArgumentsAndResetRecovers) {
    Program p;
    ASSERT_EQ(TLV_OK, p.compile("//*"));
    size_t bytes, alignment;
    ASSERT_EQ(TLV_OK, tlv_query_exec_size(p.get(), 4, &bytes, &alignment));
    std::vector<uint64_t> storage((bytes + 7) / 8);
    tlv_query_exec_t*     exec = nullptr;
    ASSERT_EQ(TLV_OK, tlv_query_exec_init(p.get(), storage.data(), bytes, 4, 8, 10000, &exec));
    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_query_exec_context(exec, 8));
    ASSERT_EQ(TLV_OK, tlv_query_exec_finish(exec, &p.diagnostic));
    EXPECT_EQ(TLV_OK, tlv_query_exec_finish(exec, &p.diagnostic));
    EXPECT_EQ(TLV_ERR_INVALID_STATE, tlv_query_exec_context(exec, 0));
    EXPECT_EQ(TLV_ERR_INVALID_STATE,
              TLV_DIAGNOSTIC_RESULT(p.diagnostic,
                                    tlv_query_exec_bind(exec, "unused", TLV_QUERY_RESULT_INTEGER, 0,
                                                        nullptr, 0, &p.diagnostic)));
    EXPECT_EQ(TLV_QUERY_ERROR_STATE, p.diagnostic.kind);
    tlv_tree_event_t event{};
    event.kind = TLV_TREE_ELEMENT;
    int matched = 79;
    EXPECT_EQ(TLV_ERR_INVALID_STATE,
              TLV_DIAGNOSTIC_RESULT(p.diagnostic,
                                    tlv_query_exec_feed(exec, &event, &matched, &p.diagnostic)));
    EXPECT_EQ(TLV_QUERY_ERROR_STATE, p.diagnostic.kind);
    EXPECT_EQ(79, matched);
    ASSERT_EQ(TLV_OK, tlv_query_exec_reset(exec));
    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_query_exec_context(exec, 8));
    EXPECT_EQ(TLV_OK, tlv_query_exec_context(exec, 0));
    EXPECT_EQ(TLV_OK, tlv_query_exec_feed(exec, &event, &matched, &p.diagnostic));
    EXPECT_STREQ("invalid state", tlv_result_string(TLV_ERR_INVALID_STATE));
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
    auto                rc =
        TLV_DIAGNOSTIC_RESULT(p.diagnostic, tlv_query_program_visit(&reader, exec, collect_event,
                                                                    &matches, &p.diagnostic));
    if (result)
        *result = rc;
    else
        EXPECT_EQ(TLV_OK, rc);
    return matches;
}
} // namespace

TEST(Unit_Tlv_QueryProgram, InfoBytesAreDefinedAcrossCompilationEntryPoints) {
    const std::string text = "//5A";
    size_t            bytes, alignment;
    ASSERT_EQ(TLV_OK, tlv_query_compile_scratch(text.data(), text.size(), nullptr, &bytes,
                                                &alignment, nullptr));
    std::vector<uint64_t>    scratch((bytes + 7) / 8);
    tlv_query_program_info_t info;
    std::memset(&info, 0xa5, sizeof info);
    info.struct_size = sizeof info;
    ASSERT_EQ(TLV_OK, tlv_query_compile(text.data(), text.size(), nullptr, scratch.data(), bytes,
                                        nullptr, 0, &info, nullptr));
    const size_t  program_size = info.program_size;
    unsigned char expected[sizeof info];
    std::memcpy(expected, &info, sizeof info);
    std::vector<uint64_t> storage((program_size + 7) / 8);
    auto                  reset_info = [&] {
        std::memset(&info, 0x5a, sizeof info);
        info.struct_size = sizeof info;
    };
    // Read the complete published extent under Memcheck, including padding.
    // Byte snapshots also verify deterministic output from all publication paths.
    reset_info();
    ASSERT_EQ(TLV_OK, tlv_query_compile(text.data(), text.size(), nullptr, scratch.data(), bytes,
                                        storage.data(), program_size, &info, nullptr));
    EXPECT_EQ(0, std::memcmp(expected, &info, sizeof info));

    ASSERT_EQ(TLV_OK, tlv_query_compile_prepare_size(text.data(), text.size(), nullptr, &bytes,
                                                     &alignment, nullptr));
    std::vector<uint64_t>      preparation((bytes + 7) / 8);
    const tlv_query_program_t* prepared = nullptr;
    reset_info();
    ASSERT_EQ(TLV_OK,
              tlv_query_compile_prepare(text.data(), text.size(), nullptr, preparation.data(),
                                        bytes, &prepared, &info, nullptr));
    EXPECT_EQ(0, std::memcmp(expected, &info, sizeof info));

    ASSERT_EQ(TLV_OK, tlv_query_program_load_scratch(prepared, program_size, nullptr, &bytes,
                                                     &alignment, nullptr));
    std::vector<uint64_t>      validation((bytes + 7) / 8);
    const tlv_query_program_t* loaded = nullptr;
    reset_info();
    ASSERT_EQ(TLV_OK, tlv_query_program_load(prepared, program_size, nullptr, validation.data(),
                                             bytes, &loaded, &info, nullptr));
    EXPECT_EQ(0, std::memcmp(expected, &info, sizeof info));
    EXPECT_EQ(prepared, loaded);

    reset_info();
    ASSERT_EQ(TLV_OK,
              tlv_query_compile_commit(prepared, program_size, nullptr, validation.data(), bytes,
                                       storage.data(), program_size, &info, nullptr));
    EXPECT_EQ(0, std::memcmp(expected, &info, sizeof info));
}

TEST(Unit_Tlv_QueryProgram, CheckedCompilationRejectsResolverDriftAndPreservesOutputs) {
    struct Resolver {
        uint8_t      tag = 0x5a;
        size_t       calls = 0;
        tlv_result_t status = TLV_OK;
    } resolver;
    tlv_query_compile_options_t options;
    tlv_query_compile_options_init(&options);
    options.resolve_context = &resolver;
    options.resolve = [](const void* context, const char*, size_t, const char*, size_t,
                         tlv_tag_t*  tag) -> tlv_result_t {
        auto& state = *static_cast<Resolver*>(const_cast<void*>(context));
        ++state.calls;
        *tag = tlv_tag(&state.tag, 1);
        return state.status;
    };
    const std::string      text = "//ns:item";
    size_t                 bytes = 0, alignment = 0;
    tlv_query_diagnostic_t diagnostic{};
    ASSERT_EQ(TLV_OK, tlv_query_compile_prepare_size(text.data(), text.size(), &options, &bytes,
                                                     &alignment, &diagnostic));
    EXPECT_EQ(0u, resolver.calls);
    std::vector<uint64_t>      preparation((bytes + 7) / 8);
    const tlv_query_program_t* prepared = nullptr;
    tlv_query_program_info_t   info{};
    info.struct_size = sizeof info;
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
              TLV_DIAGNOSTIC_RESULT(diagnostic,
                                    tlv_query_compile_prepare(text.data(), text.size(), &options,
                                                              preparation.data(), bytes - 1,
                                                              &prepared, &info, &diagnostic)));
    EXPECT_EQ(nullptr, prepared);
    EXPECT_EQ(0u, resolver.calls);
    ASSERT_EQ(TLV_OK,
              tlv_query_compile_prepare(text.data(), text.size(), &options, preparation.data(),
                                        bytes, &prepared, &info, &diagnostic));
    EXPECT_EQ(1u, resolver.calls);
    const auto    snapshot = preparation;
    unsigned char original_info[sizeof info];
    std::memcpy(original_info, &info, sizeof info);
    const auto program_size = info.program_size;
    size_t     validation_bytes;
    ASSERT_EQ(TLV_OK, tlv_query_program_load_scratch(prepared, info.program_size, &options,
                                                     &validation_bytes, &alignment, &diagnostic));
    std::vector<uint64_t> validation((validation_bytes + 7) / 8);
    std::vector<uint64_t> output((info.program_size + 7) / 8, UINT64_C(0xcacacacacacacaca));
    const auto            original_output = output;
    auto                  commit = [&](size_t scratch_size, size_t capacity) {
        return tlv_query_compile_commit(prepared, program_size, &options, validation.data(),
                                        scratch_size, output.data(), capacity, &info, &diagnostic);
    };
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, commit(validation_bytes, info.program_size - 1));
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, commit(validation_bytes - 1, info.program_size));
    EXPECT_EQ(1u, resolver.calls);
    resolver.tag = 0x50; // Equal size: capacity checks alone cannot detect this change.
    EXPECT_EQ(TLV_ERR_INVALID_VALUE, commit(validation_bytes, info.program_size));
    EXPECT_EQ(TLV_QUERY_ERROR_IMAGE, diagnostic.kind);
    EXPECT_EQ(original_output, output);
    EXPECT_EQ(0, std::memcmp(original_info, &info, sizeof info));
    EXPECT_EQ(snapshot, preparation);
    resolver.status = TLV_ERR_INVALID_VALUE;
    EXPECT_NE(TLV_OK, commit(validation_bytes, info.program_size));
    EXPECT_EQ(original_output, output);
    resolver.status = TLV_OK;
    resolver.tag = 0x5a;
    ASSERT_EQ(TLV_OK, commit(validation_bytes, info.program_size));
    EXPECT_EQ(0, std::memcmp(output.data(), prepared, info.program_size));
    EXPECT_EQ(snapshot, preparation);
    Program program;
    program.storage = output;
    EXPECT_EQ((std::vector<size_t>{0}), run(program, {0x5a, 0, 0x50, 0}));
}

TEST(Unit_Tlv_QueryProgram, CheckedCompilationRejectsAliasingAndPreservesInfoExtensions) {
    const std::string text = "//5A";
    size_t            bytes, alignment;
    ASSERT_EQ(TLV_OK, tlv_query_compile_prepare_size(text.data(), text.size(), nullptr, &bytes,
                                                     &alignment, nullptr));
    std::vector<uint64_t>      preparation((bytes + 7) / 8);
    const tlv_query_program_t* prepared = nullptr;
    struct ExtendedInfo {
        tlv_query_program_info_t info;
        uint64_t                 extension;
    } output{};
    output.info.struct_size = sizeof output;
    output.extension = UINT64_C(0xabcdef);
    ASSERT_EQ(TLV_OK,
              tlv_query_compile_prepare(text.data(), text.size(), nullptr, preparation.data(),
                                        bytes, &prepared, &output.info, nullptr));
    EXPECT_EQ(sizeof output, output.info.struct_size);
    EXPECT_EQ(UINT64_C(0xabcdef), output.extension);
    size_t validation_bytes;
    ASSERT_EQ(TLV_OK, tlv_query_program_load_scratch(prepared, output.info.program_size, nullptr,
                                                     &validation_bytes, &alignment, nullptr));
    std::vector<uint64_t> validation((validation_bytes + 7) / 8);
    std::vector<uint64_t> storage((output.info.program_size + 7) / 8);
    const auto            original = preparation;
    EXPECT_EQ(TLV_ERR_INVALID_ARG,
              tlv_query_compile_commit(prepared, output.info.program_size, nullptr,
                                       validation.data(), validation_bytes,
                                       const_cast<tlv_query_program_t*>(prepared),
                                       output.info.program_size, &output.info, nullptr));
    EXPECT_EQ(
        TLV_ERR_INVALID_ARG,
        tlv_query_compile_commit(
            prepared, output.info.program_size, nullptr, validation.data(), validation_bytes,
            storage.data(), 0, &output.info,
            reinterpret_cast<tlv_query_diagnostic_t*>(const_cast<tlv_query_program_t*>(prepared))));
    EXPECT_EQ(original, preparation);
    EXPECT_EQ(TLV_ERR_INVALID_ARG,
              tlv_query_compile_prepare(text.data(), text.size(), nullptr,
                                        reinterpret_cast<uint8_t*>(preparation.data()) + 1,
                                        bytes - 1, &prepared, &output.info, nullptr));
    ASSERT_EQ(TLV_OK, tlv_query_compile_commit(prepared, output.info.program_size, nullptr,
                                               validation.data(), validation_bytes, storage.data(),
                                               output.info.program_size, &output.info, nullptr));
    EXPECT_EQ(sizeof output, output.info.struct_size);
    EXPECT_EQ(UINT64_C(0xabcdef), output.extension);
}

TEST(Unit_Tlv_QueryProgram, CanonicalFormattingRequiresIndependentScratchSizing) {
    const std::string text = "07<0,7<307,7<00,7<07";
    Program           original;
    ASSERT_EQ(TLV_OK, original.compile(text));
    size_t required;
    ASSERT_EQ(TLV_OK, tlv_query_program_format(original.get(), nullptr, 0, &required));
    std::vector<char> formatted(required);
    ASSERT_EQ(TLV_OK,
              tlv_query_program_format(original.get(), formatted.data(), required, &required));
    size_t before, after, alignment;
    ASSERT_EQ(TLV_OK, tlv_query_compile_scratch(text.data(), text.size(), nullptr, &before,
                                                &alignment, nullptr));
    ASSERT_EQ(TLV_OK, tlv_query_compile_scratch(formatted.data(), required - 1, nullptr, &after,
                                                &alignment, nullptr));
    ASSERT_GT(after, before);
    std::vector<uint64_t>    scratch((after + 7) / 8);
    tlv_query_program_info_t info{};
    info.struct_size = sizeof info;
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
              tlv_query_compile(formatted.data(), required - 1, nullptr, scratch.data(), before,
                                nullptr, 0, &info, nullptr));
    ASSERT_EQ(TLV_OK, tlv_query_compile(formatted.data(), required - 1, nullptr, scratch.data(),
                                        after, nullptr, 0, &info, nullptr));
    EXPECT_EQ(original.info.level, info.level);
    EXPECT_EQ(original.info.result_kind, info.result_kind);
    Program roundtrip;
    ASSERT_EQ(TLV_OK, roundtrip.compile(std::string(formatted.data(), required - 1)));
}

TEST(Unit_Tlv_QueryProgram, BoundedLoaderRejectsEveryTruncationWithoutWrites) {
    Program p;
    ASSERT_EQ(TLV_OK, p.compile("//70[exists(5A)] | //50[@len > 2]"));
    const auto original = p.storage;
    size_t     bytes = 0, alignment = 0;
    ASSERT_EQ(TLV_OK, tlv_query_program_load_scratch(p.get(), p.info.program_size, nullptr, &bytes,
                                                     &alignment, &p.diagnostic));
    std::vector<uint64_t>      scratch((bytes + 7) / 8);
    const tlv_query_program_t* loaded = nullptr;
    for (size_t size = 0; size < p.info.program_size; ++size) {
        EXPECT_NE(TLV_OK,
                  TLV_DIAGNOSTIC_RESULT(
                      p.diagnostic, tlv_query_program_load(p.get(), size, nullptr, scratch.data(),
                                                           bytes, &loaded, nullptr, &p.diagnostic)))
            << size;
        EXPECT_EQ(nullptr, loaded);
    }
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
              TLV_DIAGNOSTIC_RESULT(p.diagnostic,
                                    tlv_query_program_load(p.get(), p.info.program_size, nullptr,
                                                           scratch.data(), bytes - 1, &loaded,
                                                           nullptr, &p.diagnostic)));
    EXPECT_EQ(nullptr, loaded);
    ASSERT_EQ(TLV_OK, tlv_query_program_load(p.get(), p.info.program_size, nullptr, scratch.data(),
                                             bytes, &loaded, nullptr, &p.diagnostic));
    EXPECT_EQ(p.get(), loaded);
    EXPECT_EQ(original, p.storage);
    p.storage.push_back(0);
    EXPECT_NE(TLV_OK, TLV_DIAGNOSTIC_RESULT(
                          p.diagnostic, tlv_query_program_load(p.get(), p.info.program_size + 1,
                                                               nullptr, scratch.data(), bytes,
                                                               &loaded, nullptr, &p.diagnostic)));
}

TEST(Unit_Tlv_QueryProgram, LoaderRejectsAliasedStorageBeforeWriting) {
    Program p;
    ASSERT_EQ(TLV_OK, p.compile("//5A"));
    size_t bytes, alignment;
    ASSERT_EQ(TLV_OK, tlv_query_program_load_scratch(p.get(), p.info.program_size, nullptr, &bytes,
                                                     &alignment, nullptr));
    std::vector<uint64_t>      scratch((bytes + 7) / 8, 0xabababab);
    const auto                 original = p.storage;
    const auto                 untouched = scratch;
    const tlv_query_program_t* loaded = nullptr;
    EXPECT_EQ(TLV_ERR_INVALID_ARG,
              tlv_query_program_load(p.get(), p.info.program_size, nullptr, p.storage.data(), bytes,
                                     &loaded, nullptr, nullptr));
    EXPECT_EQ(TLV_ERR_INVALID_ARG,
              tlv_query_program_load(p.get(), p.info.program_size, nullptr, scratch.data(), bytes,
                                     reinterpret_cast<const tlv_query_program_t**>(scratch.data()),
                                     nullptr, nullptr));
    EXPECT_EQ(TLV_ERR_INVALID_ARG,
              tlv_query_program_load(p.get(), p.info.program_size, nullptr, scratch.data(), bytes,
                                     &loaded, nullptr,
                                     reinterpret_cast<tlv_query_diagnostic_t*>(p.storage.data())));
    EXPECT_EQ(TLV_ERR_INVALID_ARG,
              tlv_query_program_load_scratch(p.get(), p.info.program_size, nullptr,
                                             reinterpret_cast<size_t*>(p.storage.data()),
                                             &alignment, nullptr));
    EXPECT_EQ(nullptr, loaded);
    EXPECT_EQ(original, p.storage);
    EXPECT_EQ(untouched, scratch);
}

TEST(Unit_Tlv_QueryProgram, LoaderAuthenticatesEveryInstructionField) {
    Program p;
    ASSERT_EQ(TLV_OK, p.compile("//70[exists(5A)] | //50[@len > 2]"));
    size_t bytes, alignment;
    ASSERT_EQ(TLV_OK, tlv_query_program_load_scratch(p.get(), p.info.program_size, nullptr, &bytes,
                                                     &alignment, nullptr));
    std::vector<uint64_t> scratch((bytes + 7) / 8);
    auto                  header = p.get();
    size_t                words = header->text_offset / sizeof(uint32_t);
    for (size_t word = 0; word < words; ++word) {
        auto copy = p.storage;
        reinterpret_cast<uint32_t*>(copy.data())[word] ^= UINT32_C(0x80000000);
        const auto                 untouched = copy;
        const tlv_query_program_t* loaded = p.get();
        EXPECT_NE(TLV_OK, tlv_query_program_load(copy.data(), p.info.program_size, nullptr,
                                                 scratch.data(), bytes, &loaded, nullptr, nullptr))
            << word;
        EXPECT_EQ(p.get(), loaded);
        EXPECT_EQ(untouched, copy);
    }
    auto  copy = p.storage;
    auto* corrupt = reinterpret_cast<tlv_query_program_t*>(copy.data());
    ++corrupt->version;
    const tlv_query_program_t* loaded = nullptr;
    EXPECT_EQ(TLV_ERR_UNSUPPORTED,
              TLV_DIAGNOSTIC_RESULT(p.diagnostic,
                                    tlv_query_program_load(copy.data(), p.info.program_size,
                                                           nullptr, scratch.data(), bytes, &loaded,
                                                           nullptr, &p.diagnostic)));
    EXPECT_EQ(TLV_QUERY_ERROR_IMAGE_VERSION, p.diagnostic.kind);
}

TEST(Unit_Tlv_QueryProgram, LoaderExecutesReadOnlyPageWithoutImageWrites) {
    Program p;
    ASSERT_EQ(TLV_OK, p.compile("//5A"));
    struct Page {
        void*  data;
        size_t size;
        ~Page() {
#if defined(_WIN32)
            if (data) VirtualFree(data, 0, MEM_RELEASE);
#else
            if (data != MAP_FAILED) munmap(data, size);
#endif
        }
    };
#if defined(_WIN32)
    Page page{VirtualAlloc(nullptr, p.info.program_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE),
              p.info.program_size};
    ASSERT_NE(nullptr, page.data);
#else
    Page page{mmap(nullptr, p.info.program_size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0),
              p.info.program_size};
    ASSERT_NE(MAP_FAILED, page.data);
#endif
    std::memcpy(page.data, p.get(), p.info.program_size);
#if defined(_WIN32)
    DWORD previous;
    ASSERT_TRUE(VirtualProtect(page.data, page.size, PAGE_READONLY, &previous));
#else
    ASSERT_EQ(0, mprotect(page.data, page.size, PROT_READ));
#endif
    size_t bytes, alignment;
    ASSERT_EQ(TLV_OK, tlv_query_program_load_scratch(page.data, page.size, nullptr, &bytes,
                                                     &alignment, nullptr));
    std::vector<uint64_t>      scratch((bytes + 7) / 8);
    const tlv_query_program_t* loaded = nullptr;
    ASSERT_EQ(TLV_OK, tlv_query_program_load(page.data, page.size, nullptr, scratch.data(), bytes,
                                             &loaded, nullptr, nullptr));
    ASSERT_EQ(TLV_OK, tlv_query_exec_size(loaded, 0, &bytes, &alignment));
    std::vector<uint64_t> workspace((bytes + 7) / 8);
    tlv_query_exec_t*     exec;
    ASSERT_EQ(TLV_OK, tlv_query_exec_init(loaded, workspace.data(), bytes, 0, 1, 1000, &exec));
    uint8_t          tag = 0x5a;
    tlv_tree_event_t event{};
    event.kind = TLV_TREE_ELEMENT;
    event.element.tag = tlv_tag(&tag, 1);
    int matched;
    ASSERT_EQ(TLV_OK, tlv_query_exec_feed(exec, &event, &matched, nullptr));
    EXPECT_EQ(1, matched);
    EXPECT_EQ(TLV_OK, tlv_query_exec_finish(exec, nullptr));
}

TEST(Unit_Tlv_QueryProgram, LoaderRequiresMatchingVariablesEnvironmentAndOptimizer) {
    tlv_query_variable_t        variable = {"min", TLV_QUERY_RESULT_INTEGER};
    tlv_query_compile_options_t options;
    tlv_query_compile_options_init(&options);
    options.variables = &variable;
    options.variable_count = 1;
    options.optimize = 0;
    Program p;
    ASSERT_EQ(TLV_OK, p.compile("//5A[@len > $min]", &options));
    size_t bytes, alignment;
    ASSERT_EQ(TLV_OK, tlv_query_program_load_scratch(p.get(), p.info.program_size, &options, &bytes,
                                                     &alignment, nullptr));
    std::vector<uint64_t>      scratch((bytes + 7) / 8);
    const tlv_query_program_t* loaded = nullptr;
    EXPECT_NE(TLV_OK, tlv_query_program_load(p.get(), p.info.program_size, nullptr, scratch.data(),
                                             bytes, &loaded, nullptr, nullptr));
    ASSERT_EQ(TLV_OK, tlv_query_program_load(p.get(), p.info.program_size, &options, scratch.data(),
                                             bytes, &loaded, nullptr, nullptr));
    EXPECT_EQ(p.get(), loaded);
    options.max_pattern++;
    // An unused capability must not become a plan requirement.
    EXPECT_EQ(0u, p.info.pattern_bytes);
    EXPECT_EQ(TLV_OK, tlv_query_program_load(p.get(), p.info.program_size, &options, scratch.data(),
                                             bytes, &loaded, nullptr, nullptr));
    variable.name = "needle";
    variable.type = TLV_QUERY_RESULT_BYTES;
    ASSERT_EQ(TLV_OK, p.compile("//5A[contains(value(), $needle)]", &options));
    EXPECT_EQ(options.max_pattern, p.info.pattern_bytes);
    ASSERT_EQ(TLV_OK, tlv_query_program_load_scratch(p.get(), p.info.program_size, &options, &bytes,
                                                     &alignment, nullptr));
    scratch.resize((bytes + 7) / 8);
    options.max_pattern++;
    EXPECT_NE(TLV_OK, tlv_query_program_load(p.get(), p.info.program_size, &options, scratch.data(),
                                             bytes, &loaded, nullptr, nullptr));
}

TEST(Unit_Tlv_QueryProgram, AdversarialContainsChargesLinearBytesAndExactWorkBoundary) {
    Program p;
    ASSERT_EQ(TLV_OK, p.compile("//5A[contains(value(), x'6161616162')]"));
    size_t bytes, alignment;
    ASSERT_EQ(TLV_OK, tlv_query_exec_size(p.get(), 0, &bytes, &alignment));
    std::vector<uint64_t> storage((bytes + 7) / 8);
    const uint8_t         tag = 0x5a;
    for (size_t size : {size_t(64), size_t(256), size_t(1024), size_t(4096)}) {
        std::vector<uint8_t> value(size, 'a');
        tlv_tree_event_t     event{};
        event.kind = TLV_TREE_ELEMENT;
        event.element.tag = tlv_tag(&tag, 1);
        event.element.value.data = value.data();
        event.element.value.size = value.size();
        tlv_query_exec_t* exec = nullptr;
        ASSERT_EQ(TLV_OK,
                  tlv_query_exec_init(p.get(), storage.data(), bytes, 0, 1, SIZE_MAX, &exec));
        int matched = -1;
        ASSERT_EQ(TLV_OK, tlv_query_exec_feed(exec, &event, &matched, &p.diagnostic));
        EXPECT_EQ(0, matched);
        ASSERT_EQ(TLV_OK, tlv_query_exec_finish(exec, &p.diagnostic));
        tlv_query_exec_info_t info{};
        info.struct_size = sizeof info;
        ASSERT_EQ(TLV_OK, tlv_query_exec_info(exec, &info));
        EXPECT_GE(info.work, size);
        EXPECT_LE(info.work, 2 * size + 4 * p.info.states + 32);
        ASSERT_EQ(TLV_OK,
                  tlv_query_exec_init(p.get(), storage.data(), bytes, 0, 1, info.work, &exec));
        EXPECT_EQ(TLV_OK, tlv_query_exec_feed(exec, &event, &matched, &p.diagnostic));
        EXPECT_EQ(TLV_OK, tlv_query_exec_finish(exec, &p.diagnostic));
        ASSERT_EQ(TLV_OK,
                  tlv_query_exec_init(p.get(), storage.data(), bytes, 0, 1, info.work - 1, &exec));
        auto rc = tlv_query_exec_feed(exec, &event, &matched, &p.diagnostic);
        if (rc == TLV_OK) rc = tlv_query_exec_finish(exec, &p.diagnostic);
        EXPECT_EQ(TLV_ERR_LIMIT, rc);
        EXPECT_STREQ("work", p.diagnostic.limit);
        EXPECT_EQ(TLV_ERR_INVALID_STATE, tlv_query_exec_feed(exec, &event, &matched, nullptr));
    }
}

TEST(Unit_Tlv_QueryProgram, StructuralWorkScalesWithEventsAndProgramStates) {
    for (size_t alternatives : {size_t(1), size_t(4), size_t(16)}) {
        std::string text = "//5A";
        for (size_t i = 1; i < alternatives; ++i) text += " | //50";
        Program p;
        ASSERT_EQ(TLV_OK, p.compile(text));
        size_t bytes, alignment;
        ASSERT_EQ(TLV_OK, tlv_query_exec_size(p.get(), 0, &bytes, &alignment));
        std::vector<uint64_t> storage((bytes + 7) / 8);
        size_t                unit_work = 0;
        for (size_t nodes : {size_t(1), size_t(16), size_t(64), size_t(256)}) {
            tlv_query_exec_t* exec;
            ASSERT_EQ(TLV_OK, tlv_query_exec_init(p.get(), storage.data(), bytes, 0, nodes,
                                                  SIZE_MAX, &exec));
            uint8_t          tag = 0x5a;
            tlv_tree_event_t event{};
            event.kind = TLV_TREE_ELEMENT;
            event.element.tag = tlv_tag(&tag, 1);
            size_t matches = 0;
            for (size_t i = 0; i < nodes; ++i) {
                event.offset = 2 * i;
                int matched;
                ASSERT_EQ(TLV_OK, tlv_query_exec_feed(exec, &event, &matched, nullptr));
                matches += matched != 0;
            }
            ASSERT_EQ(TLV_OK, tlv_query_exec_finish(exec, nullptr));
            tlv_query_exec_info_t info{};
            info.struct_size = sizeof info;
            ASSERT_EQ(TLV_OK, tlv_query_exec_info(exec, &info));
            if (nodes == 1) unit_work = info.work;
            EXPECT_EQ(nodes, matches);
            EXPECT_EQ(unit_work * nodes, info.work);
            EXPECT_LE(info.work, 8 * p.info.states * nodes);
        }
    }
}

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
    EXPECT_EQ(TLV_QUERY_ERROR_TYPE, p.diagnostic.kind); // Numeric range, not grammar.
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
    EXPECT_EQ(TLV_ERR_INVALID_VALUE,
              TLV_DIAGNOSTIC_RESULT(p.diagnostic,
                                    tlv_query_exec_bind(exec, "unused", TLV_QUERY_RESULT_BYTES, 0,
                                                        nullptr, 0, &p.diagnostic)));
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
    EXPECT_EQ(TLV_ERR_INVALID_VALUE, tlv_query_exec_size(p.get(), 0, &bytes, &alignment));
    ASSERT_EQ(TLV_OK, p.compile("//5A"));
    EXPECT_EQ(0u, tlv_query_program_variable_count(p.get()));
    ASSERT_EQ(TLV_OK, tlv_query_exec_size(p.get(), 0, &bytes, &alignment));
    EXPECT_EQ(sizeof(tlv_query_exec_t) + p.info.states * sizeof(query_value_t) + sizeof(size_t) +
                  p.info.states,
              bytes);
}
TEST(Unit_Tlv_QueryProgram, GrammarFailuresPairSyntaxResultAndKind) {
    Program p;
    for (const char* text :
         {"/", "//5A[@len > 1", "//5A[@len > ]", "//5A[@len 1]", "//5A[#]", "unknown::5A",
          "//5A[@len > $123]", "//5A[value() = 'abc]", "//5A[value() = x'0]",
          "//5A[value() = x'0G']", "//5A[substr(value(), 1, 2, 3) = x'']"}) {
        SCOPED_TRACE(text);
        EXPECT_EQ(TLV_ERR_SYNTAX, p.compile(text));
        EXPECT_EQ(TLV_QUERY_ERROR_SYNTAX, p.diagnostic.kind);
        EXPECT_EQ(TLV_ERR_SYNTAX, p.diagnostic.diagnostic.code);
        EXPECT_EQ(TLV_LOCATION_EXPRESSION, p.diagnostic.diagnostic.location.domain);
    }
    // Valid grammar that fails for another reason never borrows the SYNTAX kind.
    for (const char* text : {"//5A[@len = 9223372036854775808]", "//5A[num(.) > $min]"}) {
        SCOPED_TRACE(text);
        EXPECT_NE(TLV_ERR_SYNTAX, p.compile(text));
        EXPECT_NE(TLV_QUERY_ERROR_SYNTAX, p.diagnostic.kind);
    }
}
TEST(Unit_Tlv_QueryProgram, VariableIdentifiersFollowGrammar) {
    Program p;
    EXPECT_EQ(TLV_ERR_SYNTAX, p.compile("//5A[@len > $123]"));
    EXPECT_EQ(TLV_QUERY_ERROR_SYNTAX, p.diagnostic.kind);
    EXPECT_EQ(TLV_ERR_SYNTAX, p.compile("//5A[@len > $?foo]"));
    EXPECT_EQ(TLV_ERR_SYNTAX, p.compile("//5A[@len > $_foo]"));
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
    EXPECT_EQ(TLV_QUERY_S2, p.info.level);
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
    EXPECT_EQ(TLV_ERR_INVALID_VALUE,
              TLV_DIAGNOSTIC_RESULT(p.diagnostic,
                                    tlv_query_exec_bind(a, "unknown", TLV_QUERY_RESULT_BYTES, 0,
                                                        aid, sizeof aid, &p.diagnostic)));
    EXPECT_EQ(
        TLV_ERR_INVALID_VALUE,
        TLV_DIAGNOSTIC_RESULT(p.diagnostic, tlv_query_exec_bind(a, "aid", TLV_QUERY_RESULT_INTEGER,
                                                                1, nullptr, 0, &p.diagnostic)));
    ASSERT_EQ(TLV_OK, tlv_query_exec_bind(a, "aid", TLV_QUERY_RESULT_BYTES, 0, aid, sizeof aid,
                                          &p.diagnostic));
    EXPECT_EQ(
        TLV_ERR_INVALID_VALUE,
        TLV_DIAGNOSTIC_RESULT(p.diagnostic, tlv_query_exec_bind(a, "aid", TLV_QUERY_RESULT_BYTES, 0,
                                                                aid, sizeof aid, &p.diagnostic)));
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
    EXPECT_EQ(
        TLV_ERR_INVALID_STATE,
        TLV_DIAGNOSTIC_RESULT(p.diagnostic, tlv_query_exec_bind(a, "min", TLV_QUERY_RESULT_INTEGER,
                                                                0, nullptr, 0, &p.diagnostic)));
    ASSERT_EQ(TLV_OK, tlv_query_exec_init(p.get(), first.data(), bytes, 2, 10, 1000, &a));
    EXPECT_EQ(TLV_ERR_INVALID_VALUE,
              TLV_DIAGNOSTIC_RESULT(p.diagnostic,
                                    tlv_query_exec_feed(a, &event, &matched, &p.diagnostic)));
    EXPECT_EQ(TLV_QUERY_ERROR_BINDING, p.diagnostic.kind);
    options.variable_count = 0;
    EXPECT_EQ(TLV_ERR_INVALID_VALUE, p.compile("//84[value() = $aid]", &options));
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
    EXPECT_EQ(TLV_ERR_INVALID_VALUE,
              TLV_DIAGNOSTIC_RESULT(p.diagnostic, tlv_query_exec_finish(exec, &p.diagnostic)));
    EXPECT_EQ(TLV_QUERY_ERROR_BINDING, p.diagnostic.kind);
    ASSERT_EQ(TLV_OK, tlv_query_exec_init(p.get(), storage.data(), bytes, 1, 10, 1000, &exec));
    const uint8_t invalid[] = {0xc0, 0x80};
    EXPECT_EQ(TLV_ERR_INVALID_VALUE,
              TLV_DIAGNOSTIC_RESULT(p.diagnostic,
                                    tlv_query_exec_bind(exec, "a", TLV_QUERY_RESULT_STRING, 0,
                                                        invalid, sizeof invalid, &p.diagnostic)));
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
    EXPECT_EQ(TLV_ERR_INVALID_VALUE, p.compile("//5A[$a = $b]", &options));
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
    EXPECT_EQ(
        TLV_ERR_INVALID_VALUE,
        TLV_DIAGNOSTIC_RESULT(p.diagnostic, tlv_query_program_visit(&reader, exec, collect_event,
                                                                    &matches, &p.diagnostic)));
    tlv_tree_event_t event;
    EXPECT_EQ(TLV_OK, tlv_tree_reader_next_event(&reader, &event));
    EXPECT_EQ(0u, event.offset);
}
TEST(Unit_Tlv_QueryProgram, UnsupportedFeaturesHavePreciseDiagnostics) {
    Program p;
    EXPECT_EQ(TLV_OK, p.compile("//70[not(5A)] | //5A"));
    EXPECT_EQ(TLV_QUERY_S2, p.info.level);
    size_t bytes, alignment;
    EXPECT_EQ(TLV_ERR_UNSUPPORTED, tlv_query_exec_size(p.get(), 1, &bytes, &alignment));
    EXPECT_EQ(TLV_ERR_UNSUPPORTED, p.compile("//5A[num(.) > $min]"));
    EXPECT_EQ(TLV_QUERY_ERROR_CAPABILITY, p.diagnostic.kind);
    EXPECT_EQ(TLV_ERR_SYNTAX, p.compile("//5A[@len > 1"));
    EXPECT_EQ(TLV_QUERY_ERROR_SYNTAX, p.diagnostic.kind);
    EXPECT_EQ(TLV_OK, p.compile("//5A[1]"));
    EXPECT_EQ(TLV_QUERY_S2, p.info.level);
    EXPECT_EQ(TLV_ERR_SYNTAX, p.compile("//9F?"));
    EXPECT_EQ(TLV_ERR_SYNTAX, p.compile("//tag-mask(x'00', x'FFFF')"));
    EXPECT_EQ(TLV_ERR_SYNTAX, p.compile("//tag-range(x'FF', x'00')"));
    EXPECT_EQ(TLV_ERR_SYNTAX, p.compile("unknown::5A"));
    EXPECT_EQ(TLV_QUERY_ERROR_SYNTAX, p.diagnostic.kind);
    EXPECT_EQ(TLV_OK, p.compile("70/(//5A)"));
    EXPECT_EQ(TLV_OK, p.compile("//5A[ancestor::70[@len=3]]"));
    EXPECT_EQ(TLV_QUERY_S2, p.info.level);
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
              TLV_DIAGNOSTIC_RESULT(d, tlv_query_compile(text.data(), text.size(), nullptr,
                                                         scratch.data(), size - 1, nullptr, 0,
                                                         &info, &d)));
    ASSERT_EQ(TLV_OK, tlv_query_compile(text.data(), text.size(), nullptr, scratch.data(), size,
                                        nullptr, 0, &info, &d));
    std::vector<uint64_t> storage((info.program_size + 7) / 8, UINT64_MAX);
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
              TLV_DIAGNOSTIC_RESULT(d, tlv_query_compile(text.data(), text.size(), nullptr,
                                                         scratch.data(), size, storage.data(),
                                                         info.program_size - 1, &info, &d)));
    EXPECT_EQ(UINT64_MAX, storage[0]);
    EXPECT_EQ(TLV_QUERY_ERROR_STORAGE, d.kind);
    tlv_query_compile_options_t options;
    tlv_query_compile_options_init(&options);
    options.max_nesting = 1;
    const std::string nested = "((5A))";
    ASSERT_EQ(TLV_OK, tlv_query_compile_scratch(nested.data(), nested.size(), &options, &size,
                                                &alignment, &d));
    scratch.resize((size + 7) / 8);
    EXPECT_EQ(
        TLV_ERR_LIMIT,
        TLV_DIAGNOSTIC_RESULT(d, tlv_query_compile(nested.data(), nested.size(), &options,
                                                   scratch.data(), size, nullptr, 0, &info, &d)));
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
            case 13: nodes[0].axis = A_PRECEDE + 1; break;
            case 14:
                p = reinterpret_cast<tlv_query_program_t*>(reinterpret_cast<char*>(p) + 1);
                break;
        }
        const auto expected = mutation == 14 ? TLV_ERR_INVALID_ARG : TLV_ERR_INVALID_VALUE;
        size_t     bytes = 777, alignment = 777, required = 777;
        EXPECT_EQ(expected, tlv_query_exec_size(p, 4, &bytes, &alignment)) << mutation;
        EXPECT_EQ(777u, bytes);
        EXPECT_EQ(expected, tlv_query_eval_size(p, 4, 8, &bytes, &alignment)) << mutation;
        EXPECT_EQ(777u, bytes);
        EXPECT_EQ(777u, alignment);
        uint64_t          workspace[4096];
        tlv_query_exec_t* exec = nullptr;
        EXPECT_EQ(expected,
                  tlv_query_exec_init(p, workspace, sizeof workspace, 4, 100, 10000, &exec))
            << mutation;
        EXPECT_EQ(nullptr, exec);
        char output[64] = "unchanged";
        EXPECT_EQ(expected, tlv_query_program_format(p, output, sizeof output, &required))
            << mutation;
        EXPECT_STREQ("unchanged", output);
        EXPECT_EQ(777u, required);
        EXPECT_EQ(expected, tlv_query_program_explain(p, output, sizeof output, &required))
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
        EXPECT_EQ(TLV_QUERY_S2, p.info.level);
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
    EXPECT_EQ(
        TLV_NEED_MORE_DATA,
        TLV_DIAGNOSTIC_RESULT(p.diagnostic, tlv_query_program_visit(&reader, exec, collect_event,
                                                                    &matches, &p.diagnostic)));
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
TEST(Unit_Tlv_QueryProgram, TreeResourceLimitsHaveOwnedSafeReaderDiagnostics) {
    Program selector, assertion;
    ASSERT_EQ(TLV_OK, selector.compile("//*"));
    ASSERT_EQ(TLV_OK, assertion.compile("1 = 1"));
    const uint8_t wire[] = {0x70, 2, 0x5a, 0};
    auto          format = controlled::format;
    format.is_constructed = constructed;
    size_t bytes, alignment;
    ASSERT_EQ(TLV_OK, tlv_query_exec_size(selector.get(), 4, &bytes, &alignment));
    std::vector<uint64_t> storage((bytes + 7) / 8);
    for (int resource = 0; resource < 3; ++resource) {
        tlv_query_exec_t* exec = nullptr;
        ASSERT_EQ(TLV_OK,
                  tlv_query_exec_init(selector.get(), storage.data(), bytes, 4, 8, 100000, &exec));
        tlv_tree_frame_t  frames[4];
        tlv_tree_reader_t reader;
        ASSERT_EQ(TLV_OK, tlv_tree_reader_init(&reader, wire, sizeof wire, &format, frames,
                                               resource == 0 ? 0 : 4, resource == 1 ? 0 : 4,
                                               resource == 2 ? 0 : 8));
        std::vector<size_t> selected;
        std::memset(&selector.diagnostic, 0xa5, sizeof selector.diagnostic);
        ASSERT_EQ(resource == 0 ? TLV_ERR_BUFFER_TOO_SHORT : TLV_ERR_LIMIT,
                  TLV_DIAGNOSTIC_RESULT(selector.diagnostic,
                                        tlv_query_program_visit(&reader, exec, collect_event,
                                                                &selected, &selector.diagnostic)));
        const auto& detail = selector.diagnostic.reader;
        EXPECT_EQ(TLV_QUERY_ERROR_READER, selector.diagnostic.kind);
        EXPECT_TRUE(selector.diagnostic.has_reader);
        EXPECT_EQ(resource == 0 ? TLV_ERR_BUFFER_TOO_SHORT : TLV_ERR_LIMIT,
                  selector.diagnostic.diagnostic.code);
        EXPECT_EQ(TLV_DIAGNOSTIC_SEVERITY_ERROR, selector.diagnostic.diagnostic.severity);
        EXPECT_EQ(0, selector.diagnostic.diagnostic.location.kind);
        EXPECT_EQ(nullptr, selector.diagnostic.diagnostic.expected);
        EXPECT_EQ(nullptr, selector.diagnostic.diagnostic.actual);
        EXPECT_EQ(0, detail.has_tag);
        EXPECT_EQ(nullptr, detail.tag.data);
        EXPECT_EQ(0u, detail.tag.size);
        EXPECT_EQ(0, detail.has_raw_length);
        EXPECT_EQ(0u, selector.diagnostic.diagnostic.path.length);
        EXPECT_EQ(0u, selector.diagnostic.diagnostic.path.omitted);

        ASSERT_EQ(TLV_OK, tlv_query_exec_reset(exec));
        ASSERT_EQ(TLV_OK, tlv_tree_reader_init(&reader, wire, sizeof wire, &format, frames,
                                               resource == 0 ? 0 : 4, resource == 1 ? 0 : 4,
                                               resource == 2 ? 0 : 8));
        selected.clear();
        EXPECT_EQ(resource == 0 ? TLV_ERR_BUFFER_TOO_SHORT : TLV_ERR_LIMIT,
                  tlv_query_program_visit(&reader, exec, collect_event, &selected, nullptr));
    }

    tlv_schema_query_rule_t rule = {selector.get(), assertion.get(), nullptr, "limited"};
    size_t                  selector_size, assertion_size;
    ASSERT_EQ(TLV_OK,
              tlv_schema_query_size(&rule, 1, 0, 8, &selector_size, &assertion_size, &alignment));
    std::vector<uint8_t> selected(selector_size + alignment - 1);
    std::vector<uint8_t> asserted(assertion_size + alignment - 1);
    auto                 aligned = [alignment](std::vector<uint8_t>& data) {
        return reinterpret_cast<void*>((reinterpret_cast<uintptr_t>(data.data()) + alignment - 1) &
                                       ~(static_cast<uintptr_t>(alignment) - 1));
    };
    tlv_schema_query_context_t    contexts[8];
    tlv_tree_frame_t              frame;
    tlv_schema_query_workspace_t  workspace = {aligned(selected),
                                               selector_size,
                                               aligned(asserted),
                                               assertion_size,
                                               contexts,
                                               8,
                                               &frame,
                                               1};
    tlv_schema_query_diagnostic_t diagnostic;
    std::memset(&diagnostic, 0xa5, sizeof diagnostic);
    ASSERT_EQ(TLV_ERR_LIMIT,
              TLV_DIAGNOSTIC_RESULT(diagnostic, tlv_schema_query_validate_buffer(
                                                    wire, sizeof wire, &format, &rule, 1, 0, 8,
                                                    100000, &workspace, &diagnostic)));
    EXPECT_EQ(TLV_QUERY_ERROR_READER, diagnostic.query.kind);
    EXPECT_TRUE(diagnostic.query.has_reader);
    EXPECT_EQ(TLV_ERR_LIMIT, diagnostic.query.diagnostic.code);
    EXPECT_EQ(nullptr, diagnostic.query.diagnostic.expected);
    EXPECT_EQ(nullptr, diagnostic.query.reader.tag.data);
    EXPECT_EQ(0, diagnostic.query.reader.has_tag);
    EXPECT_EQ(0, diagnostic.query.reader.has_raw_length);
    EXPECT_EQ(TLV_LOCATION_UNKNOWN, diagnostic.query.diagnostic.location.kind);
    EXPECT_EQ(0u, diagnostic.query.diagnostic.path.length);
    EXPECT_EQ(0u, diagnostic.query.diagnostic.path.omitted);
    EXPECT_EQ(TLV_ERR_LIMIT, tlv_schema_query_validate_buffer(wire, sizeof wire, &format, &rule, 1,
                                                              0, 8, 100000, &workspace, nullptr));
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
    EXPECT_EQ(TLV_ERR_INVALID_VALUE,
              TLV_DIAGNOSTIC_RESULT(p.diagnostic,
                                    tlv_query_exec_feed(exec, &event, &matched, &p.diagnostic)));
    EXPECT_EQ(9, matched);
    EXPECT_EQ(TLV_QUERY_ERROR_SOURCE, p.diagnostic.kind);
    ASSERT_EQ(TLV_OK, tlv_query_exec_init(p.get(), workspace.data(), bytes, 4, 100, 1000, &exec));
    event.kind = TLV_TREE_END;
    EXPECT_EQ(TLV_ERR_INVALID_VALUE,
              TLV_DIAGNOSTIC_RESULT(p.diagnostic,
                                    tlv_query_exec_feed(exec, &event, &matched, &p.diagnostic)));
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
    EXPECT_NE(TLV_OK,
              TLV_DIAGNOSTIC_RESULT(
                  p.diagnostic, tlv_query_program_exists(&reader, exec, 0, &found, &p.diagnostic)));
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
    EXPECT_NE(TLV_OK,
              TLV_DIAGNOSTIC_RESULT(
                  p.diagnostic, tlv_query_program_exists(&reader, exec, 0, &found, &p.diagnostic)));
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

TEST(Unit_Tlv_QueryProgram, CanonicalFormatPreservesSeparatedPathTokens) {
    for (const char* text : {"/\t/.", "/ /ee", "/ //.", "// /."}) {
        Program original;
        ASSERT_EQ(TLV_OK, original.compile(text)) << text;
        char   output[64];
        size_t required;
        ASSERT_EQ(TLV_OK,
                  tlv_query_program_format(original.get(), output, sizeof output, &required));
        Program canonical;
        ASSERT_EQ(TLV_OK, canonical.compile(output)) << output;
        EXPECT_EQ(original.info.level, canonical.info.level) << output;
        EXPECT_EQ(original.info.result_kind, canonical.info.result_kind) << output;
        char second[64];
        ASSERT_EQ(TLV_OK,
                  tlv_query_program_format(canonical.get(), second, sizeof second, &required));
        EXPECT_STREQ(output, second);
    }
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
    unsigned char before[sizeof query];
    std::memcpy(before, &query, sizeof query);
    tlv_diagnostic_t offset = {};
    offset.location.begin = 99;
    EXPECT_EQ(TLV_ERR_SYNTAX, tlv_query_parse_n("6F\0/50", 6, &query, &offset));
    EXPECT_EQ(2u, offset.location.begin);
    EXPECT_EQ(0, std::memcmp(&query, before, sizeof query));
    tlv_query_t copy;
    std::memset(&copy, 0xFF, sizeof copy);
    EXPECT_EQ(0u, tlv_query_count(&copy));
    EXPECT_EQ(0u, tlv_query_step(&copy, 0).size);
    EXPECT_EQ(648u, sizeof(tlv_query_t));
    EXPECT_EQ(16u, sizeof(tlv_query_matcher_t));
}

TEST(Unit_Tlv_QueryProgram, InitializedFailuresAlwaysCarryDiagnosticDetail) {
    tlv_query_diagnostic_t d{};
    size_t                 bytes = 77, alignment = 77;
    EXPECT_EQ(TLV_ERR_NULL_ARG,
              TLV_DIAGNOSTIC_RESULT(
                  d, tlv_query_compile_scratch(nullptr, 0, nullptr, &bytes, &alignment, &d)));
    EXPECT_EQ(77u, bytes);
    EXPECT_EQ(TLV_ERR_NULL_ARG,
              TLV_DIAGNOSTIC_RESULT(d, tlv_query_exec_bind(nullptr, "x", TLV_QUERY_RESULT_INTEGER,
                                                           0, nullptr, 0, &d)));
    EXPECT_EQ(TLV_ERR_NULL_ARG, TLV_DIAGNOSTIC_RESULT(d, tlv_query_exec_finish(nullptr, &d)));
    int              matched = 77, found = 77;
    tlv_tree_event_t event{};
    EXPECT_EQ(TLV_ERR_NULL_ARG,
              TLV_DIAGNOSTIC_RESULT(d, tlv_query_exec_feed(nullptr, &event, &matched, &d)));
    EXPECT_EQ(77, matched);
    EXPECT_EQ(TLV_ERR_NULL_ARG,
              TLV_DIAGNOSTIC_RESULT(
                  d, tlv_query_program_visit(nullptr, nullptr, collect_event, nullptr, &d)));
    EXPECT_EQ(TLV_ERR_NULL_ARG,
              TLV_DIAGNOSTIC_RESULT(d, tlv_query_program_exists(nullptr, nullptr, 0, &found, &d)));
    EXPECT_EQ(77, found);
    Program p;
    ASSERT_EQ(TLV_OK, p.compile("5A"));
    ASSERT_EQ(TLV_OK, tlv_query_exec_size(p.get(), 4, &bytes, &alignment));
    std::vector<uint64_t> storage((bytes + 7) / 8);
    tlv_query_exec_t*     exec = nullptr;
    ASSERT_EQ(TLV_OK, tlv_query_exec_init(p.get(), storage.data(), bytes, 4, 10, 10000, &exec));
    ASSERT_EQ(TLV_OK, tlv_query_exec_finish(exec, &d));
    EXPECT_EQ(TLV_ERR_INVALID_STATE,
              TLV_DIAGNOSTIC_RESULT(d, tlv_query_exec_feed(exec, &event, &matched, &d)));
    EXPECT_EQ(TLV_QUERY_ERROR_STATE, d.kind);
    EXPECT_EQ(77, matched);
    auto  image = p.storage;
    auto* header = reinterpret_cast<tlv_query_program_t*>(image.data());
    for (uint32_t count : {uint32_t(0), UINT32_MAX}) {
        header->count = count;
        EXPECT_EQ(TLV_ERR_INVALID_VALUE,
                  TLV_DIAGNOSTIC_RESULT(
                      d, tlv_query_program_load_scratch(header, p.info.program_size, nullptr,
                                                        &bytes, &alignment, &d)));
        EXPECT_EQ(TLV_QUERY_ERROR_IMAGE, d.kind);
    }
}

TEST(Unit_Tlv_QueryProgram, VisitorFailureAndIncrementalStatusCarryDetail) {
    for (bool retained : {false, true}) {
        Program p;
        ASSERT_EQ(TLV_OK, p.compile("//5A"));
        size_t bytes, alignment;
        ASSERT_EQ(TLV_OK, retained ? tlv_query_eval_size(p.get(), 4, 10, &bytes, &alignment)
                                   : tlv_query_exec_size(p.get(), 4, &bytes, &alignment));
        std::vector<uint64_t> storage((bytes + 7) / 8);
        tlv_query_exec_t*     exec = nullptr;
        ASSERT_EQ(TLV_OK, retained ? tlv_query_eval_init(p.get(), nullptr, storage.data(), bytes, 4,
                                                         10, 10000, &exec)
                                   : tlv_query_exec_init(p.get(), storage.data(), bytes, 4, 10,
                                                         10000, &exec));
        const uint8_t     wire[] = {0x5a, 0};
        tlv_tree_reader_t reader;
        tlv_tree_frame_t  frames[4];
        ASSERT_EQ(TLV_OK, tlv_tree_reader_init(&reader, wire, sizeof wire, &controlled::format,
                                               frames, 4, 4, 10));
        auto fail = [](const tlv_tree_event_t*, void*) { return TLV_VISIT_ERROR; };
        tlv_query_diagnostic_t d{};
        EXPECT_EQ(TLV_ERR_VISITOR, TLV_DIAGNOSTIC_RESULT(d, tlv_query_program_visit(
                                                                &reader, exec, fail, nullptr, &d)));
        EXPECT_EQ(TLV_QUERY_ERROR_CALLBACK, d.kind);
        EXPECT_FALSE(d.has_reader);
        EXPECT_STREQ("visitor continue or stop", d.expected);
        // exists initializes its diagnostic even when the execution is poisoned.
        int found = 77;
        EXPECT_EQ(TLV_ERR_INVALID_STATE,
                  TLV_DIAGNOSTIC_RESULT(d, tlv_query_program_exists(&reader, exec, 0, &found, &d)));
        EXPECT_EQ(TLV_QUERY_ERROR_STATE, d.kind);
        EXPECT_EQ(77, found);
        ASSERT_EQ(TLV_OK, tlv_query_exec_reset(exec));
        ASSERT_EQ(TLV_OK, tlv_tree_reader_init_incremental(&reader, wire, 1, &controlled::format,
                                                           frames, 4, 4, 10));
        EXPECT_EQ(
            TLV_NEED_MORE_DATA,
            TLV_DIAGNOSTIC_RESULT(d, tlv_query_program_visit(&reader, exec, fail, nullptr, &d)));
        EXPECT_EQ(TLV_QUERY_ERROR_READER, d.kind);
        EXPECT_EQ(TLV_NEED_MORE_DATA, d.diagnostic.code);
        EXPECT_TRUE(d.has_reader);
        EXPECT_EQ(TLV_DIAGNOSTIC_SEVERITY_INFO, d.diagnostic.severity);
    }
}

TEST(Unit_Tlv_QueryProgram, PropagatedReaderStateUsesStateKindAndPreservesReaderDetail) {
    Program p;
    ASSERT_EQ(TLV_OK, p.compile("//*"));
    for (bool retained : {false, true}) {
        size_t bytes, alignment;
        ASSERT_EQ(TLV_OK, retained ? tlv_query_eval_size(p.get(), 4, 8, &bytes, &alignment)
                                   : tlv_query_exec_size(p.get(), 4, &bytes, &alignment));
        std::vector<uint64_t> storage((bytes + 7) / 8);
        tlv_query_exec_t*     exec = nullptr;
        ASSERT_EQ(TLV_OK, retained ? tlv_query_eval_init(p.get(), nullptr, storage.data(), bytes, 4,
                                                         8, 10000, &exec)
                                   : tlv_query_exec_init(p.get(), storage.data(), bytes, 4, 8,
                                                         10000, &exec));
        auto format = controlled::format;
        format.decode = [](const void*, const uint8_t*, size_t, tlv_decoded_t*,
                           tlv_format_error_t* error) {
            error->region = TLV_REGION_VALUE;
            error->has_offset = 1;
            error->offset = 1;
            return TLV_ERR_INVALID_STATE;
        };
        const uint8_t     wire[] = {0x5a, 0};
        tlv_tree_reader_t reader;
        tlv_tree_frame_t  frames[4];
        ASSERT_EQ(TLV_OK,
                  tlv_tree_reader_init(&reader, wire, sizeof wire, &format, frames, 4, 4, 8));
        tlv_query_diagnostic_t diagnostic{};
        auto visitor = [](const tlv_tree_event_t*, void*) { return TLV_VISIT_CONTINUE; };
        EXPECT_EQ(TLV_ERR_INVALID_STATE,
                  TLV_DIAGNOSTIC_RESULT(diagnostic, tlv_query_program_visit(&reader, exec, visitor,
                                                                            nullptr, &diagnostic)));
        EXPECT_EQ(TLV_QUERY_ERROR_STATE, diagnostic.kind);
        EXPECT_TRUE(diagnostic.has_reader);
        EXPECT_EQ(TLV_ERR_INVALID_STATE, diagnostic.diagnostic.code);
        EXPECT_EQ(TLV_READER_OP_VALUE, diagnostic.reader.operation);
        EXPECT_EQ(1u, diagnostic.diagnostic.location.begin);
    }
}

TEST(Unit_Tlv_QueryProgram, UnclosedFeedIsInvalidValueAndRetainsItsFailureDetail) {
    Program p;
    ASSERT_EQ(TLV_OK, p.compile("//*"));
    for (bool retained : {false, true}) {
        size_t bytes, alignment;
        ASSERT_EQ(TLV_OK, retained ? tlv_query_eval_size(p.get(), 4, 8, &bytes, &alignment)
                                   : tlv_query_exec_size(p.get(), 4, &bytes, &alignment));
        std::vector<uint64_t> storage((bytes + 7) / 8);
        tlv_query_exec_t*     exec = nullptr;
        ASSERT_EQ(TLV_OK, retained ? tlv_query_eval_init(p.get(), nullptr, storage.data(), bytes, 4,
                                                         8, 10000, &exec)
                                   : tlv_query_exec_init(p.get(), storage.data(), bytes, 4, 8,
                                                         10000, &exec));
        tlv_tree_event_t event{};
        event.kind = TLV_TREE_BEGIN;
        int matched = 79;
        ASSERT_EQ(TLV_OK, tlv_query_exec_feed(exec, &event, &matched, &p.diagnostic));
        EXPECT_EQ(TLV_ERR_INVALID_VALUE,
                  TLV_DIAGNOSTIC_RESULT(p.diagnostic, tlv_query_exec_finish(exec, &p.diagnostic)));
        EXPECT_EQ(TLV_QUERY_ERROR_EVENTS, p.diagnostic.kind);
        unsigned char original[sizeof p.diagnostic];
        std::memcpy(original, &p.diagnostic, sizeof original);
        EXPECT_EQ(TLV_ERR_INVALID_STATE, tlv_query_exec_finish(exec, &p.diagnostic));
        EXPECT_EQ(0, std::memcmp(original, &p.diagnostic, sizeof original));
        ASSERT_EQ(TLV_OK, tlv_query_exec_reset(exec));
        EXPECT_EQ(TLV_OK, tlv_query_exec_finish(exec, &p.diagnostic));
    }
}

TEST(Unit_Tlv_QueryProgram, InvalidHookConfigurationCarriesCapabilityDetail) {
    tlv_query_compile_options_t options;
    tlv_query_compile_options_init(&options);
    tlv_query_environment_t environment{};
    options.environment = &environment;
    environment.hook_count = 1;
    size_t                 bytes, alignment;
    tlv_query_diagnostic_t d{};
    EXPECT_EQ(TLV_ERR_INVALID_ARG,
              TLV_DIAGNOSTIC_RESULT(
                  d, tlv_query_compile_scratch("5A", 2, &options, &bytes, &alignment, &d)));
    EXPECT_EQ(TLV_QUERY_ERROR_CAPABILITY, d.kind);
}

TEST(Unit_Tlv_QueryProgram, SchemaRuleImagesTypesAndAlignmentRemainDistinct) {
    Program selector, assertion, number;
    ASSERT_EQ(TLV_OK, selector.compile("//5A"));
    ASSERT_EQ(TLV_OK, assertion.compile("exists(//5A)"));
    ASSERT_EQ(TLV_OK, number.compile("count(//5A)"));
#if OPENTLV_DOCUMENT && OPENTLV_READER && OPENTLV_WRITER
    tlv_document_t*        raw = nullptr;
    tlv_document_options_t options;
    ASSERT_EQ(TLV_OK, tlv_document_options_init(&options, &controlled::format));
    ASSERT_EQ(TLV_OK, tlv_document_create(&options, &raw));
    std::unique_ptr<tlv_document_t, decltype(&tlv_document_free)> document(raw, tlv_document_free);
#endif
    for (bool context : {false, true}) {
        for (int defect = 0; defect < 3; ++defect) {
            SCOPED_TRACE(defect);
            auto  damaged = context ? selector.storage : assertion.storage;
            auto* image = reinterpret_cast<tlv_query_program_t*>(damaged.data());
            const tlv_query_program_t* invalid = image;
            if (defect == 0)
                invalid = reinterpret_cast<const tlv_query_program_t*>(
                    reinterpret_cast<const char*>(image) + 1);
            else if (defect == 1)
                image->magic = 0;
            else
                invalid = number.get();
            tlv_schema_query_rule_t rules[] = {{selector.get(), assertion.get(), nullptr, "valid"},
                                               {context ? invalid : selector.get(),
                                                context ? assertion.get() : invalid, nullptr,
                                                "invalid"}};
            const auto expected = defect == 0 ? TLV_ERR_INVALID_ARG : TLV_ERR_INVALID_VALUE;
            size_t     a = 777, b = 777, alignment = 777;
            EXPECT_EQ(expected, tlv_schema_query_size(rules, 2, 4, 8, &a, &b, &alignment));
            EXPECT_EQ(777u, a);
            EXPECT_EQ(777u, b);
            EXPECT_EQ(777u, alignment);
            tlv_schema_query_workspace_t workspace{};
            for (bool detailed : {false, true}) {
                tlv_schema_query_diagnostic_t diagnostic{};
                diagnostic.rule = 777;
                auto check = [&] {
                    if (!detailed) return;
                    if (defect == 0)
                        EXPECT_EQ(777u, diagnostic.rule);
                    else {
                        EXPECT_EQ(1u, diagnostic.rule);
                        EXPECT_EQ(defect == 1 ? TLV_QUERY_ERROR_IMAGE : TLV_QUERY_ERROR_TYPE,
                                  diagnostic.query.kind);
                    }
                };
                EXPECT_EQ(expected, tlv_schema_query_validate_buffer(
                                        nullptr, 0, &controlled::format, rules, 2, 4, 8, 1000,
                                        &workspace, detailed ? &diagnostic : nullptr));
                check();
#if OPENTLV_DOCUMENT && OPENTLV_READER && OPENTLV_WRITER
                diagnostic = {};
                diagnostic.rule = 777;
                EXPECT_EQ(expected, tlv_schema_query_validate_document(
                                        document.get(), rules, 2, 4, 8, 1000, &workspace, nullptr,
                                        0, nullptr, detailed ? &diagnostic : nullptr));
                check();
#endif
            }
        }
    }
}

TEST(Unit_Tlv_QueryProgram, DeepSchemaPathsMatchBetweenBufferAndDocument) {
    Program contexts, condition;
    ASSERT_EQ(TLV_OK, contexts.compile("//50"));
    ASSERT_EQ(TLV_OK, condition.compile("exists(5A)"));
    auto nested_format = controlled::format;
    nested_format.is_constructed = [](const void*, const tlv_tag_t* tag) {
        return tag->data[0] >= 0x80 ? 1 : 0;
    };
    tlv_schema_query_rule_t rule{contexts.get(), condition.get(), nullptr, "deep"};
    size_t                  a, b, alignment;
    ASSERT_EQ(TLV_OK, tlv_schema_query_size(&rule, 1, 64, 100, &a, &b, &alignment));
    std::vector<uint8_t> selector_storage(a + alignment), assertion_storage(b + alignment);
    auto                 aligned = [alignment](std::vector<uint8_t>& storage) {
        return reinterpret_cast<void*>(
            (reinterpret_cast<uintptr_t>(storage.data()) + alignment - 1) & ~(alignment - 1));
    };
    tlv_schema_query_context_t   selected[1]{};
    tlv_tree_frame_t             frames[64]{};
    tlv_schema_query_workspace_t workspace{
        aligned(selector_storage), a, aligned(assertion_storage), b, selected, 1, frames, 64};
    for (size_t depth : {31u, 32u, 33u, 40u}) {
        SCOPED_TRACE(depth);
        std::vector<uint8_t> wire = {0x50, 0};
        for (size_t i = depth; i-- > 0;)
            wire.insert(wire.begin(),
                        {static_cast<uint8_t>(0x80 + i), static_cast<uint8_t>(wire.size())});
        tlv_schema_query_diagnostic_t diagnostic{};
        ASSERT_EQ(TLV_ERR_SCHEMA,
                  tlv_schema_query_validate_buffer(wire.data(), wire.size(), &nested_format, &rule,
                                                   1, 64, 100, 1000000, &workspace, &diagnostic));
        const size_t retained = depth < 32 ? depth : 32;
        ASSERT_EQ(retained, diagnostic.schema.diagnostic.path.length);
        EXPECT_EQ(depth - retained, diagnostic.schema.diagnostic.path.omitted);
        for (size_t i = 0; i < retained; ++i)
            EXPECT_EQ(0x80 + i, diagnostic.schema.diagnostic.path.tags[i].data[0]);
#if OPENTLV_DOCUMENT && OPENTLV_READER && OPENTLV_WRITER
        tlv_document_options_t options;
        ASSERT_EQ(TLV_OK, tlv_document_options_init(&options, &nested_format));
        options.max_depth = 64;
        tlv_document_t* raw = nullptr;
        ASSERT_EQ(TLV_OK, tlv_document_parse(wire.data(), wire.size(), &options, &raw, nullptr));
        std::unique_ptr<tlv_document_t, decltype(&tlv_document_free)> document(raw,
                                                                               tlv_document_free);
        tlv_schema_query_diagnostic_t                                 doc_diagnostic{};
        ASSERT_EQ(TLV_ERR_SCHEMA, tlv_schema_query_validate_document(
                                      document.get(), &rule, 1, 64, 100, 1000000, &workspace,
                                      nullptr, 0, nullptr, &doc_diagnostic));
        ASSERT_EQ(retained, doc_diagnostic.schema.diagnostic.path.length);
        EXPECT_EQ(diagnostic.schema.diagnostic.path.omitted,
                  doc_diagnostic.schema.diagnostic.path.omitted);
        for (size_t i = 0; i < retained; ++i)
            EXPECT_TRUE(tlv_tag_equal(diagnostic.schema.diagnostic.path.tags[i],
                                      doc_diagnostic.schema.diagnostic.path.tags[i]));
#endif
    }
}
