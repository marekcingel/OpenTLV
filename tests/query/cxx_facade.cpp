// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#include "tlv++/query/program.hpp"
#include "tlv/config.h"
#include "tlv/query/adapters.h"
#include "tlv/formats/fixed.h"
#if OPENTLV_DOCUMENT
#include "tlv++/document/document.hpp"
#endif
#if OPENTLV_FORMAT_BER
#include "tlv/builtins/asn1/query.h"
#endif
#include <cstring>
#include <iostream>
#include <iomanip>
#include <map>

namespace {
int constructed(const void*, const tlv_tag_t* tag) {
    return tag->size == 1 && tag->data[0] == 0x70;
}
int fail(tlv::query_failure error) {
    std::cerr << error.code << ' ' << error.diagnostic.kind << ' ' << error.diagnostic.begin << ' '
              << error.diagnostic.end << '\n';
    return 1;
}
tlv_result_t resolve(const void*, const char* scope, size_t scope_size, const char* name,
                     size_t size, tlv_tag_t* tag) {
    static const uint8_t leaf = 0x5a, container = 0x70;
    if (scope_size != 7 || std::memcmp(scope, "fixture", 7)) return TLV_ERR_INVALID_TAG;
    if (size == 4 && !std::memcmp(name, "leaf", 4))
        *tag = tlv_tag(&leaf, 1);
    else if (size == 9 && !std::memcmp(name, "container", 9))
        *tag = tlv_tag(&container, 1);
    else
        return TLV_ERR_INVALID_TAG;
    return TLV_OK;
}
std::vector<uint8_t> unhex(const std::string& text) {
    if (text.size() % 2) throw std::invalid_argument("odd hex");
    std::vector<uint8_t> result;
    for (size_t i = 0; i < text.size(); i += 2) {
        size_t consumed;
        auto   value = std::stoul(text.substr(i, 2), &consumed, 16);
        if (consumed != 2) throw std::invalid_argument("invalid hex");
        result.push_back(static_cast<uint8_t>(value));
    }
    return result;
}
tlv::bytes view(const std::vector<uint8_t>& data, size_t size) {
    return {reinterpret_cast<const tlv::byte*>(data.data()), size};
}
void scalar(const tlv_query_result_t& result) {
    if (result.kind == TLV_QUERY_RESULT_NODES) return;
    if (result.kind == TLV_QUERY_RESULT_BOOL)
        std::cout << "bool:" << result.boolean;
    else if (result.kind == TLV_QUERY_RESULT_INTEGER)
        std::cout << "int:" << result.integer;
    else {
        std::cout << (result.kind == TLV_QUERY_RESULT_BYTES ? "bytes:" : "string:");
        for (size_t i = 0; i < result.size; ++i)
            std::cout << std::hex << std::setw(2) << std::setfill('0') << unsigned(result.data[i]);
    }
    std::cout << '\n';
}
} // namespace
int main(int argc, char** argv) {
    if (argc == 2 && !std::strcmp(argv[1], "--language-features")) return 0;
    if (argc == 2 && !std::strcmp(argv[1], "--capabilities")) {
#if OPENTLV_DOCUMENT
        std::cout << "document ";
#endif
#if OPENTLV_FORMAT_BER
        std::cout << "asn1 ";
#endif
        return 0;
    }
    if (argc < 3) return 2;
    std::string        mode = argc >= 4 ? argv[3] : "o";
    auto               input = unhex(argv[2]);
    tlv_fixed_format_t fixed{};
    fixed.tag_size = fixed.length_size = 1;
    fixed.length_order = TLV_BYTE_ORDER_BIG_ENDIAN;
    tlv_format_t format{};
    if (tlv_fixed_format_init(&format, &fixed) != TLV_OK) return 2;
    format.is_constructed = constructed;
    tlv_query_environment_t environment{};
    environment.format = &format;
    size_t           hook_count;
    const auto*      builtin = tlv_query_builtin_hooks(&hook_count);
    tlv_query_hook_t hooks[4];
    std::memcpy(hooks, builtin, hook_count * sizeof *hooks);
#if OPENTLV_FORMAT_BER
    environment.tags = &tlv_asn1_query_tags;
    hooks[hook_count++] = tlv_asn1_query_date;
#endif
    environment.hooks = hooks;
    environment.hook_count = hook_count;
    struct binding {
        std::string             name;
        tlv_query_result_kind_t type;
        int64_t                 integer;
        std::vector<uint8_t>    data;
    };
    std::vector<binding> bindings;
    for (int i = 5; i < argc; ++i) {
        std::string argument = argv[i];
        auto        first = argument.find(':'), second = argument.find(':', first + 1);
        if (first == std::string::npos || second == std::string::npos) return 2;
        binding value{};
        value.name = argument.substr(0, first);
        auto type = argument.substr(first + 1, second - first - 1),
             data = argument.substr(second + 1);
        if (type == "int") {
            value.type = TLV_QUERY_RESULT_INTEGER;
            value.integer = std::stoll(data);
        } else if (type == "bytes") {
            value.type = TLV_QUERY_RESULT_BYTES;
            value.data = unhex(data);
        } else if (type == "string") {
            value.type = TLV_QUERY_RESULT_STRING;
            value.data.assign(data.begin(), data.end());
        } else
            return 2;
        bindings.push_back(std::move(value));
    }
    std::vector<tlv_query_variable_t> declarations;
    for (const auto& value : bindings) declarations.push_back({value.name.c_str(), value.type});
    tlv_query_compile_options_t options;
    tlv_query_compile_options_init(&options);
    options.environment = &environment;
    options.resolve = resolve;
    options.variables = declarations.data();
    options.variable_count = declarations.size();
    options.optimize = mode.find('u') == std::string::npos;
    auto program = tlv::query_program::compile(argv[1], &options);
    if (!program) return fail(program.error());
    const bool document_mode =
        program->info().level == TLV_QUERY_D || mode.find('d') != std::string::npos;
    const bool retained = document_mode || program->info().level >= TLV_QUERY_S2 ||
                          mode.find('r') != std::string::npos;
    auto execution = tlv::query_execution::create(*program, 128, 1024, 100000000,
                                                  retained ? &environment : nullptr, retained);
    if (!execution) return fail(execution.error());
    for (const auto& value : bindings) {
        bool referenced = false;
        for (size_t i = 0; i < program->variable_count(); ++i) {
            auto declaration = program->variable(i);
            if (!declaration) return fail(declaration.error());
            if (std::string(declaration->name, declaration->name_size) == value.name)
                referenced = true;
        }
        if (!referenced) continue;
        auto status = value.type == TLV_QUERY_RESULT_INTEGER
                          ? execution->bind(value.name.c_str(), value.integer)
                          : execution->bind(value.name.c_str(), view(value.data, value.data.size()),
                                            value.type == TLV_QUERY_RESULT_STRING);
        if (!status) return fail(status.error());
    }
    if (document_mode) {
#if OPENTLV_DOCUMENT
        tlv::document_format document_options(format);
        document_options.retain_source_locations = true;
        auto document = tlv::document::parse(view(input, input.size()), document_options);
        if (!document) return 2;
        std::vector<std::pair<tlv::node, size_t>> offsets;
        std::vector<tlv::node>                    stack;
        auto                                      node = document->first();
        tlv::tree_frame                           frames[128];
        tlv::tree_reader reader(view(input, input.size()), format, {frames, 128}, 128, 1024);
        for (;;) {
            auto item = reader.next();
            if (!item) {
                if (item.error().code != TLV_ERR_END_OF_BUFFER) return 2;
                break;
            }
            if (!node) return 2;
            offsets.push_back({node, item->offset});
            if (node.next()) stack.push_back(node.next());
            node = node.first_child();
            if (!node && !stack.empty()) {
                node = stack.back();
                stack.pop_back();
            }
        }
        tlv_tree_writer_frame_t frames_out[128];
        std::vector<uint8_t>    values(input.size() + 4096), staged(values.size()),
            scratch(values.size());
        tlv_tree_writer_workspace_t writer{};
        writer.frames = frames_out;
        writer.frame_capacity = 128;
        writer.data = staged.data();
        writer.data_capacity = staged.size();
        writer.scratch = scratch.data();
        writer.scratch_capacity = scratch.size();
        auto status = document->evaluate(*execution, values.data(), values.size(), &writer);
        if (!status) return fail(status.error());
        if (program->info().result_kind == TLV_QUERY_RESULT_NODES) {
            for (;;) {
                auto selected = document->next(*execution);
                if (!selected) {
                    if (selected.error().code != TLV_ERR_END_OF_BUFFER)
                        return fail(selected.error());
                    break;
                }
                bool found = false;
                for (const auto& entry : offsets)
                    if (entry.first == *selected) {
                        std::cout << entry.second << '\n';
                        found = true;
                        break;
                    }
                if (!found) return 2;
            }
        }
        auto result = execution->result();
        if (!result) return fail(result.error());
        scalar(*result);
        return 0;
#else
        return fail({TLV_ERR_UNSUPPORTED_TYPE, {}});
#endif
    }
    tlv::tree_frame frames[128];
    size_t          split = argc >= 5 ? std::stoul(argv[4]) : input.size();
    if (split > input.size()) return 2;
    tlv::tree_reader reader(view(input, split), format, {frames, 128}, 128, 1024,
                            argc >= 5 ? tlv::input_mode::incremental : tlv::input_mode::final);
    auto             collect = [](const tlv::tree_event& event) {
        std::cout << event.offset << '\n';
        return TLV_VISIT_CONTINUE;
    };
    auto visited = execution->visit(reader, collect);
    if (argc >= 5 && !visited && visited.error().code == TLV_NEED_MORE_DATA) {
        auto changed = reader.set_input(view(input, input.size()), 0, tlv::input_mode::final);
        if (!changed) return 2;
        visited = execution->visit(reader, collect);
    }
    if (!visited) return fail(visited.error());
    if (program->info().result_kind == TLV_QUERY_RESULT_NODES) return 0;
    auto result = execution->result();
    if (!result) return fail(result.error());
    scalar(*result);
    return 0;
}
