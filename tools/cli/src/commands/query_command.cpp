// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "commands/query_command.hpp"
#include <iostream>
#include "commands/support.hpp"
#include "diagnostics.hpp"
#include "tlv++/query/program.hpp"
#include "tlv++/native.hpp"
#include <cstring>
#include <limits>
#include "tlv/query/adapters.h"
#if OPENTLV_FORMAT_BER
#include "tlv/builtins/asn1/query.h"
#endif
#if OPENTLV_EMV
#include "tlv/builtins/emv/query.h"
#endif
#if OPENTLV_DOCUMENT
#include "tlv++/document/document.hpp"
#endif

namespace {

// The query path as text: uppercase hex tags joined by "/", however the user
// spelled it.
std::string query_path(const tlv::query& query) {
    size_t required = 0;
    tlv_query_format(&query.c_query(), nullptr, 0, &required);
    std::string path(required, '\0');
    tlv_query_format(&query.c_query(), &path[0], required, &required);
    path.resize(required - 1);
    return path;
}

} // namespace

namespace cli {

int query_command::run() {
    // Preserve the V1 output shape and validation rules for existing invocations.
    if (options_.query && !options_.query_count && !options_.query_exists &&
        !options_.query_explain && options_.query_variables.empty() &&
        !strcmp(options_.query_backend, "auto"))
        return traversal_command::run();
    auto selected_format = format_storage_.get();
    if (!selected_format) return fail(2, "unknown or disabled format; use otlv formats");
    auto report = [&](const tlv::query_failure& failure, int status) {
        const auto&    d = failure.diagnostic;
        nlohmann::json detail = {{"error", tlv_strerror(failure.code)},
                                 {"code", failure.code},
                                 {"kind", d.kind},
                                 {"begin", d.begin},
                                 {"end", d.end}};
        if (d.has_source_offset) detail["source_offset"] = d.source_offset;
        if (d.expected) detail["expected"] = d.expected;
        if (d.limit) {
            detail["limit"] = d.limit;
            detail["configured"] = d.configured;
        }
        if (d.kind == TLV_QUERY_ERROR_CODEC) detail["codec"] = d.codec;
        if (d.kind == TLV_QUERY_ERROR_READER) {
            detail["reader"] = {{"code", d.reader.diagnostic.code},
                                {"operation", d.reader.operation}};
            if (d.reader.diagnostic.has_offset)
                detail["reader"]["offset"] = d.reader.diagnostic.offset;
            if (d.reader.has_tag)
                detail["reader"]["tag"] = hex_string(d.reader.tag.data, d.reader.tag.size);
        }
        if (!strcmp(options_.diagnostics, "json"))
            std::cerr << detail.dump() << '\n';
        else
            std::cerr << "otlv: " << tlv_strerror(failure.code) << " query=" << d.begin << ':'
                      << d.end << (d.expected ? " expected=" : "") << (d.expected ? d.expected : "")
                      << '\n';
        return status;
    };
    struct variable {
        std::string             name, value;
        tlv_query_result_kind_t type;
        int64_t                 integer = 0;
    };
    std::vector<variable> variables;
    for (const auto& text : options_.query_variables) {
        auto colon = text.find(':');
        auto equals = text.find('=', colon);
        if (colon == std::string::npos || equals == std::string::npos || !colon)
            return fail(2, "--var requires NAME:int=DECIMAL, NAME:bytes=HEX or NAME:string=UTF8");
        variable v;
        v.name = text.substr(0, colon);
        v.value = text.substr(equals + 1);
        auto type = text.substr(colon + 1, equals - colon - 1);
        if (type == "int") {
            v.type = TLV_QUERY_RESULT_INTEGER;
            size_t end = 0;
            if (v.value.empty() || v.value.find_first_not_of("-0123456789") != std::string::npos)
                return fail(2, "invalid int variable");
            try {
                v.integer = std::stoll(v.value, &end, 10);
            } catch (...) {
                return fail(2, "int variable outside int64 range");
            }
            if (end != v.value.size()) return fail(2, "invalid int variable");
        } else if (type == "bytes") {
            v.type = TLV_QUERY_RESULT_BYTES;
            if (v.value.size() % 2)
                return fail(2, "bytes variable requires even-length hexadecimal");
            auto digit = [](char c) {
                return c >= '0' && c <= '9'   ? c - '0'
                       : c >= 'a' && c <= 'f' ? c - 'a' + 10
                       : c >= 'A' && c <= 'F' ? c - 'A' + 10
                                              : -1;
            };
            std::string decoded;
            for (size_t i = 0; i < v.value.size(); i += 2) {
                int a = digit(v.value[i]), b = digit(v.value[i + 1]);
                if (a < 0 || b < 0) return fail(2, "invalid hexadecimal bytes variable");
                decoded.push_back(static_cast<char>(a * 16 + b));
            }
            v.value = std::move(decoded);
        } else if (type == "string")
            v.type = TLV_QUERY_RESULT_STRING;
        else
            return fail(2, "unknown variable type; use int, bytes or string");
        variables.push_back(std::move(v));
    }
    std::vector<tlv_query_variable_t> declarations;
    for (const auto& v : variables) declarations.push_back({v.name.c_str(), v.type});
    tlv_query_compile_options_t compile_options;
    tlv_query_compile_options_init(&compile_options);
    tlv_query_environment_t environment{};
    environment.format = &tlv::native::descriptor(*selected_format);
    const auto*      builtin_hooks = tlv_query_builtin_hooks(&environment.hook_count);
    tlv_query_hook_t hooks[4];
    std::memcpy(hooks, builtin_hooks, environment.hook_count * sizeof *hooks);
#if OPENTLV_FORMAT_BER
    if (!std::strcmp(options_.format, "ber") || !std::strcmp(options_.format, "der") ||
        !std::strcmp(options_.format, "cer")) {
        environment.tags = &tlv_asn1_query_tags;
        hooks[environment.hook_count++] = tlv_asn1_query_date;
    }
#endif
    environment.hooks = hooks;
    compile_options.environment = &environment;
#if OPENTLV_EMV
    if (!strcmp(options_.format, "emv")) compile_options.resolve = tlv_emv_query_resolve;
#endif
    compile_options.variables = declarations.data();
    compile_options.variable_count = declarations.size();
    std::string text = options_.path;
    if (options_.query_count) text = "count(" + text + ")";
    if (options_.query_exists) text = "exists(" + text + ")";
    auto program = tlv::query_program::compile(text, &compile_options);
    if (!program) return report(program.error(), 2);
    bool document_backend =
        !strcmp(options_.query_backend, "document") ||
        (program->info().level == TLV_QUERY_D && !strcmp(options_.query_backend, "auto"));
    if (program->info().level == TLV_QUERY_D && !document_backend)
        return fail(2, "Query requires Document; streaming backend does not materialize input");
    if (options_.value_only && program->info().result_kind != TLV_QUERY_RESULT_NODES)
        return fail(2, "--value requires a node selection");
    auto execution = tlv::query_execution::create(*program, options_.max_depth,
                                                  options_.max_elements, 100000000, &environment);
    if (!execution) return report(execution.error(), 2);
    for (const auto& v : variables) {
        auto bound =
            v.type == TLV_QUERY_RESULT_INTEGER
                ? execution->bind(v.name.c_str(), v.integer)
                : execution->bind(v.name.c_str(),
                                  tlv::bytes(reinterpret_cast<const tlv::byte*>(v.value.data()),
                                             v.value.size()),
                                  v.type == TLV_QUERY_RESULT_STRING);
        if (!bound) return report(bound.error(), 2);
    }
    if (options_.query_explain) {
        const auto&    info = program->info();
        nlohmann::json explanation = {
            {"query", program->format()},
            {"language", info.language_version},
            {"result_kind", info.result_kind},
            {"level", info.level},
            {"backend", document_backend ? "document" : "streaming-retained"},
            {"program_bytes", info.program_size},
            {"program_alignment", info.program_alignment},
            {"scratch_bytes", info.scratch_size},
            {"scratch_alignment", info.scratch_alignment},
            {"max_depth", options_.max_depth},
            {"candidates", options_.max_elements},
            {"max_work", 100000000},
            {"validation", "complete structural traversal"},
            {"stable_input_required", true},
            {"ir_unstable", program->explain()}};
        std::cerr << explanation.dump() << '\n';
    }
    nlohmann::json matches = nlohmann::json::array();
    auto           emit = [&](const tlv::element_view& element, bool source, size_t offset) {
        ++matches_;
        if (is_json(options_))
            matches.push_back(
                {{"path", program->format()},
                 {"offset", source ? nlohmann::json(offset) : nlohmann::json(nullptr)},
                 {"tag", hex_string(element.tag().as_bytes())},
                 {"length", element.value().size()},
                 {"value", hex_string(element.value().as_bytes())}});
        else {
            if (!options_.value_only) {
                std::cout << "offset=" << (source ? std::to_string(offset) : "unavailable")
                          << " tag=";
                print_hex(element.tag().as_bytes());
                std::cout << " length=" << element.value().size() << " value=";
            }
            print_hex(element.value().as_bytes());
            std::cout << '\n';
        }
    };
    std::vector<uint8_t> value_snapshot, scratch;
#if OPENTLV_DOCUMENT
    std::unique_ptr<tlv::document> document;
#endif
    if (document_backend) {
#if OPENTLV_DOCUMENT
        tlv::document_format settings(*selected_format);
        settings.max_depth = options_.max_depth;
        settings.max_elements = options_.max_elements;
        auto parsed = tlv::document::parse(
            tlv::bytes(reinterpret_cast<const tlv::byte*>(data()), size()), settings);
        if (!parsed) return fail(3, tlv_strerror(parsed.error().code));
        document.reset(new tlv::document(std::move(*parsed)));
        std::vector<tlv_tree_writer_frame_t> frames(options_.max_depth + 1);
        tlv_tree_writer_workspace_t          staging{};
        staging.frames = frames.data();
        staging.frame_capacity = frames.size();
        if (program->info().constructed_values_required) {
            auto encoded = document->encode();
            if (!encoded) return fail(3, tlv_strerror(encoded.error().code));
            value_snapshot.resize(encoded->size());
            scratch.resize(encoded->size());
            staging.scratch = scratch.data();
            staging.scratch_capacity = scratch.size();
        }
        auto evaluated =
            document->evaluate(*execution, value_snapshot.data(), value_snapshot.size(),
                               program->info().constructed_values_required ? &staging : nullptr);
        if (!evaluated) return report(evaluated.error(), 3);
        if (program->info().result_kind == TLV_QUERY_RESULT_NODES)
            for (;;) {
                auto node = document->next(*execution);
                if (!node && node.error().code == TLV_ERR_END_OF_BUFFER) break;
                if (!node) return report(node.error(), 3);
                // Constructed Value output is obtained through the normal Document encoder.
                auto                   value = node->value();
                std::vector<tlv::byte> children;
                if (node->is_constructed())
                    for (auto child : node->children()) {
                        auto encoded = child.encode();
                        if (!encoded) return fail(3, tlv_strerror(encoded.error().code));
                        children.insert(children.end(), encoded->begin(), encoded->end());
                    }
                emit(tlv::element_view(node->tag(), node->is_constructed()
                                                        ? tlv::value_view(tlv::bytes(
                                                              children.data(), children.size()))
                                                        : value),
                     false, 0);
            }
#else
        return fail(2, "Document backend is disabled in this build");
#endif
    } else {
        std::vector<tlv::tree_frame> frames(options_.max_depth + 1);
        tlv::tree_reader reader(tlv::bytes(reinterpret_cast<const tlv::byte*>(data()), size()),
                                *selected_format, {frames.data(), frames.size()},
                                options_.max_depth, options_.max_elements);
        auto             visited = execution->visit(reader, [&](const tlv::tree_event& event) {
            emit(event.element, true, event.offset);
            return TLV_VISIT_CONTINUE;
        });
        if (!visited) return report(visited.error(), 3);
    }
    auto result = execution->result();
    if (!result) return report(result.error(), 3);
    if (result->kind == TLV_QUERY_RESULT_NODES) {
        if (is_json(options_)) std::cout << nlohmann::json({{"matches", matches}}).dump() << '\n';
        if (!matches_) return fail(5, ("no match for query " + program->format()).c_str());
    } else {
        nlohmann::json value;
        if (result->kind == TLV_QUERY_RESULT_BOOL)
            value = result->boolean != 0;
        else if (result->kind == TLV_QUERY_RESULT_INTEGER)
            value = result->integer;
        else if (result->kind == TLV_QUERY_RESULT_BYTES)
            value = hex_string(result->data, result->size);
        else
            value = std::string(result->size ? reinterpret_cast<const char*>(result->data) : "",
                                result->size);
        if (is_json(options_))
            std::cout << nlohmann::json({{"type", result->kind}, {"value", value}}).dump() << '\n';
        else if (result->kind == TLV_QUERY_RESULT_BYTES || result->kind == TLV_QUERY_RESULT_STRING)
            std::cout << value.get<std::string>() << '\n';
        else
            std::cout << value.dump() << '\n';
    }
    return std::cout ? 0 : 3;
}

int query_command::prepare() {
    if (!options_.query) return fail(2, "invalid query");
    matcher_.reset(new tlv::query_matcher(*options_.query));
    return 0;
}

// query's visitor: prints each element the path addresses. Text output is
// the dump line without nesting, --value prints only the value bytes, and
// --output json collects the elements into one document printed at the end.
tlv_visit_result_t query_command::visit_element(const tlv::element_view& element, std::size_t depth,
                                                std::size_t offset) {
    const auto native = tlv::native::descriptor(element);
    diagnostic_scope_visit(scope_, data(), &native, depth, format_->is_constructed);
    if (!matcher_->matches(element.tag(), depth)) return TLV_VISIT_CONTINUE;
    ++matches_;
    if (is_json(options_)) {
        nlohmann::json object;
        object["path"] = query_path(*options_.query);
        object["offset"] = offset;
        object["tag"] = hex_string(element.tag().as_bytes());
        object["length"] = (uint64_t)element.value().size();
        object["value"] = hex_string(element.value().as_bytes());
        json_root_.push_back(std::move(object));
        return TLV_VISIT_CONTINUE;
    }
    if (options_.value_only) {
        print_hex(element.value().as_bytes());
    } else {
        std::cout << "offset=" << offset << " tag=";
        print_hex(element.tag().as_bytes());
        std::cout << " length=" << element.value().size() << " value=";
        print_hex(element.value().as_bytes());
    }
    std::cout << "\n";
    return std::cout ? TLV_VISIT_CONTINUE : TLV_VISIT_ERROR;
}

void query_command::render_output() {
    if (result_ != TLV_OK || !is_json(options_)) return;
    nlohmann::json document;
    document["matches"] = std::move(json_root_);
    std::cout << document.dump() << "\n";
}

int query_command::after_success() {
    if (matches_) return 0;
    std::cerr << "otlv: no match for query " << query_path(*options_.query) << "\n";
    return 5;
}

} // namespace cli
