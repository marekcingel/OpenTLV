// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_CLI_COMMANDS_SUPPORT_HPP
#define OPENTLV_CLI_COMMANDS_SUPPORT_HPP
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include "decode.hpp"
#include "diagnostic_render.hpp"
#include "options.hpp"
#include "presentation.hpp"
#include "tlv/reader/visitor.h"
#include "tlv/formats/fixed.h"
#include "tlv++/native.hpp"
#include "tlv++/reader/tree.hpp"

// Small utilities shared by more than one file under commands/, kept out of
// any single command's own file so none of them has to include another
// command's internals just to reuse a formatting helper.

namespace cli {

// A byte range --recover skipped, and the first error that made it unreadable.
struct skipped_range {
    tlv_reader_diagnostic_t diagnostic{};
    std::size_t             offset;
    std::size_t             length;
    tlv_result_t            error;
    std::size_t             error_offset;
};

bool is_json(const options& o);

// Owns runtime Fixed configuration; returned views borrow this owner. Built-in
// views borrow immutable program-lifetime descriptors. No shared mutable state.
class format_selection {
public:
    explicit format_selection(const options& o);
    format_selection(const format_selection&) = delete;
    format_selection&                      operator=(const format_selection&) = delete;
    tlv::expected<tlv::format, tlv::error> get() const;

private:
    const char*        name_;
    tlv_fixed_format_t fixed_{};
    tlv_format_t       descriptor_{};
    tlv_result_t       result_ = TLV_OK;
};

// Prints `length` bytes as uppercase hex ("0A1B..."), restoring std::cout's
// prior formatting state afterward so callers can freely mix this with
// ordinary decimal output.
void print_hex(const uint8_t* data, std::size_t length);
void print_hex(tlv::bytes bytes);

// Prints a tag's bytes as hex, wrapped in the CLI's tag accent color when
// enabled. Shared by dump's element output and --pdol.
void print_tag(const tlv_tag_t& tag, bool color);
void print_tag(tlv::tag tag, bool color);

// Same encoding as print_hex, built as a string instead of streamed, for
// --output json's field values (which are never color-wrapped).
std::string hex_string(const uint8_t* data, std::size_t length);
std::string hex_string(tlv::bytes bytes);

// What every traversal of the input needs to know about the selected format.
struct traversal_env {
    const cli::options* options;
    const tlv_format_t* format;
    bool                is_der;
};

// Traverses `slice_size` bytes of `slice`, which starts at absolute offset `base`
// of the input, allowing at most `max_elements` elements. On failure
// *error_offset receives the failing element's absolute offset.
tlv_result_t visit_slice(const traversal_env& env, const uint8_t* slice, std::size_t slice_size,
                         std::size_t base, std::size_t max_elements, tlv_tree_visitor_t visitor,
                         void* context, std::size_t* error_offset,
                         tlv_reader_diagnostic_t* diagnostic = nullptr);

// Adds the "name" and, if requested, "description" EMV dictionary fields to
// a JSON element object, from the same lookup the text renderer uses. A tag
// unknown in its context is labelled only when `label_unknown`; the decode
// document leaves it unnamed.
template <class Json>
void json_emv(Json& object, const cli_presentation_t& presentation, const tlv_element_t* element,
              std::size_t depth, int describe, bool label_unknown = true) {
    const cli_emv_info info = cli_presentation_emv_info(&presentation, element, depth, describe);
    if (info.known)
        object["name"] = info.name;
    else if (label_unknown)
        object["name"] = "Unknown EMV tag in this context";
    if (info.has_description) object["description"] = info.description;
}

// Adds the "decoded" or "decode_error" field to a JSON element object, or
// neither for a tag/value kind with no codec.
template <class Json>
void json_decode(Json& object, const cli_presentation_t& presentation, const tlv_element_t* element,
                 std::size_t depth) {
    const decode_result result = decode_emv_value(presentation.contexts[depth], element);
    if (result.status == decode_status::ok)
        object["decoded"] = result.text;
    else if (result.status == decode_status::error)
        object["decode_error"] = result.text;
}

// The "skipped" array shared by dump's and decode's JSON documents.
template <class Json> Json skipped_json(const std::vector<skipped_range>& skipped) {
    Json array = Json::array();
    for (const skipped_range& range : skipped) {
        Json object;
        object["offset"] = range.offset;
        object["length"] = range.length;
        object["error"] = error_name(range.error);
        object["error_offset"] = range.error_offset;
        object["message"] = tlv_strerror(range.error);
        array.push_back(std::move(object));
    }
    return array;
}

} // namespace cli
#endif
