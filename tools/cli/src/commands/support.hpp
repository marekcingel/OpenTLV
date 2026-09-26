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
#include "tlv/reader/walker.h"

// Small utilities shared by more than one file under commands/, kept out of
// any single command's own file so none of them has to include another
// command's internals just to reuse a formatting helper.

namespace cli {

// A byte range --recover skipped, and the first error that made it unreadable.
struct skipped_range {
    std::size_t  offset;
    std::size_t  length;
    tlv_result_t error;
    std::size_t  error_offset;
};

bool is_json(const options& o);

// Prints `length` bytes as uppercase hex ("0A1B..."), restoring std::cout's
// prior formatting state afterward so callers can freely mix this with
// ordinary decimal output.
void print_hex(const uint8_t* data, std::size_t length);

// Prints a tag's bytes as hex, wrapped in the CLI's tag accent color when
// enabled. Shared by dump's element output and --pdol.
void print_tag(const tlv_tag_t& tag, bool color);

// Same encoding as print_hex, built as a string instead of streamed, for
// --output json's field values (which are never color-wrapped).
std::string hex_string(const uint8_t* data, std::size_t length);

// What every walk of the input needs to know about the selected format.
struct walk_env {
    const options*             options;
    const tlv_reader_format_t* format;
    tlv_is_constructed_fn      predicate; // BER nesting predicate for the generic walker
    bool                       is_der;
};

// Walks `slice_size` bytes of `slice`, which starts at absolute offset `base`
// of the input, allowing at most `max_elements` elements. On failure
// *error_offset receives the failing element's absolute offset.
tlv_result_t walk_slice(const walk_env& env, const uint8_t* slice, std::size_t slice_size,
                        std::size_t base, std::size_t max_elements, tlv_tree_visitor_t visitor,
                        void* context, std::size_t* error_offset);

// Adds the "name" and, if requested, "description" EMV dictionary fields to
// a JSON element object, from the same lookup the text renderer uses. A tag
// unknown in its context is labelled only when `label_unknown`; the decode
// document leaves it unnamed.
template <class Json>
void json_emv(Json& object, const cli_presentation_t& presentation, const tlv_view_t* view,
              std::size_t depth, int describe, bool label_unknown = true) {
    const cli_emv_info info = cli_presentation_emv_info(&presentation, view, depth, describe);
    if (info.known)
        object["name"] = info.name;
    else if (label_unknown)
        object["name"] = "Unknown EMV tag in this context";
    if (info.has_description) object["description"] = info.description;
}

// Adds the "decoded" or "decode_error" field to a JSON element object, or
// neither for a tag/value kind with no codec.
template <class Json>
void json_decode(Json& object, const cli_presentation_t& presentation, const tlv_view_t* view,
                 std::size_t depth) {
    const decode_result result = decode_emv_value(presentation.contexts[depth], view);
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
